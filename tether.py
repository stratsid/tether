#!/usr/bin/python3
"""tether — time-boxed permission leases + tamper-proof audit log for Claude Code.

Installed copy lives in root-owned /usr/local/lib/tether; leases in root-owned
/Library/Application Support/tether; log is root:staff, mode 0660, flag `sappnd`
(system append-only: staff may append, nobody but root can truncate/edit/delete).
Claude runs as the user without the sudo password, so it can read but not alter any of it.

  sudo tether install                         install hooks + managed settings (review the repo first)
  sudo tether grant 'Bash(ssh nexus:*)' 10h   lease a permission rule for a duration
  sudo tether revoke ['RULE' | --all]         end lease(s) now
  sudo tether policy ssh-only|any|REGEX      restrict which rules can ever be leased (tether policy = show)
  sudo tether prune                           drop expired leases from managed allow list (hook asks for them anyway)
  sudo tether lock-hooks | unlock-hooks       move your ~/.claude hooks to managed scope + ignore user/project hooks
  sudo tether ssh-grant HOST 10h [note] [--from IP] [--permitopen H:P,..]   temporary restricted key + lease
  sudo tether ssh-revoke HOST                 remove that key from HOST and locally, end the lease
  tether status                               leases + integrity check
  tether log [-n N] [--since ISO] [--tool T] [--grep S] [--json]
  tether revert ID|--since ISO [--dry-run]    restore files changed by Write/Edit
  sudo tether uninstall
Python 3.9 compatible (/usr/bin/python3), stdlib only.
"""
import base64, datetime as dt, fnmatch, json, os, re, shlex, shutil, subprocess, sys, uuid

PREFIX = os.environ.get("TETHER_PREFIX", "")          # tests only; empty in production
LIB = PREFIX + "/usr/local/lib/tether"
ETC = PREFIX + "/Library/Application Support/tether"
LEASES = ETC + "/leases.json"
POLICY = ETC + "/policy.json"          # {"allow_rule_regex": "..."}; root-owned
LOCKED = ETC + "/locked-hooks.json"    # present while `tether lock-hooks` is in effect
LOGDIR = PREFIX + "/Library/Logs/tether"
LOG = LOGDIR + "/tether.log"
MANAGED = PREFIX + "/Library/Application Support/ClaudeCode/managed-settings.json"
BIN = PREFIX + "/usr/local/bin/tether"
PY = "/usr/bin/python3"
MAX_BLOB = 5 * 1024 * 1024
FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}
MAX_RESPONSE = 2000
# Never snapshot these into the log (it is readable by group staff).
SECRET_SUBSTR = ("/.ssh/", "/Library/Keychains/", "/.aws/", "/.gnupg/", "/.config/gh/",
                 "/.config/edge0/api_key", "/.claude/", ETC + "/ssh/")
SECRET_BASE = (".env", ".env.*", "*.pem", "*.key", "id_rsa*", "id_ed25519*")
SECRET_RES = [re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)", re.S),
              re.compile(r"AKIA[0-9A-Z]{16}"),
              re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
              re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
              re.compile(r"Bearer\s+[^\s\"'\\]+")]
CTRL_RE = re.compile("[\x00-\x1f\x7f-\x9f]")
UNSAFE_MSG = ("tether: unsafe form under lease %s: redirections / ssh options are not allowed; "
              "use: ssh HOST 'command' (single quotes; no local $, braces, globs)")

def is_secret_path(p):
    for c in {p, os.path.realpath(os.path.expanduser(p))}:
        if any(x in c for x in SECRET_SUBSTR):
            return True
        if any(fnmatch.fnmatch(os.path.basename(c), g) for g in SECRET_BASE):
            return True
    return False

def redact(s):
    for rx in SECRET_RES:
        s = rx.sub("[REDACTED]", s)
    return s

def clean(s):
    """Make agent-controlled text safe to print to a terminal: ESC -> ^[, other C0/C1 dropped."""
    return CTRL_RE.sub("", str(s).replace("\x1b", "^["))

def now():
    return dt.datetime.now(dt.timezone.utc)

def iso(t):
    return t.astimezone().isoformat(timespec="seconds")

def parse_ts(s):
    t = dt.datetime.fromisoformat(s)
    return t if t.tzinfo else t.astimezone()

def parse_dur(s):
    m = re.fullmatch(r"(\d+)([mhd])", s)
    if not m:
        sys.exit("duration must look like 30m, 10h or 2d")
    n, u = int(m.group(1)), m.group(2)
    return dt.timedelta(minutes=n) if u == "m" else dt.timedelta(hours=n) if u == "h" else dt.timedelta(days=n)

# ---------------- log ----------------
def append_log(entry):
    entry.setdefault("ts", iso(now()))
    line = json.dumps(entry, separators=(",", ":")) + "\n"
    fd = os.open(LOG, os.O_WRONLY | os.O_APPEND)
    try:
        os.write(fd, line.encode())
    finally:
        os.close(fd)

def read_log():
    out = []
    try:
        with open(LOG, encoding="utf-8", errors="replace") as f:
            for l in f:
                try:
                    out.append(json.loads(l))
                except ValueError:
                    pass
    except FileNotFoundError:
        pass
    return out

# ---------------- leases / matching ----------------
def load_leases():
    try:
        with open(LEASES) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return []

def load_policy():
    try:
        with open(POLICY) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}

def policy_ok(rule, pol=None):
    rx = (pol if pol is not None else load_policy()).get("allow_rule_regex")
    return True if not rx else re.search(rx, rule) is not None

INTERP_RE = re.compile(r"^(python[\d.]*|pypy[\d.]*|bash|sh|zsh|dash|ksh|fish|node|nodejs|deno|bun|ruby|perl|php|"
                       r"lua|Rscript|osascript|tclsh)$")
PROJECT_FILE = {"make": "Makefile", "gmake": "Makefile", "npm": "package.json", "npx": "package.json",
                "yarn": "package.json", "pnpm": "package.json"}

def agent_writable(p):
    """True unless p (or, if missing, its nearest existing ancestor) and every directory above it are
    root-owned and not group/other writable. A root-owned file in a user-owned dir can be swapped out."""
    p = os.path.realpath(os.path.expanduser(p))
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    while True:
        st = os.stat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return True
        if p in ("/", ""):
            return False
        p = os.path.dirname(p)

def writable_targets(rule):
    """Files a Bash rule would execute that a non-root user could edit (=> lease = arbitrary exec):
    paths, bare tokens naming a file in the current dir, interpreter + script, make/npm project files."""
    m = RULE_RE.match(rule.strip())
    if not m or m.group(1) != "Bash" or not m.group(2):
        return []
    spec = m.group(2)[:-2] if m.group(2).endswith(":*") else m.group(2)
    try:
        toks = shlex.split(spec)
    except ValueError:
        toks = spec.split()
    cwd = os.getcwd()
    bad = []
    def chk(p, label=None):
        if agent_writable(p):
            bad.append(label or os.path.realpath(p))
    for tok in toks:
        p = os.path.expanduser(tok)
        if os.path.sep in p:
            chk(p)
        elif os.path.isfile(os.path.join(cwd, p)):
            chk(os.path.join(cwd, p))
    if toks:
        c0 = os.path.basename(toks[0])
        args = toks[1:]
        if INTERP_RE.match(c0):
            script = next((a for a in args if not a.startswith("-")), None)
            if "-m" in args:
                bad.append("%s -m (imports modules from the working dir)" % c0)
            elif "-c" in args or "-e" in args:
                pass                                   # inline code fixed by the rule itself
            elif script is None:
                bad.append("%s with no fixed script (runs any code)" % c0)
            elif os.path.sep not in os.path.expanduser(script):
                chk(os.path.join(cwd, script))         # missing => agent can create it
        elif c0 in PROJECT_FILE:
            chk(os.path.join(cwd, PROJECT_FILE[c0]),
                "%s (%s runs ./%s)" % (os.path.join(os.path.realpath(cwd), PROJECT_FILE[c0]), c0, PROJECT_FILE[c0]))
    return sorted(set(bad))

def lease_active(l, t=None):
    return parse_ts(l["expires"]) > (t or now())

RULE_RE = re.compile(r"^([A-Za-z_][\w.\-]*)(?:\((.*)\))?$", re.S)
def split_cmd(cmd):
    """Split on && || ; | & newline OUTSIDE quotes. Returns None if unparseable or if it contains
    command substitution outside single quotes ($(...) or backticks): never auto-allow those.
    An & that is part of a redirection (&> >& <&) is not a separator."""
    parts, cur, i, q, redir = [], [], 0, None, False
    while i < len(cmd):
        ch = cmd[i]
        if q == "'":
            cur.append(ch); q = None if ch == "'" else q; i += 1; continue
        if ch == "\\" and i + 1 < len(cmd):
            cur.append(cmd[i:i + 2]); i += 2; redir = False; continue
        if q == '"':
            if ch == "`" or cmd.startswith("$(", i):
                return None
            cur.append(ch); q = None if ch == '"' else q; i += 1; continue
        if ch in "'\"":
            q = ch; cur.append(ch); i += 1; redir = False; continue
        if ch == "`" or cmd.startswith("$(", i):
            return None
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            parts.append("".join(cur)); cur = []; i += 2; redir = False; continue
        if ch == "&" and (redir or cmd[i + 1:i + 2] == ">"):
            cur.append(ch); i += 1; redir = False; continue
        if ch in ";|&\n":
            parts.append("".join(cur)); cur = []; i += 1; redir = False; continue
        cur.append(ch); i += 1; redir = ch in "<>"
    if q:
        return None
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]

def has_redirect(s):
    """Any < or > outside quotes and not backslash-escaped (covers <( >( << &> 2>)."""
    q, i = None, 0
    while i < len(s):
        ch = s[i]
        if q == "'":
            q = None if ch == "'" else q
        elif ch == "\\":
            i += 2; continue
        elif q == '"':
            q = None if ch == '"' else q
        elif ch in "'\"":
            q = ch
        elif ch in "<>":
            return True
        i += 1
    return False

def bash_tokens(s):
    """Shell-like tokens (quotes removed, < > & | ; ( ) split off) or None if unparseable."""
    try:
        lx = shlex.shlex(s, posix=True, punctuation_chars=True)
        lx.whitespace_split = True
        return list(lx)
    except ValueError:
        return None

def lease_prefix(rule):
    """Bash(PREFIX:*) / Bash(EXACT) -> (prefix tokens, is_wildcard); None for other rules or bare Bash."""
    m = RULE_RE.match(rule.strip())
    if not m or m.group(1) != "Bash" or m.group(2) in (None, "", "*"):
        return None
    spec = m.group(2)
    wild = spec.endswith(":*")
    toks = bash_tokens(spec[:-2] if wild else spec)
    return (toks, wild) if toks else None

def loosely_covers(rule, toks):
    """Token-level prefix match, tolerant of extra whitespace, quoting and redirects glued to words,
    so `ssh  nexus -o ...` or `ssh nexus>f` still count as 'under the lease' for deny purposes."""
    lp = lease_prefix(rule)
    return bool(lp) and toks is not None and toks[:len(lp[0])] == lp[0]

def scan_ctx(s):
    """[(char, ctx)] with ctx u=unquoted, s=in '...', d=in "...", e=backslash-escaped, q=quote/escape char."""
    out, q, i = [], None, 0
    while i < len(s):
        ch = s[i]
        if q == "'":
            if ch == "'":
                q = None; out.append((ch, "q"))
            else:
                out.append((ch, "s"))
        elif ch == "\\" and i + 1 < len(s):
            out.append((ch, "q")); out.append((s[i + 1], "e")); i += 2; continue
        elif q == '"':
            if ch == '"':
                q = None; out.append((ch, "q"))
            else:
                out.append((ch, "d"))
        elif ch in "'\"":
            q = ch; out.append((ch, "q"))
        else:
            out.append((ch, "u"))
        i += 1
    return out

def raw_words(ctx):
    words, cur = [], []
    for ch, c in ctx:
        if c == "u" and ch in " \t\n":
            if cur:
                words.append(cur); cur = []
        else:
            cur.append((ch, c))
    if cur:
        words.append(cur)
    return words

BRACE_RE = re.compile(r"\{[^{}\s]*(,|\.\.)[^{}\s]*\}")
FIRST_OK = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_./~'\"")

def unsafe_under(rule, sub, toks):
    """-> short description of the unsafe construct, or None. Only for subs loosely covered by rule."""
    if not loosely_covers(rule, toks):
        return None
    if has_redirect(sub):
        return "redirection"
    ctx = scan_ctx(sub)
    if any(ch == "$" and c != "s" for ch, c in ctx):
        return "$ outside single quotes (local expansion)"
    if BRACE_RE.search("".join(ch if c == "u" else "\x00" for ch, c in ctx)):
        return "brace expansion"
    ptoks, wild = lease_prefix(rule)
    words = raw_words(ctx)
    if wild and len(words) > len(ptoks):
        w = words[len(ptoks)]
        if w[0][0] not in FIRST_OK or (w[0][1] == "q" and w[0][0] == "\\"):
            return "first argument starts with %r" % w[0][0]
        for j, (ch, c) in enumerate(w):
            if c == "u" and (ch in "{}*?[" or (ch == "~" and j + 1 < len(w) and w[j + 1][0] == "-")):
                return "glob/expansion in first argument"
    rest = toks[len(ptoks):]
    if wild and rest and rest[0].startswith("-"):
        return "ssh option after host"
    return None

def subst_under_lease(cmd, act):
    """Command has $(...) or backticks: deny if any segment starts with an active lease prefix."""
    toks = bash_tokens(cmd)
    if toks is None:
        return None
    seg, segs = [], []
    for t_ in toks + [";"]:
        if t_ in (";", "&&", "||", "|", "&", "\n"):
            if seg:
                segs.append(seg); seg = []
        else:
            seg.append(t_)
    return next((l for l in act for sg in segs if loosely_covers(l["rule"], sg)), None)

def norm_pattern(pat):
    """realpath() the literal directory part of an absolute glob, so it compares with realpath()ed paths."""
    if not pat.startswith("/"):
        return pat
    g = min([pat.find(c) for c in "*?[" if c in pat] or [len(pat)])
    if g == len(pat):
        return os.path.realpath(pat)
    head = pat[:pat.rfind("/", 0, g)]
    return (os.path.realpath(head) + pat[len(head):]) if head else pat

def spec_matches(tool, spec, tool_input, sub=None):
    if spec is None or spec in ("", "*"):
        return True
    if tool == "Bash":
        c = sub if sub is not None else tool_input.get("command", "")
        if spec.endswith(":*"):
            p = spec[:-2]
            return c == p or c.startswith(p + " ")
        return c == spec
    path = tool_input.get(FILE_TOOLS.get(tool, "file_path")) or tool_input.get("path") or ""
    if not path or ".." in re.split(r"[/\\]", path):
        return False                          # never lease-match a path with a .. component
    path = os.path.realpath(os.path.expanduser(path))
    pat = spec[1:] if spec.startswith("//") else os.path.expanduser(spec)
    return fnmatch.fnmatch(path, norm_pattern(pat))

def rule_matches(rule, tool, tool_input, sub=None):
    m = RULE_RE.match(rule.strip())
    return bool(m) and m.group(1) == tool and spec_matches(tool, m.group(2), tool_input, sub)

def expired_ask(l):
    return "ask", "tether: lease %s expired at %s — asking instead of auto-allowing" % (l["rule"], l["expires"]), l["rule"]


# Allow-list gate for leased Bash commands. Deny-listing shell syntax is whack-a-mole across bash AND zsh
# (zsh: =(cmd) runs cmd, *(e:'cmd':) glob qualifiers run code, ...). Under an active lease the remainder after
# the leased prefix must be ONLY plain words or single-quoted strings, in which no local shell expands anything.
SAFE_WORD = r"[A-Za-z0-9_./:@%+=,-]+"
SAFE_SQ = r"(?:'[^']*')+"
SAFE_REST = re.compile(r"^(?:\s+(?:%s|%s))*\s*$" % (SAFE_WORD, SAFE_SQ))
FIRST = re.compile(r"^\s+(%s|%s)" % (SAFE_WORD, SAFE_SQ))

def strict_shape(rule, sub):
    """None if `sub` is in the allowed shape for this lease, else a reason string."""
    m = RULE_RE.match(rule.strip())
    spec = m.group(2) if m else ""
    exact = spec[:-2] if spec.endswith(":*") else spec
    if sub == exact:
        return None
    if not sub.startswith(exact + " "):
        return "command must start with exactly '%s ' (single spaces, no quoting of the prefix)" % exact
    rest = sub[len(exact):]
    if not SAFE_REST.match(rest):
        return "only plain words [A-Za-z0-9_./:@%+=,-] or 'single-quoted' strings may follow the prefix"
    if re.search(r"(?:^|\s)=", rest):
        return "words starting with '=' trigger zsh =cmd expansion; quote them"
    f = FIRST.match(rest)
    if f:
        w = f.group(1)
        if w.startswith(("-", "=")) or w.lstrip("'").startswith("-"):
            return "first argument after the prefix may not start with '-' or '=' (ssh option / zsh =cmd expansion)"
    return None

def decide(tool, tool_input, leases, t=None):
    """-> (decision or None, reason, lease_rule)"""
    pol = load_policy()
    act = [l for l in leases if lease_active(l, t) and policy_ok(l["rule"], pol)]
    exp = [l for l in leases if not lease_active(l, t)]
    if tool == "Bash":
        subs = split_cmd(tool_input.get("command", ""))
        if not subs:                      # empty, unbalanced quotes, or command substitution
            bad = subst_under_lease(tool_input.get("command", ""), act) if subs is None else None
            if bad:
                return "deny", UNSAFE_MSG % bad["rule"] + " (found: command substitution)", bad["rule"]
            return None, "", None
        toks = [bash_tokens(s) for s in subs]
        if any(t_ is None for t_ in toks):
            return None, "", None
        # Unsafe form under an ACTIVE lease => deny: the lease is also a managed allow rule, and
        # only a hook deny overrides an allow rule.
        for s, tk in zip(subs, toks):
            for l in act:
                if loosely_covers(l["rule"], tk):
                    why = strict_shape(l["rule"], s)
                    if why:
                        return "deny", UNSAFE_MSG % l["rule"] + " (found: %s)" % why, l["rule"]
                why = unsafe_under(l["rule"], s, tk)
                if why:
                    return "deny", UNSAFE_MSG % l["rule"] + " (found: %s)" % why, l["rule"]
        cover = []
        for s, tk in zip(subs, toks):
            hit = next((l for l in act if rule_matches(l["rule"], tool, tool_input, s)), None)
            if hit is None:
                gone = next((l for l in exp if rule_matches(l["rule"], tool, tool_input, s)
                             or loosely_covers(l["rule"], tk)), None)
                if gone:
                    return expired_ask(gone)
                return None, "", None
            cover.append(hit["rule"])
        return "allow", "tether lease: " + ", ".join(sorted(set(cover))), cover[0]
    hit = next((l for l in act if rule_matches(l["rule"], tool, tool_input)), None)
    if hit:
        return "allow", "tether lease: " + hit["rule"], hit["rule"]
    gone = next((l for l in exp if rule_matches(l["rule"], tool, tool_input)), None)
    if gone:
        return expired_ask(gone)
    return None, "", None

# ---------------- hook ----------------
def hook(phase):
    try:
        ev = json.load(sys.stdin)
    except ValueError:
        ev = {}
    tool = ev.get("tool_name", "?")
    ti = ev.get("tool_input") or {}
    e = {"phase": phase, "id": uuid.uuid4().hex[:12], "tool_use_id": ev.get("tool_use_id"),
         "session": ev.get("session_id"), "cwd": ev.get("cwd"), "tool": tool}
    out = None
    if phase == "pre":
        e["input"] = ti
        if tool in FILE_TOOLS:
            p = ti.get(FILE_TOOLS[tool], "")
            e["path"] = p
            if p and os.path.isfile(p):
                if is_secret_path(p):
                    e["prior_b64"] = None; e["prior_note"] = "secret path: not snapshotted"
                elif os.path.getsize(p) <= MAX_BLOB:
                    with open(p, "rb") as f:
                        e["prior_b64"] = base64.b64encode(f.read()).decode()
                else:
                    e["prior_b64"] = None; e["prior_note"] = "too large to snapshot"
                e["existed"] = True
            else:
                e["existed"] = False
        d, why, rule = decide(tool, ti, load_leases())
        if d:
            e["decision"], e["lease"] = d, rule
            out = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                          "permissionDecision": d, "permissionDecisionReason": why}}
    else:
        if tool == "Read":
            e["response_note"] = "Read response not logged"
        else:
            r = ev.get("tool_response")
            s = redact(r if isinstance(r, str) else json.dumps(r))
            e["response"] = s[:MAX_RESPONSE] + ("…[truncated %d chars]" % (len(s) - MAX_RESPONSE)
                                                 if len(s) > MAX_RESPONSE else "")
    try:
        append_log(e)
    except OSError as err:
        # Can't audit → never auto-allow; fall back to normal prompting.
        out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                      "permissionDecisionReason": "tether log unwritable: %s" % err}} if phase == "pre" else None
    if out:
        print(json.dumps(out))
    return 0

# ---------------- root commands ----------------
def need_root():
    if os.geteuid() != 0 and not PREFIX:
        sys.exit("run with sudo")

def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return default

def load_locked():
    return load_json(LOCKED, None)

def managed_doc(leases, drop_hooks=None):
    """drop_hooks: {event: [entries]} copied in by a previous lock-hooks, to remove now."""
    doc = load_json(MANAGED, {})
    pre = {"matcher": "*", "hooks": [{"type": "command", "command": "%s %s/tether.py hook pre" % (PY, LIB), "timeout": 15}]}
    post = {"matcher": "*", "hooks": [{"type": "command", "command": "%s %s/tether.py hook post" % (PY, LIB), "timeout": 15}]}
    locked = load_locked()
    extra = (locked or {}).get("hooks") or {}
    strip = {}
    for src in (extra, drop_hooks or {}):
        for ev, lst in src.items():
            strip.setdefault(ev, []).extend(lst)
    mine = {"PreToolUse": [pre], "PostToolUse": [post]}
    hooks = doc.setdefault("hooks", {})
    for ev in sorted(set(hooks) | set(extra) | set(mine)):
        lst = [x for x in hooks.get(ev, []) if "tether.py" not in json.dumps(x) and x not in strip.get(ev, [])]
        hooks[ev] = mine.get(ev, []) + lst + extra.get(ev, [])
        if not hooks[ev]:
            del hooks[ev]
    if locked:
        doc["allowManagedHooksOnly"] = True
    perms = doc.setdefault("permissions", {})
    allow = [r for r in perms.get("allow", []) if r not in {l["rule"] for l in leases}]
    pol = load_policy()
    perms["allow"] = allow + sorted({l["rule"] for l in leases if lease_active(l) and policy_ok(l["rule"], pol)})
    lock = ["Edit(/%s/**)" % LIB, "Write(/%s/**)" % LIB,
            "Edit(/%s/**)" % ETC, "Write(/%s/**)" % ETC,
            "Edit(/%s)" % MANAGED, "Write(/%s)" % MANAGED, "Read(/%s/ssh/**)" % ETC,
            "Edit(~/.claude/settings.json)", "Write(~/.claude/settings.json)",
            "Edit(~/.claude/settings.local.json)", "Write(~/.claude/settings.local.json)",
            "Edit(**/.claude/**)", "Write(**/.claude/**)",
            "Edit(**/.git/hooks/**)", "Write(**/.git/hooks/**)"]
    perms["deny"] = sorted(set(perms.get("deny", [])) | set(lock))
    # Ignore allow/ask/deny rules from user/project/local settings, so an agent that writes
    # ~/.claude/settings.json via a shell command still can't grant itself anything.
    doc["allowManagedPermissionRulesOnly"] = True
    return doc

def write_root(path, data, mode=0o644):
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        f.write(data)
    os.chmod(tmp, mode)
    if not PREFIX:
        os.chown(tmp, 0, 0)
    os.replace(tmp, path)

def regen():
    leases = load_leases()
    write_root(LEASES, json.dumps(leases, indent=1))
    write_root(MANAGED, json.dumps(managed_doc(leases), indent=2))

def cmd_install():
    need_root()
    src = os.path.dirname(os.path.realpath(__file__))
    try:
        first = "tether.py hook pre" not in open(MANAGED).read()
    except OSError:
        first = True
    for d in (LIB, ETC, LOGDIR, os.path.dirname(MANAGED), os.path.dirname(BIN)):
        os.makedirs(d, exist_ok=True)
    if os.path.exists(MANAGED) and not os.path.exists(MANAGED + ".pre-tether"):
        shutil.copy2(MANAGED, MANAGED + ".pre-tether")
    shutil.copy2(os.path.join(src, "tether.py"), LIB + "/tether.py")
    os.chmod(LIB + "/tether.py", 0o755)
    if not PREFIX:
        for p in (LIB, LIB + "/tether.py", ETC, LOGDIR):
            os.chown(p, 0, 0)
    if not os.path.exists(LEASES):
        write_root(LEASES, "[]")
    if not os.path.exists(LOG):           # first install only: an existing sappnd log can't be chmod'ed, even by root
        open(LOG, "a").close()
        os.chmod(LOG, 0o660)              # root:staff 660 -- staff (the agent's user) may append, others can't read
        if not PREFIX:
            import grp
            os.chown(LOG, 0, grp.getgrnam("staff").gr_gid)
            subprocess.run(["chflags", "sappnd", LOG], check=True)
    if os.path.lexists(BIN):
        os.remove(BIN)
    os.symlink(LIB + "/tether.py", BIN)
    regen()
    append_log({"phase": "admin", "action": "install", "by": os.environ.get("SUDO_USER", "?")})
    if first:
        print("installed. Restart Claude Code (claude --continue) so the hooks load. Then: tether status")
    else:
        print("reinstalled. Managed settings reload live; changes are in effect now. Check: tether status")

def cmd_grant(rule, dur, note, force=False):
    need_root()
    if not RULE_RE.match(rule.strip()):
        sys.exit("bad rule: %r  (e.g. 'Bash(ssh nexus:*)')" % rule)
    if not policy_ok(rule):
        sys.exit("refused: rule does not match policy allow_rule_regex %r (see: tether policy)" % load_policy().get("allow_rule_regex"))
    bad = writable_targets(rule)
    if bad and not force:
        sys.exit("refused: the agent can edit %s, so this lease would let it run anything.\n"
                 "Lease a root-owned path instead, or pass --force if you accept that." % ", ".join(bad))
    leases = load_leases()
    ssh_cleanup(leases)
    t = now()
    leases.append({"rule": rule.strip(), "granted": iso(t), "expires": iso(t + parse_dur(dur)),
                   "note": note, "by": os.environ.get("SUDO_USER", "?")})
    write_root(LEASES, json.dumps(leases, indent=1))
    regen()
    append_log({"phase": "admin", "action": "grant", "rule": rule, "expires": leases[-1]["expires"], "note": note})
    print("granted %s until %s" % (rule, leases[-1]["expires"]))

def cmd_revoke(rule):
    need_root()
    leases, t = load_leases(), iso(now())
    n = 0
    for l in leases:
        if lease_active(l) and (rule is None or l["rule"] == rule):
            l["expires"] = t; n += 1
    ssh_cleanup(leases)
    write_root(LEASES, json.dumps(leases, indent=1))
    if ssh_leases(leases):
        write_ssh_config(leases)
    regen()
    append_log({"phase": "admin", "action": "revoke", "rule": rule or "ALL", "count": n})
    print("revoked %d lease(s)" % n)

def user_home():
    u = os.environ.get("SUDO_USER")
    if u and not PREFIX:
        import pwd
        return pwd.getpwnam(u).pw_dir
    return os.path.expanduser("~")

def cmd_lock_hooks():
    need_root()
    if not os.path.exists(LIB + "/tether.py"):
        sys.exit("tether is not installed; run: sudo tether install")
    src = os.path.join(user_home(), ".claude", "settings.json")
    try:
        with open(src) as f:
            uh = json.load(f).get("hooks") or {}
    except FileNotFoundError:
        uh = {}
    except ValueError as err:
        sys.exit("cannot parse %s: %s" % (src, err))
    if not isinstance(uh, dict):
        sys.exit("%s: hooks is not an object" % src)
    prev = load_locked() or {}
    prev_hooks = prev.get("hooks") or {}
    cur = load_json(MANAGED, {}).get("hooks") or {}
    take = {}
    for ev, lst in uh.items():
        have = [x for x in cur.get(ev, []) if x not in prev_hooks.get(ev, [])]
        new = [x for x in (lst or []) if x not in have and "tether.py" not in json.dumps(x)]
        if new:
            take[ev] = new
    prior = prev["prior_allowManagedHooksOnly"] if prev else load_json(MANAGED, {}).get("allowManagedHooksOnly")
    write_root(LOCKED, json.dumps({"source": src, "locked": iso(now()), "hooks": take,
                                   "prior_allowManagedHooksOnly": prior}, indent=1))
    write_root(MANAGED, json.dumps(managed_doc(load_leases(), drop_hooks=prev_hooks), indent=2))
    n = sum(len(v) for v in take.values())
    append_log({"phase": "admin", "action": "lock-hooks", "source": src, "hooks": take})
    print("hooks locked: allowManagedHooksOnly=true; %d hook group(s) copied from %s into managed settings:" % (n, src))
    for ev, lst in sorted(take.items()):
        for x in lst:
            print("  %s %s" % (ev, clean(json.dumps(x))))
    print("Review the hooks above: they now run from managed scope. Re-run lock-hooks after editing your own hooks.")

def cmd_unlock_hooks():
    need_root()
    prev = load_locked()
    if prev is None:
        sys.exit("hooks are not locked")
    os.remove(LOCKED)
    doc = managed_doc(load_leases(), drop_hooks=prev.get("hooks"))
    if prev.get("prior_allowManagedHooksOnly") is None:
        doc.pop("allowManagedHooksOnly", None)
    else:
        doc["allowManagedHooksOnly"] = prev["prior_allowManagedHooksOnly"]
    write_root(MANAGED, json.dumps(doc, indent=2))
    append_log({"phase": "admin", "action": "unlock-hooks"})
    print("hooks unlocked: user/project hooks run again; copied hooks removed from managed settings")

def cmd_uninstall():
    need_root()
    append_log({"phase": "admin", "action": "uninstall"})
    if os.path.exists(MANAGED + ".pre-tether"):
        os.replace(MANAGED + ".pre-tether", MANAGED)
    elif os.path.exists(MANAGED):
        os.remove(MANAGED)
    for p in (BIN, LOCKED):
        if os.path.lexists(p):
            os.remove(p)
    shutil.rmtree(LIB, ignore_errors=True)
    print("uninstalled hooks + managed settings. Log kept (append-only) at", LOG)

# ---------------- temporary ssh keys ----------------
HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_VAL_RE = re.compile(r"^[A-Za-z0-9._:%\[\]-]+$")
PERMITOPEN_RE = re.compile(r"^(\[[0-9A-Fa-f:.]+\]|[A-Za-z0-9.*-]+):(\d{1,5}|\*)$")
# Remote side, run by the user's own ssh. Drops tether: lines whose expiry-time has passed and lines for
# the lease ids in $1 (space separated), then appends stdin (if any). Atomic replace via mv.
REMOTE_SCRIPT = r'''umask 077; mkdir -p "$HOME/.ssh" || exit 1; f="$HOME/.ssh/authorized_keys"; touch "$f" || exit 1
now=$(date -u +%Y%m%d%H%M)
awk -v now="$now" -v drop=" $1 " '
  /tether:[0-9a-f]+[ \t]*$/ {
    id = $NF; sub(/^tether:/, "", id)
    if (index(drop, " " id " ")) next
    if (match($0, /expiry-time="[0-9]+Z?"/)) { e = substr($0, RSTART + 13, 12); if (e <= now) next }
  }
  { print }' "$f" > "$f.tether.tmp" || exit 1
cat >> "$f.tether.tmp" && chmod 600 "$f.tether.tmp" && mv "$f.tether.tmp" "$f"'''

def ssh_bin():
    return os.environ.get("TETHER_SSH", "/usr/bin/ssh")

def invoking_user():
    import pwd
    u = os.environ.get("SUDO_USER")
    if u and not PREFIX:
        return pwd.getpwnam(u)
    return pwd.getpwuid(os.getuid())

def agent_sock(pw):
    s = os.environ.get("SSH_AUTH_SOCK")
    if s or PREFIX or os.geteuid() != 0:
        return s
    try:   # sudo strips the env; ask the user's launchd session for its agent socket
        r = subprocess.run(["launchctl", "asuser", str(pw.pw_uid), "launchctl", "getenv", "SSH_AUTH_SOCK"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or None
    except (OSError, subprocess.SubprocessError):
        return None

def run_user(argv, input=None, timeout=60):
    """Run argv as the invoking (sudo) user, with their HOME and ssh agent."""
    pw = invoking_user()
    if PREFIX:
        env = dict(os.environ)
    else:
        env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
               "HOME": pw.pw_dir, "USER": pw.pw_name, "LOGNAME": pw.pw_name}
        sock = agent_sock(pw)
        if sock:
            env["SSH_AUTH_SOCK"] = sock
    kw = {}
    if os.geteuid() == 0 and not PREFIX:
        kw = {"user": pw.pw_uid, "group": pw.pw_gid, "extra_groups": os.getgrouplist(pw.pw_name, pw.pw_gid)}
    try:
        return subprocess.run(argv, input=input, capture_output=True, text=True, env=env, timeout=timeout,
                              cwd=pw.pw_dir if not PREFIX else None, **kw)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(argv, 124, "", "timed out after %ds" % timeout)
    except OSError as err:
        return subprocess.CompletedProcess(argv, 127, "", str(err))

def as_user(fn):
    """Run fn() with the invoking user's uid/gid (so root never writes into the user's home)."""
    if os.geteuid() != 0 or PREFIX:
        return fn()
    pw = invoking_user()
    pid = os.fork()
    if pid == 0:
        try:
            os.initgroups(pw.pw_name, pw.pw_gid); os.setgid(pw.pw_gid); os.setuid(pw.pw_uid)
            fn(); os._exit(0)
        except BaseException as err:          # noqa: report and fail the child only
            sys.stderr.write("tether: %s\n" % err); os._exit(1)
    _, st = os.waitpid(pid, 0)
    if st:
        sys.exit("tether: editing files as %s failed" % pw.pw_name)

def ssh_dir():
    return ETC + "/ssh"

def ssh_key(host):
    return "%s/%s-claude" % (ssh_dir(), host)

def ssh_leases(leases):
    return [l for l in leases if l.get("ssh")]

def host_alias_exists(home, host):
    try:
        with open(os.path.join(home, ".ssh", "config")) as f:
            for line in f:
                t = line.strip().split()
                if t and t[0].lower() == "host" and host in t[1:]:
                    return True
    except OSError:
        pass
    return False

def ssh_resolve(host):
    r = run_user([ssh_bin(), "-G", host], timeout=20)
    if r.returncode:
        sys.exit("ssh -G %s failed: %s" % (host, r.stderr.strip()))
    opts = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        opts.setdefault(k.lower(), v.strip())
    for k in ("hostname", "user", "port"):
        if not SAFE_VAL_RE.match(opts.get(k, "")):
            sys.exit("ssh -G %s: unusable %s %r" % (host, k, opts.get(k)))
    if opts.get("hostkeyalias") and not SAFE_VAL_RE.match(opts["hostkeyalias"]):
        opts.pop("hostkeyalias")
    return opts

def tailnet_ip():
    import ipaddress
    ts = os.environ.get("TETHER_TAILSCALE") or shutil.which("tailscale") or "/usr/local/bin/tailscale"
    r = run_user([ts, "ip", "-4"], timeout=15)
    ip = (r.stdout.split() or [""])[0] if r.returncode == 0 else ""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        return None

def write_ssh_config(leases):
    """Root-owned client config with one Host block per active ssh lease."""
    out = ["# managed by tether -- regenerated on every grant/revoke; do not edit"]
    for l in ssh_leases(leases):
        if not lease_active(l):
            continue
        s = l["ssh"]
        out += ["Host %s" % s["alias"], "  HostName %s" % s["hostname"], "  User %s" % s["user"],
                "  Port %s" % s["port"], '  IdentityFile "%s"' % s["key"], "  IdentitiesOnly yes",
                "  IdentityAgent none", "  ExitOnForwardFailure yes", "  ServerAliveInterval 30"]
        if s.get("hostkeyalias"):
            out.append("  HostKeyAlias %s" % s["hostkeyalias"])
    os.makedirs(ssh_dir(), exist_ok=True)
    write_root(ssh_dir() + "/config", "\n".join(out) + "\n")

def ensure_include(home):
    """Put `Include "<tether ssh config>"` as the first line of ~/.ssh/config (idempotent, backed up)."""
    inc = 'Include "%s/config"' % ssh_dir()
    def edit():
        d = os.path.join(home, ".ssh"); p = os.path.join(d, "config")
        os.makedirs(d, mode=0o700, exist_ok=True)
        try:
            with open(p) as f:
                old = f.read()
        except FileNotFoundError:
            old = None
        lines = (old or "").splitlines()
        if lines and lines[0].strip() == inc:
            return
        if old is not None and not os.path.exists(p + ".bak-tether"):
            shutil.copy2(p, p + ".bak-tether")
        new = "\n".join([inc] + [x for x in lines if x.strip() != inc]) + "\n"
        tmp = p + ".tether.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(new)
        if old is not None:
            os.chmod(tmp, os.stat(p).st_mode & 0o777)
        os.replace(tmp, p)
    as_user(edit)

def remote_edit(host, drop_ids, new_line=None):
    """Run REMOTE_SCRIPT on HOST as the user. -> CompletedProcess"""
    cmd = "sh -c %s tether %s" % (shlex.quote(REMOTE_SCRIPT), shlex.quote(" ".join(drop_ids)))
    return run_user([ssh_bin(), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", host, cmd],
                    input=(new_line + "\n") if new_line else "", timeout=60)

def ssh_cleanup(leases):
    """Destroy local private keys whose lease expired (unlink as root, else truncate: the user owns them)."""
    live = {l["ssh"]["key"] for l in ssh_leases(leases) if lease_active(l)}
    for l in ssh_leases(leases):
        k = l["ssh"]["key"]
        if lease_active(l) or k in live:
            continue
        for p in (k, k + ".pub"):
            try:
                if os.geteuid() == 0 or PREFIX:
                    os.remove(p)
                elif p == k and os.path.getsize(p):
                    open(p, "w").close()
            except OSError:
                pass

def utc_stamp(t):
    return t.astimezone(dt.timezone.utc).strftime("%Y%m%d%H%MZ")

def listen_opt(permitlisten):
    """authorized_keys has no permitlisten="none" (sshd rejects the whole key line: "invalid permission
    port"). `port-forwarding` re-enables -R too, so "none" maps to 127.0.0.1:1: a privileged port a
    non-root login can never bind, which leaves remote forwarding effectively off."""
    return "127.0.0.1:1" if permitlisten == "none" else permitlisten

def extra_identities(alias, key):
    """IdentityFile lines from the user's own config (e.g. `Host *`) also apply to the alias, because
    ssh_config accumulates IdentityFile. Return any besides the lease key."""
    r = run_user([ssh_bin(), "-G", alias], timeout=15)
    out = []
    for ln in (r.stdout or "").splitlines():
        k, _, v = ln.partition(" ")
        if k.lower() == "identityfile" and os.path.realpath(os.path.expanduser(v)) != os.path.realpath(key):
            out.append(v)
    return out

def cmd_ssh_grant(host, dur, note, frm=None, permitopen="127.0.0.1:8080", permitlisten="none"):
    need_root()
    if not HOST_RE.match(host):
        sys.exit("bad host alias %r" % host)
    pw = invoking_user()
    home = user_home()
    if not host_alias_exists(home, host):
        sys.exit("%s is not a Host alias in %s/.ssh/config" % (host, home))
    alias = host + "-claude"
    rule = "Bash(ssh %s:*)" % alias
    if not policy_ok(rule):
        sys.exit("refused: %s does not match policy allow_rule_regex (see: tether policy)" % rule)
    opens = [x.strip() for x in permitopen.split(",") if x.strip()]
    for x in opens:
        if not PERMITOPEN_RE.match(x):
            sys.exit("bad --permitopen entry %r (want host:port)" % x)
    if permitlisten != "none" and not PERMITOPEN_RE.match(permitlisten) and not re.fullmatch(r"\d{1,5}", permitlisten):
        sys.exit("bad --permitlisten %r" % permitlisten)
    frm = frm or tailnet_ip()
    if not frm:
        sys.exit("could not get this Mac's tailnet IP from `tailscale ip -4`; pass --from IP")
    import ipaddress
    try:
        frm = str(ipaddress.ip_address(frm))
    except ValueError:
        sys.exit("bad --from %r" % frm)
    opts = ssh_resolve(host)
    leases = load_leases()
    ssh_cleanup(leases)
    t = now(); exp = t + parse_dur(dur); lid = uuid.uuid4().hex[:12]
    os.makedirs(ssh_dir(), exist_ok=True)
    os.chmod(ssh_dir(), 0o755)
    if not PREFIX:
        os.chown(ssh_dir(), 0, 0)
    key = ssh_key(host)
    for p in (key, key + ".pub"):
        if os.path.lexists(p):
            os.remove(p)
    r = subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "tether:" + lid, "-f", key],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit("ssh-keygen failed: %s" % r.stderr.strip())
    os.chmod(key, 0o600); os.chmod(key + ".pub", 0o644)
    if not PREFIX:
        os.chown(key, pw.pw_uid, pw.pw_gid)      # ssh refuses keys others can read; the agent runs as this user
        os.chown(key + ".pub", 0, 0)
    with open(key + ".pub") as f:
        pub = " ".join(f.read().split()[:2])
    fp = subprocess.run(["ssh-keygen", "-lf", key + ".pub"], capture_output=True, text=True).stdout.split()
    fp = fp[1] if len(fp) > 1 else "?"
    o = ["restrict", "pty", "port-forwarding"] + ['permitopen="%s"' % x for x in opens] + \
        ['permitlisten="%s"' % listen_opt(permitlisten), 'expiry-time="%s"' % utc_stamp(exp), 'from="%s"' % frm]
    line = "%s %s tether:%s" % (",".join(o), pub, lid)
    old = [l for l in ssh_leases(leases) if l["ssh"]["host"] == host and not l["ssh"].get("remote_removed")]
    rr = remote_edit(host, [l["ssh"]["id"] for l in old], line)
    if rr.returncode:
        for p in (key, key + ".pub"):
            if os.path.lexists(p):
                os.remove(p)
        sys.exit("installing the key on %s failed (your own `ssh %s` must work non-interactively; if your key is in "
                 "ssh-agent run: sudo --preserve-env=SSH_AUTH_SOCK tether ssh-grant ...):\n  %s"
                 % (host, host, (rr.stderr or rr.stdout).strip()))
    for l in old:
        l["ssh"]["remote_removed"] = True
        if lease_active(l):
            l["expires"] = iso(t)
    leases.append({"rule": rule, "granted": iso(t), "expires": iso(exp), "note": note, "by": pw.pw_name,
                   "ssh": {"id": lid, "host": host, "alias": alias, "key": key, "fingerprint": fp, "from": frm,
                           "permitopen": opens, "hostname": opts["hostname"], "user": opts["user"],
                           "port": opts["port"], "hostkeyalias": opts.get("hostkeyalias")}})
    write_root(LEASES, json.dumps(leases, indent=1))
    write_ssh_config(leases)
    ensure_include(home)
    regen()
    append_log({"phase": "admin", "action": "ssh-grant", "host": host, "alias": alias, "lease_id": lid,
                "fingerprint": fp, "expires": iso(exp), "from": frm, "permitopen": opens, "note": note})
    print("granted %s until %s (key %s, from %s)" % (rule, iso(exp), fp, frm))
    v = run_user([ssh_bin(), "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", alias, "true"], timeout=30)
    if v.returncode:
        print("WARNING: test login `ssh %s true` failed: %s" % (alias, (v.stderr or "").strip()[:300]))
    extra = extra_identities(alias, key)
    if extra:
        print("WARNING: %s also picks up IdentityFile %s from your own ~/.ssh/config (ssh_config adds these up)."
              % (alias, ", ".join(extra)))
        print("  Harmless while those keys need a passphrase (the alias has no agent), but to keep the alias on the")
        print("  lease key only, exclude it in your config, e.g. change `Host *` to `Host * !*-claude`.")
    else:
        print("verified: `ssh %s true` works" % alias)

def cmd_ssh_revoke(host):
    need_root()
    leases = load_leases()
    mine = [l for l in ssh_leases(leases) if l["ssh"]["host"] == host and not l["ssh"].get("remote_removed")]
    if not mine:
        sys.exit("no ssh lease for %s" % host)
    rr = remote_edit(host, [l["ssh"]["id"] for l in mine])
    t = iso(now())
    for l in mine:
        if lease_active(l):
            l["expires"] = t
        if rr.returncode:
            l["ssh"]["remote_failed"] = t
        else:
            l["ssh"]["remote_removed"] = True; l["ssh"].pop("remote_failed", None)
    ssh_cleanup(leases)
    write_root(LEASES, json.dumps(leases, indent=1))
    write_ssh_config(leases)
    regen()
    append_log({"phase": "admin", "action": "ssh-revoke", "host": host, "lease_ids": [l["ssh"]["id"] for l in mine],
                "remote_removed": rr.returncode == 0})
    if rr.returncode:
        print("lease expired and local key deleted, but removing the key from %s FAILED: %s\n"
              "It stays inert after its expiry-time; retry: sudo tether ssh-revoke %s"
              % (host, (rr.stderr or rr.stdout).strip()[:300], host))
    else:
        print("revoked ssh key(s) for %s on the remote and locally" % host)

def ssh_status_lines(leases, t):
    out = []
    for l in ssh_leases(leases):
        s = l["ssh"]
        left = (parse_ts(l["expires"]) - t).total_seconds()
        st = "ACTIVE %dh%02dm left" % (left // 3600, left % 3600 // 60) if left > 0 else "expired"
        flag = ""
        if left <= 0 and s.get("remote_failed"):
            flag = "  !! expired locally but still on remote (retry: sudo tether ssh-revoke %s)" % s["host"]
        elif left <= 0 and not s.get("remote_removed"):
            flag = "  (remote line inert after expiry-time; removed on next ssh-grant/ssh-revoke)"
        out.append("  %-18s %-14s %s %s%s" % (s["alias"], s["host"], s.get("fingerprint", "?"), st, flag))
    return out

# ---------------- user commands ----------------
def cmd_status():
    t = now()
    leases = load_leases()
    print("leases:")
    for l in leases:
        left = parse_ts(l["expires"]) - t
        st = "ACTIVE %dh%02dm left" % (left.total_seconds() // 3600, left.total_seconds() % 3600 // 60) if left.total_seconds() > 0 else "expired"
        print("  %-40s %-20s %s" % (l["rule"], st, l.get("note") or ""))
    if not leases:
        print("  (none)")
    if ssh_leases(leases):
        ssh_cleanup(leases)
        print("ssh keys:")
        for x in ssh_status_lines(leases, t):
            print(x)
    ok = True
    def chk(cond, msg):
        nonlocal ok
        print("  [%s] %s" % ("ok" if cond else "!!", msg)); ok &= bool(cond)
    print("integrity:")
    for p in (LIB + "/tether.py", LEASES, MANAGED, LOG):
        try:
            s = os.stat(p)
            chk(s.st_uid == 0 or PREFIX, "%s owned by root" % p)
        except FileNotFoundError:
            chk(False, "%s exists" % p)
    try:
        flags = subprocess.run(["ls", "-lO", LOG], capture_output=True, text=True).stdout
        chk("sappnd" in flags or PREFIX, "log has sappnd (append-only) flag")
    except OSError:
        pass
    try:
        chk("tether.py hook pre" in open(MANAGED).read(), "managed settings carry the tether hooks")
    except OSError:
        pass
    if load_json(MANAGED, {}).get("allowManagedHooksOnly"):
        lk = load_locked() or {}
        print("hooks: LOCKED (allowManagedHooksOnly; %d hook group(s) moved from %s)"
              % (sum(len(v) for v in (lk.get("hooks") or {}).values()), lk.get("source", "?")))
    else:
        print("hooks: unlocked (user/project hooks also run; see: sudo tether lock-hooks)")
    n = len(read_log())
    print("log: %s (%d entries)" % (LOG, n))
    return 0 if ok else 1

def fmt(e):
    s = _fmt(e)
    return clean(s) if s else s

def _fmt(e):
    ts = str(e.get("ts", ""))[11:19]
    if e.get("phase") == "admin":
        return "%s ADMIN %s %s" % (ts, e.get("action"), {k: v for k, v in e.items() if k not in ("phase", "action", "ts")})
    if e.get("phase") == "post":
        return None
    ti = e.get("input") or {}
    what = ti.get("command") or ti.get("file_path") or ti.get("notebook_path") or ti.get("pattern") or ti.get("url") or ""
    what = str(what).replace("\n", " ⏎ ")
    dec = (" [%s]" % e["decision"]) if e.get("decision") else ""
    return "%s %s %-6s%s %s" % (ts, e.get("id", ""), e.get("tool", ""), dec, what[:160])

def cmd_log(n, since, tool, grep, as_json):
    rows = read_log()
    if since:
        st = parse_ts(since)
        rows = [r for r in rows if "ts" in r and parse_ts(r["ts"]) >= st]
    if tool:
        rows = [r for r in rows if r.get("tool") == tool]
    if grep:
        rows = [r for r in rows if grep in json.dumps(r)]
    rows = rows[-n:] if n else rows
    for r in rows:
        if as_json:
            print(json.dumps(r))
        else:
            s = fmt(r)
            if s:
                print(s)

def cmd_revert(target, since, dry):
    rows = read_log()
    if since:
        st = parse_ts(since)
        sel = [r for r in rows if r.get("phase") == "pre" and r.get("tool") in FILE_TOOLS and parse_ts(r["ts"]) >= st]
    else:
        sel = [r for r in rows if r.get("phase") == "pre" and (r.get("id") == target or r.get("tool_use_id") == target)]
        if not sel:
            sys.exit("no entry %s" % target)
    done = []
    for r in reversed(sel):            # newest first, so the oldest snapshot wins last
        p = r.get("path")
        if r.get("tool") not in FILE_TOOLS:
            print(clean("%s: %s is not a file edit; manual revert. Command was:" % (r["id"], r["tool"])) + "\n  "
                  + clean((r.get("input") or {}).get("command")))
            continue
        if r.get("existed"):
            if r.get("prior_b64") is None:
                print(clean("%s: no snapshot (%s) for %s" % (r["id"], r.get("prior_note"), p))); continue
            print(clean("%s restore %s" % ("would" if dry else "", p)))
            if not dry:
                with open(p, "wb") as f:
                    f.write(base64.b64decode(r["prior_b64"]))
        else:
            print(clean("%s delete %s (created by %s)" % ("would" if dry else "", p, r["id"])))
            if not dry and os.path.exists(p):
                os.remove(p)
        done.append(r["id"])
    if done and not dry:
        append_log({"phase": "admin", "action": "revert", "ids": done})

def main(a):
    if not a or a[0] in ("-h", "--help", "help"):
        print(__doc__); return 0
    c = a[0]
    if c == "hook":
        return hook(a[1] if len(a) > 1 else "pre")
    if c == "install":
        cmd_install()
    elif c == "grant":
        if len(a) < 3:
            sys.exit("usage: tether grant RULE DURATION [note] [--force]")
        force = "--force" in a
        rest = [x for x in a[3:] if x != "--force"]
        cmd_grant(a[1], a[2], " ".join(rest), force)
    elif c == "policy":
        if len(a) == 1:
            print(json.dumps(load_policy() or {"allow_rule_regex": None}, indent=1)); return 0
        need_root()
        rx = {"ssh-only": r"^Bash\(ssh [^\s]+(:\*)?\)$", "any": None}.get(a[1], a[1])
        if rx:
            re.compile(rx)
        write_root(POLICY, json.dumps({"allow_rule_regex": rx}, indent=1))
        regen()
        append_log({"phase": "admin", "action": "policy", "allow_rule_regex": rx})
        print("policy allow_rule_regex =", rx)
    elif c == "revoke":
        cmd_revoke(None if len(a) < 2 or a[1] == "--all" else a[1])
    elif c == "prune":
        need_root(); lz = load_leases(); ssh_cleanup(lz)
        if ssh_leases(lz):
            write_ssh_config(lz)
        regen(); print("managed allow list now = active leases only")
    elif c in ("ssh-grant", "ssh-revoke"):
        import argparse
        p = argparse.ArgumentParser(prog="tether " + c)
        p.add_argument("host")
        if c == "ssh-grant":
            p.add_argument("duration"); p.add_argument("note", nargs="*")
            p.add_argument("--from", dest="frm"); p.add_argument("--permitopen", default="127.0.0.1:8080")
            p.add_argument("--permitlisten", default="none")
            o = p.parse_args(a[1:])
            cmd_ssh_grant(o.host, o.duration, " ".join(o.note), o.frm, o.permitopen, o.permitlisten)
        else:
            cmd_ssh_revoke(p.parse_args(a[1:]).host)
    elif c == "lock-hooks":
        cmd_lock_hooks()
    elif c == "unlock-hooks":
        cmd_unlock_hooks()
    elif c == "uninstall":
        cmd_uninstall()
    elif c == "status":
        return cmd_status()
    elif c == "log":
        import argparse
        p = argparse.ArgumentParser(prog="tether log")
        p.add_argument("-n", type=int, default=50); p.add_argument("--since"); p.add_argument("--tool")
        p.add_argument("--grep"); p.add_argument("--json", action="store_true")
        o = p.parse_args(a[1:]); cmd_log(o.n, o.since, o.tool, o.grep, o.json)
    elif c == "revert":
        import argparse
        p = argparse.ArgumentParser(prog="tether revert")
        p.add_argument("id", nargs="?"); p.add_argument("--since"); p.add_argument("--dry-run", action="store_true")
        o = p.parse_args(a[1:])
        if not (o.id or o.since):
            sys.exit("give an ID or --since")
        cmd_revert(o.id, o.since, o.dry_run)
    else:
        sys.exit("unknown command %s" % c)
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
