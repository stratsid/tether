#!/usr/bin/python3
"""tether — time-boxed permission leases + tamper-proof audit log for Claude Code.

Installed copy lives in root-owned /usr/local/lib/tether; leases in root-owned
/Library/Application Support/tether; log is root-owned, mode 0666, flag `sappnd`
(system append-only: anyone may append, nobody but root can truncate/edit/delete).
Claude runs as the user without the sudo password, so it can read but not alter any of it.

  sudo tether install                         install hooks + managed settings (review the repo first)
  sudo tether grant 'Bash(ssh nexus:*)' 10h   lease a permission rule for a duration
  sudo tether revoke ['RULE' | --all]         end lease(s) now
  sudo tether policy ssh-only|any|REGEX      restrict which rules can ever be leased (tether policy = show)
  sudo tether prune                           drop expired leases from managed allow list (hook denies them anyway)
  tether status                               leases + integrity check
  tether log [-n N] [--since ISO] [--tool T] [--grep S] [--json]
  tether revert ID|--since ISO [--dry-run]    restore files changed by Write/Edit
  sudo tether uninstall
Python 3.9 compatible (/usr/bin/python3), stdlib only.
"""
import base64, datetime as dt, fnmatch, json, os, re, shutil, subprocess, sys, uuid

PREFIX = os.environ.get("TETHER_PREFIX", "")          # tests only; empty in production
LIB = PREFIX + "/usr/local/lib/tether"
ETC = PREFIX + "/Library/Application Support/tether"
LEASES = ETC + "/leases.json"
POLICY = ETC + "/policy.json"          # {"allow_rule_regex": "..."}; root-owned
LOGDIR = PREFIX + "/Library/Logs/tether"
LOG = LOGDIR + "/tether.log"
MANAGED = PREFIX + "/Library/Application Support/ClaudeCode/managed-settings.json"
BIN = PREFIX + "/usr/local/bin/tether"
PY = "/usr/bin/python3"
MAX_BLOB = 5 * 1024 * 1024
FILE_TOOLS = {"Write": "file_path", "Edit": "file_path", "MultiEdit": "file_path", "NotebookEdit": "notebook_path"}

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

def writable_targets(rule):
    """Files named in a Bash rule that a non-root user could edit (=> lease = arbitrary exec)."""
    m = RULE_RE.match(rule.strip())
    if not m or m.group(1) != "Bash" or not m.group(2):
        return []
    spec = m.group(2)[:-2] if m.group(2).endswith(":*") else m.group(2)
    bad = []
    for tok in spec.split():
        p = os.path.expanduser(tok)
        if os.path.sep not in p:
            continue
        p = os.path.realpath(p)
        while p and not os.path.exists(p):
            p = os.path.dirname(p)
        st = os.stat(p)
        if st.st_uid != 0 or st.st_mode & 0o022:
            bad.append(p)
    return bad

def lease_active(l, t=None):
    return parse_ts(l["expires"]) > (t or now())

RULE_RE = re.compile(r"^([A-Za-z_][\w.\-]*)(?:\((.*)\))?$", re.S)
def split_cmd(cmd):
    """Split on && || ; | & newline OUTSIDE quotes. Returns None if unparseable or if it contains
    command substitution outside single quotes ($(...) or backticks): never auto-allow those."""
    parts, cur, i, q = [], [], 0, None
    while i < len(cmd):
        ch = cmd[i]
        if q == "'":
            cur.append(ch); q = None if ch == "'" else q; i += 1; continue
        if ch == "\\" and i + 1 < len(cmd):
            cur.append(cmd[i:i + 2]); i += 2; continue
        if q == '"':
            if ch == "`" or cmd.startswith("$(", i):
                return None
            cur.append(ch); q = None if ch == '"' else q; i += 1; continue
        if ch in "'\"":
            q = ch; cur.append(ch); i += 1; continue
        if ch == "`" or cmd.startswith("$(", i):
            return None
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            parts.append("".join(cur)); cur = []; i += 2; continue
        if ch in ";|&\n":
            parts.append("".join(cur)); cur = []; i += 1; continue
        cur.append(ch); i += 1
    if q:
        return None
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]

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
    pat = spec[1:] if spec.startswith("//") else os.path.expanduser(spec)
    return fnmatch.fnmatch(path, pat)

def rule_matches(rule, tool, tool_input, sub=None):
    m = RULE_RE.match(rule.strip())
    return bool(m) and m.group(1) == tool and spec_matches(tool, m.group(2), tool_input, sub)

def decide(tool, tool_input, leases, t=None):
    """-> (decision or None, reason, lease_rule)"""
    pol = load_policy()
    act = [l for l in leases if lease_active(l, t) and policy_ok(l["rule"], pol)]
    exp = [l for l in leases if not lease_active(l, t)]
    if tool == "Bash":
        subs = split_cmd(tool_input.get("command", ""))
        if not subs:                      # empty, unbalanced quotes, or command substitution
            return None, "", None
        cover = []
        for s in subs:
            hit = next((l for l in act if rule_matches(l["rule"], tool, tool_input, s)), None)
            if hit is None:
                gone = next((l for l in exp if rule_matches(l["rule"], tool, tool_input, s)), None)
                if gone:
                    return "deny", "tether: lease %s expired at %s" % (gone["rule"], gone["expires"]), gone["rule"]
                return None, "", None
            cover.append(hit["rule"])
        return "allow", "tether lease: " + ", ".join(sorted(set(cover))), cover[0]
    hit = next((l for l in act if rule_matches(l["rule"], tool, tool_input)), None)
    if hit:
        return "allow", "tether lease: " + hit["rule"], hit["rule"]
    gone = next((l for l in exp if rule_matches(l["rule"], tool, tool_input)), None)
    if gone:
        return "deny", "tether: lease %s expired at %s" % (gone["rule"], gone["expires"]), gone["rule"]
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
                if os.path.getsize(p) <= MAX_BLOB:
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
        r = ev.get("tool_response")
        s = r if isinstance(r, str) else json.dumps(r)
        e["response"] = s[:4000] + ("…[truncated %d chars]" % (len(s) - 4000) if s and len(s) > 4000 else "")
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

def managed_doc(leases):
    try:
        with open(MANAGED) as f:
            doc = json.load(f)
    except (FileNotFoundError, ValueError):
        doc = {}
    pre = {"matcher": "*", "hooks": [{"type": "command", "command": "%s %s/tether.py hook pre" % (PY, LIB), "timeout": 15}]}
    post = {"matcher": "*", "hooks": [{"type": "command", "command": "%s %s/tether.py hook post" % (PY, LIB), "timeout": 15}]}
    hooks = doc.setdefault("hooks", {})
    for ev, h in (("PreToolUse", pre), ("PostToolUse", post)):
        lst = [x for x in hooks.get(ev, []) if "tether.py" not in json.dumps(x)]
        hooks[ev] = [h] + lst
    perms = doc.setdefault("permissions", {})
    allow = [r for r in perms.get("allow", []) if r not in {l["rule"] for l in leases}]
    pol = load_policy()
    perms["allow"] = allow + sorted({l["rule"] for l in leases if lease_active(l) and policy_ok(l["rule"], pol)})
    lock = ["Edit(/%s/**)" % LIB, "Write(/%s/**)" % LIB,
            "Edit(/%s/**)" % ETC, "Write(/%s/**)" % ETC,
            "Edit(/%s)" % MANAGED, "Write(/%s)" % MANAGED,
            "Edit(~/.claude/settings.json)", "Write(~/.claude/settings.json)",
            "Edit(~/.claude/settings.local.json)", "Write(~/.claude/settings.local.json)"]
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
        os.chmod(LOG, 0o666)
        if not PREFIX:
            os.chown(LOG, 0, 0)
            subprocess.run(["chflags", "sappnd", LOG], check=True)
    if os.path.lexists(BIN):
        os.remove(BIN)
    os.symlink(LIB + "/tether.py", BIN)
    regen()
    append_log({"phase": "admin", "action": "install", "by": os.environ.get("SUDO_USER", "?")})
    print("installed. Restart Claude Code (claude --continue) so the hooks load. Then: tether status")

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
    write_root(LEASES, json.dumps(leases, indent=1))
    regen()
    append_log({"phase": "admin", "action": "revoke", "rule": rule or "ALL", "count": n})
    print("revoked %d lease(s)" % n)

def cmd_uninstall():
    need_root()
    append_log({"phase": "admin", "action": "uninstall"})
    if os.path.exists(MANAGED + ".pre-tether"):
        os.replace(MANAGED + ".pre-tether", MANAGED)
    elif os.path.exists(MANAGED):
        os.remove(MANAGED)
    for p in (BIN,):
        if os.path.lexists(p):
            os.remove(p)
    shutil.rmtree(LIB, ignore_errors=True)
    print("uninstalled hooks + managed settings. Log kept (append-only) at", LOG)

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
    n = len(read_log())
    print("log: %s (%d entries)" % (LOG, n))
    return 0 if ok else 1

def fmt(e):
    ts = e.get("ts", "")[11:19]
    if e.get("phase") == "admin":
        return "%s ADMIN %s %s" % (ts, e.get("action"), {k: v for k, v in e.items() if k not in ("phase", "action", "ts")})
    if e.get("phase") == "post":
        return None
    ti = e.get("input") or {}
    what = ti.get("command") or ti.get("file_path") or ti.get("notebook_path") or ti.get("pattern") or ti.get("url") or ""
    what = what.replace("\n", " ⏎ ")
    dec = (" [%s]" % e["decision"]) if e.get("decision") else ""
    return "%s %s %-6s%s %s" % (ts, e["id"], e.get("tool", ""), dec, what[:160])

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
            print("%s: %s is not a file edit; manual revert. Command was:\n  %s" % (r["id"], r["tool"], (r.get("input") or {}).get("command")))
            continue
        if r.get("existed"):
            if r.get("prior_b64") is None:
                print("%s: no snapshot (%s) for %s" % (r["id"], r.get("prior_note"), p)); continue
            print("%s restore %s" % ("would" if dry else "", p))
            if not dry:
                with open(p, "wb") as f:
                    f.write(base64.b64decode(r["prior_b64"]))
        else:
            print("%s delete %s (created by %s)" % ("would" if dry else "", p, r["id"]))
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
        need_root(); regen(); print("managed allow list now = active leases only")
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
