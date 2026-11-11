# tether

**Time-boxed permission leases for [Claude Code](https://code.claude.com), with a tamper-proof audit log of
every tool call.**

Let an agent work unattended, for example overnight, with a narrow set of extra permissions that **expire on
their own**. The agent can't widen them, and everything it does is recorded in a log it can't edit. Any file it
changed can be restored from that log.

```
$ sudo tether grant 'Bash(ssh buildbox:*)' 10h overnight benchmarks
granted Bash(ssh buildbox:*) until 2026-11-10T08:00:00-08:00

$ tether status
leases:
  Bash(ssh buildbox:*)                     ACTIVE 9h58m left    overnight benchmarks
integrity:
  [ok] /usr/local/lib/tether/tether.py owned by root
  [ok] /Library/Application Support/tether/leases.json owned by root
  [ok] /Library/Application Support/ClaudeCode/managed-settings.json owned by root
  [ok] /Library/Logs/tether/tether.log owned by root
  [ok] log has sappnd (append-only) flag
  [ok] managed settings carry the tether hooks
log: /Library/Logs/tether/tether.log (1834 entries)

$ tether log -n 3
02:14:13 ac21c380e95c Bash   [allow] ssh buildbox nvidia-smi
02:14:20 8e409bc36a52 Edit   /Users/me/proj/src/server.py
02:14:31 28144c4b01c0 Bash   [ask] ssh buildbox reboot         # after the lease expired: back to prompting

$ tether revert 8e409bc36a52      # put server.py back exactly as it was
 restore /Users/me/proj/src/server.py
```

## Why
Claude Code's own permission rules live in files that the agent, running as you, can edit. tether moves the
grant into places only root can write:

| piece | location | protection |
|---|---|---|
| hook + CLI | `/usr/local/lib/tether/tether.py` (symlinked as `/usr/local/bin/tether`) | root-owned, 755 |
| leases | `/Library/Application Support/tether/leases.json` | root-owned, 644 |
| Claude Code policy | `/Library/Application Support/ClaudeCode/managed-settings.json` | root-owned. The **managed** scope outranks all user and project settings, and user `disableAllHooks` can't turn off managed hooks |
| audit log | `/Library/Logs/tether/tether.log` | owner root, group staff, mode 660, with the **`sappnd`** flag: staff (you, and the agent running as you) can append, but only root can edit, truncate or delete; other users can't read it |

As long as the agent doesn't know your sudo password, it can read all of this but change none of it.
Managed settings also deny `Edit`/`Write` on the tether paths, `~/.claude/settings*.json`, `**/.claude/**` and
`**/.git/hooks/**`.

## Requirements
- macOS: it uses `chflags sappnd` and `/Library/...` paths. Linux support (`chattr +a`, `/etc/claude-code/`) is a TODO.
- Claude Code 2.x, which supports managed settings and the PreToolUse/PostToolUse hooks.
- `/usr/bin/python3` (ships with the Xcode Command Line Tools). Stdlib only, no `pip`.
- sudo, to install and to grant. Viewing and reverting don't need it.

## Install
```sh
git clone https://github.com/<you>/tether.git ~/tether
less ~/tether/tether.py                       # read it: it runs as root once, and as a hook on every tool call
~/tether/tests/smoke.sh                       # sandboxed self-test, no root needed
sudo /usr/bin/python3 ~/tether/tether.py install
tether status
```
On a **first** install, restart Claude Code (`claude --continue`) so the hooks load. Re-running `install` later
(to update tether) needs no restart: managed settings reload live. The installer backs up any existing managed
settings to `managed-settings.json.pre-tether` and merges into them rather than replacing them.

**Upgrading from a version that created the log as mode 666:** an existing `sappnd` log can't be changed
without first clearing the flag, so migrate it by hand:
```sh
LOG=/Library/Logs/tether/tether.log
sudo chflags nosappnd $LOG; sudo chgrp staff $LOG; sudo chmod 660 $LOG; sudo chflags sappnd $LOG
```

## Usage
### Grant, check, revoke
```sh
sudo tether grant 'RULE' DURATION [note]     # DURATION: 30m, 10h, 2d
tether status
sudo tether revoke 'RULE'                    # end one lease now
sudo tether revoke --all                     # end all leases now
sudo tether prune                            # drop expired leases from the managed allow list
```
### Policy: limit what can ever be leased (recommended)
```sh
sudo tether policy ssh-only        # only rules like Bash(ssh HOST:*) can be granted or honoured
sudo tether policy '^Bash\(pytest'  # or any regex over the rule text
sudo tether policy any             # remove the restriction
tether policy                      # show
```
The policy file is root-owned. The hook ignores any lease that doesn't match it, even one already granted.

### Lock hooks (recommended, opt-in)
```sh
sudo tether lock-hooks      # copy your ~/.claude/settings.json hooks into managed settings, then ignore
                            # all user/project hooks (allowManagedHooksOnly: true)
tether status               # "hooks: LOCKED ..."
sudo tether unlock-hooks    # remove the copied hooks and the flag
```
Without this, an agent that can write a project's `.claude/settings.json` (or your user settings, through a shell
command) can plant a hook that runs arbitrary code on the next tool call. `lock-hooks` closes that: only managed
hooks run, and your own hooks keep working because they're copied verbatim into the managed scope (they're
printed so you can review them; they still run as you). Project hooks stop running. If you change the hooks in
`~/.claude/settings.json`, run `sudo tether lock-hooks` again to re-copy them.

### Temporary ssh keys
```sh
sudo tether ssh-grant nexus 10h overnight benchmarks        # HOST = an alias in your ~/.ssh/config
sudo tether ssh-grant nexus 4h --permitopen 127.0.0.1:8080,127.0.0.1:11434 --from 100.101.102.103
tether status                                               # "ssh keys:" with fingerprint + time left
sudo tether ssh-revoke nexus                                # remove the key on nexus and locally, end the lease
```
`ssh-grant` gives the agent its own short-lived key instead of yours:
1. Generates an ed25519 key `/Library/Application Support/tether/ssh/HOST-claude` (comment `tether:<lease-id>`;
   private key owned by you, mode 600, because ssh insists and the agent runs as you; public key root 644).
2. Using **your own** `ssh HOST` (run as you, with your agent: if your key lives in ssh-agent use
   `sudo --preserve-env=SSH_AUTH_SOCK tether ssh-grant ...`), removes expired `tether:` lines from the remote
   `~/.ssh/authorized_keys` and appends
   `restrict,pty,port-forwarding,permitopen="127.0.0.1:8080",permitlisten="127.0.0.1:1",expiry-time="YYYYMMDDHHMMZ",from="<this Mac's tailnet IP>" ssh-ed25519 ... tether:<id>`.
   `expiry-time` is in UTC (`Z`, OpenSSH 8.2+), so the remote refuses the key after the lease even if nothing
   cleans up. The tailnet IP comes from `tailscale ip -4`, or `--from IP`.
3. Writes a root-owned `/Library/Application Support/tether/ssh/config` with `Host HOST-claude` (HostName/User/Port
   from `ssh -G HOST`, `IdentityFile` = the new key, `IdentitiesOnly yes`, `IdentityAgent none`,
   `ExitOnForwardFailure yes`, `ServerAliveInterval 30`, and your `HostKeyAlias` if you set one) and adds
   `Include "/Library/Application Support/tether/ssh/config"` as the first line of `~/.ssh/config` (backed up once to
   `config.bak-tether`).
4. Leases `Bash(ssh HOST-claude:*)` for the same duration, so every rule above applies to it (redirections and
   `ssh HOST-claude -o/-L/...` are denied), logs the key fingerprint (never the key), and test-logs in with
   `ssh HOST-claude true`.

Local private keys whose lease has expired are destroyed on the next `grant`/`revoke`/`prune`/`status`
(`status`, not being root, truncates them; root deletes them). If `ssh-revoke` can't reach the host, the lease and
local key still go, and `status` shows `expired locally but still on remote` until a retry succeeds.
Tests use `TETHER_SSH` / `TETHER_TAILSCALE` to substitute fake binaries.

### Built-in loophole check
`grant` **refuses** a Bash rule that would run a file a non-root user can edit, such as
`Bash(/Users/me/proj/run.sh:*)`, `Bash(python3 ~/proj/tool.py:*)`, `Bash(./x:*)`, `Bash(python3 x.py:*)` (resolved
in the current directory), a bare token naming a file in the current directory, `Bash(make:*)` (`./Makefile`),
`Bash(npm run build:*)` (`./package.json`), `python3 -m ...`, or a bare interpreter such as `Bash(node:*)`. The agent
could rewrite (or create) that file and then run anything under the lease. A file counts as safe only if it and
every directory above it are root-owned and not group/other-writable. Lease root-owned paths instead, or pass
`--force` if you accept the risk.

RULE uses Claude Code's permission-rule syntax:

| rule | allows |
|---|---|
| `Bash(ssh buildbox:*)` | any command starting with `ssh buildbox ` (word boundary, so `ssh buildboxevil` doesn't match) |
| `Bash(npm test)` | exactly `npm test` |
| `Bash(/Users/me/proj/run_bench.sh:*)` | one script, any arguments |
| `Edit(//Users/me/proj/**)` | edits under that absolute path (`//` = absolute) |
| `WebFetch` | a whole tool |

Compound Bash commands (`a && b`, `a | b`, `a; b`) are allowed automatically only if **every** part is covered
by an active lease. Otherwise tether stays out of it and Claude Code's normal prompting applies.

**Unsafe forms are denied** under an active Bash lease: a covered command that has a redirection outside quotes
(`<`, `>`, `<(`, `>(`, `<<`, `&>`, `2>&1`) or whose first word after the leased prefix starts with `-`
(e.g. `ssh host -o ProxyCommand=...`), any `$` outside single quotes (`$X`, `${X}`, `$'..'`, `"$VAR"`, `$(..)`,
backticks), unquoted brace expansion (`{a,b}`, `{1..3}`), or a glob/escape that bash could turn into an option in
the first argument after the prefix (`?oX`, `[-]o`, `~-`, `\-o`, `{`, `*`; it must start with a letter, digit,
`_ . / ~` or a quote). Those can read or overwrite local files, run local commands, or send local secrets
(`ssh host "echo $API_KEY"`) through an ssh lease. Put the remote work in quotes instead: `ssh host 'cmd > /tmp/out'`. This is a hard `deny`, not a
prompt, because the lease is also a managed allow rule and only a hook deny overrides an allow rule. Note that
the `-` check applies to every `PREFIX:*` lease, so `Bash(npm test:*)` will refuse `npm test --watch`.

File leases (`Edit(//...)`, `Write(//...)`, `Read(//...)`) are matched against the `realpath()` of the target, so a
symlink can't lead out of the leased tree, and a path with any `..` component is never auto-allowed.

### Examples
```sh
# Overnight remote benchmarking on one machine
sudo tether grant 'Bash(ssh gpubox:*)' 10h overnight llama benchmarks

# Lock leasing to ssh only, then lease one host
sudo tether policy ssh-only
sudo tether grant 'Bash(ssh gpubox:*)' 8h

# Allow edits only inside one repo for a working session
sudo tether grant 'Edit(//Users/me/work/api/**)' 3h
sudo tether grant 'Write(//Users/me/work/api/**)' 3h
```

### Audit and revert
```sh
tether log                                   # last 50 tool calls, one line each
tether log -n 0 --tool Bash                  # every Bash call
tether log --since 2026-11-09T23:00          # since a time (local or with offset)
tether log --grep buildbox --json | jq .     # full JSON entries (input, cwd, session, response)
tether revert <id>                           # undo one Write/Edit
tether revert --since 2026-11-09T23:00 --dry-run   # preview undoing all file changes since then
tether revert --since 2026-11-09T23:00             # do it, newest first
```

## How it works
On **every** tool call in every Claude Code session on the machine:
1. **PreToolUse hook:** appends a JSON line (time, session, cwd, tool, full input) to the log.
   - For `Write`/`Edit`/`MultiEdit`/`NotebookEdit`, it also stores the file's previous bytes, up to 5 MB, base64,
     or notes that the file didn't exist. That's what `revert` uses. Secret paths (`~/.ssh/`, `~/.aws/`,
     `~/.gnupg/`, `~/.config/gh/`, `~/Library/Keychains/`, `~/.claude/`, `.env*`, `*.pem`, `*.key`, `id_rsa*`,
     `id_ed25519*`, `~/.config/edge0/api_key`) are never snapshotted (`"prior_note": "secret path: not snapshotted"`),
     so they can't be reverted from the log.
   - If an **active lease** covers the call, it returns `allow` (or `deny` for an unsafe form, see above).
   - If only an **expired or revoked lease** matches, it returns `ask`: back to normal prompting.
   - If the log can't be written, it returns `ask`: nothing is auto-allowed without an audit trail.
2. **PostToolUse hook:** appends the tool's response, with obvious secrets redacted (private-key blocks, `AKIA…`,
   `ghp_…`-style GitHub tokens, `sk-…` keys, `Bearer …`) and truncated to 2000 chars. `Read` responses are
   never logged.
3. **Active leases** are also written into managed `permissions.allow`. In auto mode, allow rules resolve
   before the safety classifier, so leased commands aren't second-guessed.

### Strict shape under Bash leases (allow-list)
Under an active Bash lease, the text after the leased prefix may contain **only** plain words
(`A-Za-z0-9_./:@%+=,-`, not starting with `-` or `=`) or `'single-quoted'` strings. Anything else is **denied**:
`$`, globs, braces, redirects, parentheses, double quotes, extra spaces in the prefix. Blocking dangerous syntax one
construct at a time can't keep up with bash **and** zsh. For example, zsh's `=(cmd)` and glob qualifiers like
`*(e:'cmd':)` run local code. So put remote commands in single quotes:
```sh
ssh nexus 'ls ~/edge0/models | head; nvidia-smi'     # allowed
ssh nexus ls *.py                                    # denied: unquoted glob (use: ssh nexus 'ls *.py')
```

## Limits
- **Bash side effects aren't auto-revertible.** You get the exact command and its output, but undoing it is
  manual. Pair it with snapshots (Time Machine local snapshots, btrfs/zfs on remote hosts) for real rollback.
- **Only the agent's own tool calls are logged.** Processes those commands spawn aren't. If a leased command
  launches another agent, sandbox that agent separately (for example with `sandbox-exec`).
- **Leases are prefix rules.** `Bash(ssh host:*)` means *anything* on that host as your user, so keep them
  narrow and short.
- **Redaction is best effort.** Only the patterns above are caught: an AWS *secret* key, a password in a config
  file, or a token in an unusual format printed by a Bash command will be logged. Tool *inputs* (commands, and
  `Write`/`Edit` content) are logged as-is, so a command that contains a token puts it in the log.
- **Shell variables expand locally.** `ssh host echo $GH_TOKEN` sends your local value to the host; the lease
  doesn't stop that.
- **The writable-script check runs in the directory where you run `grant`.** `Bash(make:*)` is judged against
  `./Makefile` there, but the agent may run it elsewhere; for `make`/`npm`/interpreter leases assume the agent
  controls the project files unless they're root-owned. Programs found through `PATH` aren't checked.
- **Expired leases ask, they don't deny.** Until `revoke`/`prune` removes an expired rule from the managed allow
  list, tether's `ask` is what makes Claude Code prompt again.
- **`**/.claude/**` is denied for Edit/Write**, which also blocks the agent from editing `.claude/` files in your
  projects (and, when the working directory is under `~`, its own memory/`CLAUDE.md` files under `~/.claude/`).
  The pattern is relative to the working directory, so `~/.claude` from a project outside your home isn't covered
  by it (the `~/.claude/settings*.json` rules still are). `lock-hooks` is what actually stops planted hooks.
- **The temporary ssh key is readable by the agent** (it has to be, to use it). It can copy the key and use it
  with any ssh options outside tether's prefix, which prompts as usual, or from any process it starts. The
  authorized_keys options (`from=`, `permitopen=`, `expiry-time=`) are what actually bound it; it still gets a
  shell on the remote as your remote user. Because `ssh HOST-claude -L ...` is an unsafe form under the lease,
  tunnels through the permitted ports need your approval. authorized_keys has no `permitlisten="none"`
  (sshd rejects the whole key line), so remote forwarding is pinned to `127.0.0.1:1`, a privileged port a
  non-root login can't bind (verified on OpenSSH 10.5: `-R` refused). `ssh_config` adds up `IdentityFile`
  lines, so a `Host *` IdentityFile in your own config also applies to the alias; ssh-grant warns about it. The remote side
  needs a POSIX `sh`, `awk` and `date` (Linux/macOS, not Windows OpenSSH).
- **Bash is not sandboxed by tether.** Commands without a lease go through Claude Code's normal permission
  flow (prompt, or the auto-mode classifier). tether denies the file tools (Edit/Write) on files that run code
  later as you (shell rc files, `~/.ssh/**`, LaunchAgents, git config, the iTerm hook script), but a shell
  command could still write them. Never lease a script the agent can edit (grant refuses without `--force`).
- **The log only grows.** Rotate it as root: `sudo chflags nosappnd LOG && sudo mv LOG LOG.1 && sudo tether install`.
- **The hook runs `/usr/bin/python3`** on each tool call, which adds about 30–60 ms.
- **If the agent knows your sudo password,** or sudo is passwordless, none of this holds.

## Uninstall
```sh
sudo tether uninstall     # restores the previous managed settings; the log is kept
```

## Development
`TETHER_PREFIX=/some/tmp` redirects every system path, so everything runs unprivileged.
`tests/smoke.sh` covers allow, deny, compound commands, the word boundary, expiry, unsafe redirect/option forms,
`..`/symlink file paths, secret snapshots and redaction, the log mode, lock-hooks, the writable-script check,
control characters in `tether log`, the installer message, revert and the managed-settings contents. It prints
only `ok` lines when everything passes.

## License

MIT. Copyright (c) 2026 Sid Sannabhadti. See [LICENSE](LICENSE).
