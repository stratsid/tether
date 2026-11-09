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
02:14:31 28144c4b01c0 Bash   [deny] ssh buildbox reboot        # after the lease expired

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
| audit log | `/Library/Logs/tether/tether.log` | root-owned, mode 666, with the **`sappnd`** flag: anyone can append, but only root can edit, truncate or delete |

As long as the agent doesn't know your sudo password, it can read all of this but change none of it.
Managed settings also deny `Edit`/`Write` on the tether paths and on `~/.claude/settings*.json`.

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
There's no Claude Code restart: settings files are watched and reload live. The installer backs up any
existing managed settings to `managed-settings.json.pre-tether` and merges into them rather than replacing them.

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

### Built-in loophole check
`grant` **refuses** a Bash rule that points at a file a non-root user can edit, such as
`Bash(/Users/me/proj/run.sh:*)` or `Bash(python3 ~/proj/tool.py:*)`. The agent could rewrite that file and then run
anything under the lease. Lease root-owned paths instead, or pass `--force` if you accept the risk.

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
     or notes that the file didn't exist. That's what `revert` uses.
   - If an **active lease** covers the call, it returns `allow`.
   - If only an **expired lease** matches, it returns `deny`. A hook deny beats every allow rule.
   - If the log can't be written, it returns `ask`: nothing is auto-allowed without an audit trail.
2. **PostToolUse hook:** appends the tool's response, truncated to 4 KB.
3. **Active leases** are also written into managed `permissions.allow`. In auto mode, allow rules resolve
   before the safety classifier, so leased commands aren't second-guessed.

## Limits
- **Bash side effects aren't auto-revertible.** You get the exact command and its output, but undoing it is
  manual. Pair it with snapshots (Time Machine local snapshots, btrfs/zfs on remote hosts) for real rollback.
- **Only the agent's own tool calls are logged.** Processes those commands spawn aren't. If a leased command
  launches another agent, sandbox that agent separately (for example with `sandbox-exec`).
- **Leases are prefix rules.** `Bash(ssh host:*)` means *anything* on that host as your user, so keep them
  narrow and short.
- **The log only grows.** Rotate it as root: `sudo chflags nosappnd LOG && sudo mv LOG LOG.1 && sudo tether install`.
- **The hook runs `/usr/bin/python3`** on each tool call, which adds about 30–60 ms.
- **If the agent knows your sudo password,** or sudo is passwordless, none of this holds.

## Uninstall
```sh
sudo tether uninstall     # restores the previous managed settings; the log is kept
```

## Development
`TETHER_PREFIX=/some/tmp` redirects every system path, so everything runs unprivileged.
`tests/smoke.sh` covers allow, deny, compound commands, the word boundary, expiry, revert and the managed-settings
contents.
