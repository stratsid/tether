# tether

Time-boxed permission leases for Claude Code, with a tamper-proof audit log of every tool call.
Claude runs as you but without your sudo password; everything tether enforces is root-owned, so Claude can read it
but not change it.

## How it locks
| piece | location | protection |
|---|---|---|
| hook + CLI | `/usr/local/lib/tether/tether.py` (symlink `/usr/local/bin/tether`) | root-owned 755 |
| leases | `/Library/Application Support/tether/leases.json` | root-owned 644 |
| Claude Code policy | `/Library/Application Support/ClaudeCode/managed-settings.json` | root-owned; **managed scope beats every user/project setting**; user `disableAllHooks` can't turn managed hooks off |
| audit log | `/Library/Logs/tether/tether.log` | root-owned, mode 666, **`sappnd`** flag: appends only, no edit/truncate/delete without root |

Managed settings also deny Claude `Edit`/`Write` on the tether paths and on `~/.claude/settings*.json`.

## What happens on each tool call (every Claude Code session on this Mac)
- **PreToolUse hook:** writes a JSON line to the log with time, session, cwd, tool and full input.
  - For `Write`/`Edit`/`NotebookEdit`, it also stores the file's prior bytes (≤5 MB) or notes that the file didn't exist yet.
  - If an **active lease** covers the call, it returns `allow`. For Bash, every `&&`/`;`/`|` subcommand must be covered, or it doesn't decide.
  - If only an **expired lease** matches, it returns `deny`. Hook deny beats any allow rule.
  - If the log can't be written, it returns `ask`: no audit, no auto-allow.
- **PostToolUse hook:** logs the tool's response, truncated to 4 KB.
- **Active leases** are also written to managed `permissions.allow`. Allow rules resolve before the auto-mode classifier.

## Use
```sh
sudo /usr/bin/python3 ~/build/tether/tether.py install     # once (review tether.py first: it runs as root)
sudo tether grant 'Bash(ssh nexus:*)' 10h overnight edge0  # lease
tether status                                              # leases + integrity checks
tether log -n 100 | tether log --since 2026-11-09T23:00 --tool Bash | tether log --grep nexus --json
tether revert <id>            # undo one Write/Edit (restores prior bytes / deletes created file)
tether revert --since <ISO>   # undo every file change since a time, newest first
sudo tether revoke --all      # end all leases now
sudo tether prune             # drop expired leases from managed allow list
sudo tether uninstall         # restores prior managed settings; log is kept
```
Changes take effect live, with no Claude Code restart: settings files are watched.

## Limits (honest)
- **Bash side effects aren't auto-revertible.** The log has the exact command and output, so undo is manual.
  On nexus, `snap-pac` btrfs snapshots cover pacman changes.
- **Only Claude's own tool calls are logged.** Child processes spawned by a logged command, such as a local agent
  harness running model-written shell, are not.
- **The log keeps growing.** File snapshots are inline base64. Rotating it needs root: `sudo chflags nosappnd`, then archive.
- **Lease rules match by prefix**, the same as Claude Code rules. `Bash(ssh nexus:*)` means anything on nexus as `sid`.
  sudo there still needs your password.

## Test
`tests/smoke.sh` runs everything in a temp prefix with no root.
