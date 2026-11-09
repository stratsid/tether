#!/bin/bash
# Sandbox smoke test: TETHER_PREFIX redirects every system path into a temp dir. No root needed.
set -euo pipefail
here=$(cd "$(dirname "$0")/.." && pwd)
S=$(mktemp -d); export TETHER_PREFIX=$S
T() { /usr/bin/python3 "$here/tether.py" "$@"; }
fail=0; check() { if [ "$2" = "$3" ]; then echo "ok   $1"; else echo "FAIL $1: got [$2] want [$3]"; fail=1; fi; }
dec() { echo "{\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"$1\"},\"tool_use_id\":\"t\"}" | T hook pre \
        | /usr/bin/python3 -c 'import sys,json; s=sys.stdin.read().strip(); print(json.loads(s)["hookSpecificOutput"]["permissionDecision"] if s else "none")'; }

T install >/dev/null
T grant 'Bash(ssh nexus:*)' 10h overnight >/dev/null
T grant 'Bash(echo old:*)' 1m test >/dev/null
/usr/bin/python3 - "$S/Library/Application Support/tether/leases.json" <<'EOF'
import json,sys; p=sys.argv[1]; l=json.load(open(p)); l[-1]["expires"]="2020-01-01T00:00:00+00:00"; json.dump(l,open(p,"w"))
EOF

check "leased command allowed"          "$(dec 'ssh nexus nvidia-smi')"          allow
check "compound, all leased -> allow"   "$(dec 'ssh nexus ls && ssh nexus df')"  allow
check "compound w/ unleased -> no-op"   "$(dec 'ssh nexus ls && rm -rf /tmp/x')" none
check "prefix must end at word"         "$(dec 'ssh nexusevil ls')"              none
check "expired lease -> deny"           "$(dec 'echo old hi')"                   deny
check "unrelated -> no-op"              "$(dec 'ls')"                            none
check "quoted ; and | stay inside ssh"  "$(dec "ssh nexus 'uptime; ls | head'")"     allow
check "\$( ) never auto-allowed"        "$(dec 'ssh nexus $(whoami)')"           none
check "backtick never auto-allowed"     "$(dec 'ssh nexus `id`')"                none
check "unbalanced quote -> no-op"       "$(dec "ssh nexus 'ls")"                 none
check "background & splits"             "$(dec 'ssh nexus ls & rm -rf /tmp/x')"  none

echo orig > "$S/f.txt"
echo "{\"tool_name\":\"Edit\",\"tool_input\":{\"file_path\":\"$S/f.txt\",\"old_string\":\"orig\",\"new_string\":\"new\"},\"tool_use_id\":\"e1\"}" | T hook pre >/dev/null
echo new > "$S/f.txt"
echo "{\"tool_name\":\"Write\",\"tool_input\":{\"file_path\":\"$S/created.txt\",\"content\":\"x\"},\"tool_use_id\":\"w1\"}" | T hook pre >/dev/null
echo x > "$S/created.txt"
echo "{\"tool_name\":\"Edit\",\"tool_response\":{\"ok\":1},\"tool_use_id\":\"e1\"}" | T hook post
T revert e1 >/dev/null;  check "revert restores edit"   "$(cat "$S/f.txt")" orig
T revert w1 >/dev/null;  check "revert deletes created" "$([ -e "$S/created.txt" ] && echo exists || echo gone)" gone
check "log has entries" "$(T log -n 0 --json | wc -l | tr -d ' ')" 19
T prune >/dev/null
M="$S/Library/Application Support/ClaudeCode/managed-settings.json"
check "managed allow has active lease only" "$(/usr/bin/python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["permissions"]["allow"])' "$M")" "['Bash(ssh nexus:*)']"
check "managed deny locks lib"  "$(grep -c '//' "$M" | tr -d ' ' | awk '{print ($1>0)?"yes":"no"}')" yes
# policy + writable-script loophole
echo 'echo hi' > "$S/script.sh"
check "grant on user-writable script refused" "$(T grant "Bash($S/script.sh:*)" 1h 2>&1 | grep -c refused)" 1
T policy ssh-only >/dev/null
check "policy blocks non-ssh grant" "$(T grant 'Bash(ls:*)' 1h 2>&1 | grep -c 'does not match policy')" 1
check "policy allows ssh grant" "$(T grant 'Bash(ssh other:*)' 1h 2>&1 | grep -c granted)" 1
check "ssh lease still allowed under policy" "$(dec 'ssh nexus uptime')" allow
check "policy rejects regex injection" "$(T grant 'Bash(ssh x && rm:*)' 1h 2>&1 | grep -c 'does not match policy')" 1
T log -n 12
rm -rf "$S"; exit $fail
