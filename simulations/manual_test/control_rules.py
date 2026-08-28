#!/usr/bin/env python3
"""control_rules.py — add/remove the two CONTROL rules that prove the stage-2
chain-gate behavior. Both are exact clones of the SSH stage-2 rule (833) query +
correlation; the ONLY difference is the `chain` block:

    MT-CTRL-nochain    : no chain block   -> SHOULD emit alerts on injected data
    MT-CTRL-withchain  : chain stage-2    -> emits NOTHING (gate suppresses it)

If nochain fires and withchain does not on the SAME data, the chain gate is the
suppressor. Rules are added via the SIEM API and identified/removed BY NAME
(the API's create response returns a phantom id+1 and DELETE lies with 404, so we
never trust the returned id — we scan by name and verify with the total count).

Usage:
  SIEM_URL=http://10.10.10.60:8008/v1  SIEM_USER=siem  SIEM_PASS=password \
      python3 control_rules.py add
  python3 control_rules.py cleanup
  python3 control_rules.py status
"""
import json, os, sys, urllib.request

API  = os.environ.get("SIEM_URL",  "http://10.10.10.60:8008/v1")
USER = os.environ.get("SIEM_USER", "siem")
PASS = os.environ.get("SIEM_PASS", "password")
NAMES = ["MT-CTRL-nochain (manual-test)", "MT-CTRL-withchain (manual-test)"]
# rule_id of the real loaded SSH stage-1 rule (832) — withchain depends on it
STAGE1_RULE_ID = os.environ.get("STAGE1_RULE_ID", "c7683cc7-c4d3-4f67-9d1b-96ab7385fa35")

QUERY = ('FROM logs-updive.audit-*\n'
         '| WHERE @timestamp >= NOW() - 10 minutes\n'
         '| WHERE auditd.message_type == "user_start" AND auditd.result == "success"\n'
         '    AND process.executable == "/usr/sbin/sshd" AND source.ip IS NOT NULL\n'
         '| EVAL host.name = host.hostname, user.name = auditd.data.acct\n'
         '| KEEP @timestamp, agent_id, source.ip, user.name, host.name, auditd.message_type, auditd.result\n'
         '| LIMIT 500')
CORR = {"enabled": True, "timeframe_sec": 300, "ignore_sec": 120, "escalate_severity": "critical",
        "same_fields": ["source.ip"], "dedup_fields": ["source.ip", "user.name", "host.name"]}

_tok = None
def call(method, path, body=None, auth=True):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if auth: h["Authorization"] = "Bearer " + token()
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try:
        return urllib.request.urlopen(req, timeout=30).getcode(), json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as e:
        try: return e.code, json.load(e)
        except Exception: return e.code, {}

def token():
    global _tok
    if _tok is None:
        _, r = call("POST", "/auth/login", {"username": USER, "password": PASS}, auth=False)
        _tok = r["data"]["token"]
    return _tok

def total():
    return call("GET", "/detection-rules?per_page=1")[1]["paginator"]["meta"]["total"]

def find(name):
    page, hits = 1, []
    while True:
        r = call("GET", f"/detection-rules?per_page=100&page={page}")[1]
        for it in r["data"]["items"]:
            if it["name"] == name:
                hits.append(it["id"])
        if page >= r["paginator"]["meta"]["last_page"]: break
        page += 1
    return hits

def make(name, with_chain):
    p = {"name": name, "description": "manual-test control rule (safe to delete)",
         "type": "esql", "enabled": True, "params": "[]", "query_language": "esql",
         "schedule_interval": "5m", "index": ["logs-updive.audit-*"], "query": QUERY,
         "severity": "high", "risk_score": 90, "max_signals": 100,
         "correlation": CORR, "tags": ["manual-test", "chain-gate-control"]}
    if with_chain:
        p["chain"] = {"enabled": True, "stage": 2, "timeframe_sec": 3600,
                      "depends_on_rule_ids": [STAGE1_RULE_ID]}
    code, _ = call("POST", "/detection-rules", p)
    return code

def cmd_add():
    print("total before:", total())
    for name in NAMES:
        code = make(name, with_chain="withchain" in name)
        print(f"  created {name!r} (HTTP {code})")
    print("total after :", total())
    print("\nrules now present (by name):")
    for name in NAMES:
        print(f"  {name}: ids {find(name)}")
    print("\nNow inject data:  python3 inject_chain.py 5 120")
    print("Then watch:       python3 control_rules.py status   (and the SIEM /alerts UI)")

def cmd_cleanup():
    base = total()
    removed = 0
    for name in NAMES:
        for rid in find(name):
            call("DELETE", f"/detection-rules/{rid}")   # 404 body is a lie; it deletes
            removed += 1
    # verify by re-scanning
    left = sum(len(find(n)) for n in NAMES)
    print(f"delete calls issued: {removed} | control rules still present: {left} | total {base} -> {total()}")
    print("cleanup ok" if left == 0 else "WARNING: some remain, re-run cleanup")

def cmd_status():
    from collections import Counter
    its = call("GET", "/alerts?per_page=100")[1]["data"]["items"]
    ids = {}
    for name in NAMES:
        ids[name] = set(find(name))
    cnt = Counter(a["detection_rule_id"] for a in its if str(a["detected_at"]).startswith(_today()))
    for name in NAMES:
        n = sum(cnt.get(i, 0) for i in ids[name])
        print(f"  {name:36s} rule_ids={sorted(ids[name])}  alerts_today={n}")
    print("  (expect: nochain > 0, withchain == 0  => chain gate suppresses stage-2)")

def _today():
    # derive 'today' from the newest alert timestamp (avoids client clock issues)
    its = call("GET", "/alerts?per_page=1")[1]["data"]["items"]
    return its[0]["detected_at"][:10] if its else "2026-01-01"

if __name__ == "__main__":
    c = sys.argv[1] if len(sys.argv) > 1 else "status"
    {"add": cmd_add, "cleanup": cmd_cleanup, "status": cmd_status}.get(c, cmd_status)()
