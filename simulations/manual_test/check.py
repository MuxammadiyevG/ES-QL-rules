#!/usr/bin/env python3
"""check.py — observe the result of the injection against the REAL loaded chain
rules (no rule creation needed). Shows:
  - stage-1 rule 832 alerts today (should fire on the injected burst)
  - stage-2 rule 833 alerts today (stays 0 -> the bug)
  - the SSH chain row in /alert-chains: expected/completed stages + member count
    (today's chain-rule chains come back expected=null / members=0 -> the bug)

Usage: SIEM_URL=... SIEM_USER=siem SIEM_PASS=password python3 check.py
"""
import json, os, sys, urllib.request
from collections import Counter

API  = os.environ.get("SIEM_URL",  "http://10.10.10.60:8008/v1")
USER = os.environ.get("SIEM_USER", "siem")
PASS = os.environ.get("SIEM_PASS", "password")
S1, S2, S3 = 832, 833, 724   # loaded SSH chain: stage1 -> stage2 -> stage3

_tok = None
def call(method, path, body=None, auth=True):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Accept": "application/json", "Content-Type": "application/json"}
    if auth: h["Authorization"] = "Bearer " + token()
    req = urllib.request.Request(API + path, data=data, method=method, headers=h)
    try: return json.load(urllib.request.urlopen(req, timeout=30))
    except urllib.error.HTTPError as e:
        try: return json.load(e)
        except Exception: return {}

def token():
    global _tok
    if _tok is None:
        _tok = call("POST", "/auth/login", {"username": USER, "password": PASS}, auth=False)["data"]["token"]
    return _tok

def rule(rid):
    r = call("GET", f"/detection-rules/{rid}")["data"]["rule"]
    return r["last_run_at"], r["next_run_at"], r["execution_status"], r["execution_message"]

def main():
    its = call("GET", "/alerts?per_page=100")["data"]["items"]
    today = its[0]["detected_at"][:10] if its else "2026-01-01"
    cnt = Counter(a["detection_rule_id"] for a in its if str(a["detected_at"]).startswith(today))

    print(f"== detection-rule runs & alerts (today={today}) ==")
    for tag, rid in (("stage1", S1), ("stage2", S2), ("stage3", S3)):
        last, nxt, st, msg = rule(rid)
        print(f"  {tag} rule {rid}: {st:5}  last={last} next={nxt}")
        print(f"        alerts_today={cnt.get(rid,0)}   engine_msg={msg!r}")

    print("\n== SSH chains created today in /alert-chains ==")
    page, found = 1, 0
    while True:
        r = call("GET", f"/alert-chains?per_page=100&page={page}")
        for i in r["data"]["items"]:
            if str(i.get("created_at","")).startswith(today) and \
               any(k in i["name"] for k in ("SSH Brute", "Auth Failure", "Successful Login", "Post-Compromise")):
                d = call("GET", f"/alert-chains/{i['id']}")["data"]
                c = d["chain"]
                print(f"  chain #{c['id']} '{c['name'][:40]}'")
                print(f"      expected_stages={c['expected_stages_count']} completed={c['completed_stages_count']} "
                      f"is_complete={c['is_complete']} members={len(d['members'])} "
                      f"stages={sorted(m['stage'] for m in d['members'])}")
                found += 1
        if page >= r["paginator"]["meta"]["last_page"]: break
        page += 1
    if not found:
        print("  (none yet — wait for the 5m scheduler after injecting, then re-run)")

    print("\nEXPECTED-IF-HEALTHY: stage2 alerts>0 and a chain with completed>=2 / members>=2.")
    print("OBSERVED-BUG      : stage2 alerts=0, chain expected_stages=null / members=0 (stuck at stage 1).")

if __name__ == "__main__":
    main()
