#!/usr/bin/env python3
"""Inject the Windows 'Account Takeover via Password Reset' kill-chain into the
logs-winlogbeat-default data stream so the SIEM correlation engine assembles a
COMPLETE 2-stage alert-chain (replicates the proven complete chain #234).

  Stage1 rule 912 (8ccab6be...) : event 4724 password reset  freq=1 same_fields=[host.name]
  Stage2 rule 879 (depends 912) : event 4624 logon (type 3)  freq=1 same_fields=[host.name]

Both stages key their chain on host.name == winlog.computer_name, so the same
synthetic computer_name collapses them into ONE chain -> completed 2/2.

Synthetic host SIM-ATO-DC.simlab is unique -> teardown = delete_by_query on it.
Usage: python3 inject_winato_chain.py [n_waves] [sleep_sec]
"""
import json, os, sys, time, base64, urllib.request, datetime

ES   = os.environ.get("ES_URL", "http://10.10.10.60:9200")
AUTH = base64.b64encode(os.environ.get("ES_AUTH", "elastic:elasticpassword").encode()).decode()
DS   = "logs-winlogbeat-default"                 # matches rule pattern logs-winlog*
HOST = os.environ.get("SIM_WINHOST", "SIM-ATO-DC.simlab")
ATT  = os.environ.get("SIM_ATTACKER", "svc_helpdesk")   # SubjectUserName (resets pw)
VIC  = os.environ.get("SIM_VICTIM",  "a.tester")        # TargetUserName (taken over)
IP   = os.environ.get("SIM_WINIP",   "203.0.113.55")
TAG  = "sim-claude-chain"

def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def base(ts, code, task, keyword="Audit Success"):
    return {
        "@timestamp": iso(ts), "@version": "1",
        "agent": {"name": HOST, "id": "sim-win-agent-0001", "type": "updive-win", "version": "9.3.0"},
        "agent_id": 0, "agent_token": "unknown",
        "ecs": {"version": "8.11.0"},
        "log": {"level": "information"},
        "host": {"name": HOST},
        "tags": [TAG],
        "event": {"code": str(code), "kind": "event", "provider": "Microsoft-Windows-Security-Auditing",
                  "module": "security"},
        "winlog": {
            "computer_name": HOST, "channel": "Security", "event_id": str(code),
            "task": task, "keywords": [keyword], "opcode": "Info",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
            "process": {"pid": 1004, "thread": {"id": 9084}},
        },
    }

def e4724(ts):  # password reset attempt -> Stage 1
    d = base(ts, 4724, "User Account Management")
    d["event"]["category"] = ["iam"]; d["event"]["type"] = ["change"]; d["event"]["action"] = "reset-password"
    d["winlog"]["event_data"] = {
        "SubjectUserName": ATT, "SubjectDomainName": "SIMLAB",
        "SubjectUserSid": "S-1-5-21-111-222-333-1001", "SubjectLogonId": "0xabc123",
        "TargetUserName": VIC, "TargetDomainName": "SIMLAB",
        "TargetSid": "S-1-5-21-111-222-333-2002",
    }
    return d

def e4624(ts):  # successful network logon of the victim account -> Stage 2
    d = base(ts, 4624, "Logon")
    d["event"]["category"] = ["authentication"]; d["event"]["type"] = ["start"]; d["event"]["action"] = "logged-in"
    d["event"]["outcome"] = "success"
    d["winlog"]["event_data"] = {
        "TargetUserName": VIC, "TargetDomainName": "SIMLAB",
        "TargetUserSid": "S-1-5-21-111-222-333-2002", "TargetLogonId": "0x4ee5b016",
        "LogonType": "3", "IpAddress": IP, "IpPort": "50221",
        "LogonProcessName": "NtLmSsp", "AuthenticationPackageName": "NTLM",
        "SubjectUserName": "-", "SubjectDomainName": "-", "SubjectUserSid": "S-1-0-0",
        "SubjectLogonId": "0x0", "WorkstationName": "SIM-WKS", "ProcessName": "-",
    }
    return d

def build_wave(now):
    return [
        e4724(now - datetime.timedelta(seconds=40)),   # reset first
        e4624(now - datetime.timedelta(seconds=10)),   # then victim logs on
    ]

def bulk(docs):
    lines = []
    for d in docs:
        lines.append(json.dumps({"create": {"_index": DS}})); lines.append(json.dumps(d))
    body = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(ES.rstrip("/") + "/_bulk", data=body, method="POST",
          headers={"Content-Type": "application/x-ndjson", "Authorization": "Basic " + AUTH})
    r = json.load(urllib.request.urlopen(req, timeout=60))
    errs = [it for it in r.get("items", []) if list(it.values())[0].get("status", 200) >= 300]
    return r.get("errors"), errs

def main():
    waves = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    gap   = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    for w in range(waves):
        now = datetime.datetime.now(datetime.timezone.utc)
        errors, errs = bulk(build_wave(now))
        print(f"wave {w+1}/{waves}  4724+4624 on {HOST}  now={iso(now)}  errors={errors}")
        if errs:
            print("  FAILED:", json.dumps(errs[:2])[:1000]); sys.exit(1)
        if w < waves - 1 and gap: time.sleep(gap)
    print("done.")

if __name__ == "__main__":
    main()
