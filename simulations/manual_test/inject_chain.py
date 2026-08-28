#!/usr/bin/env python3
"""inject_chain.py — "bazaga ma'lumot tiqadigan" (data injector).

Injects a fresh-timestamped Linux SSH kill-chain into Elasticsearch so the
SIEM correlation engine's chain rules can pick it up on REAL query windows
(rules look at NOW()-10min, so timestamps MUST be fresh -> this script stamps now).

Writes into data stream  logs-updive.audit-simtest  (matched by the rules'
`FROM logs-updive.audit-*`), isolated under the synthetic host below so cleanup
is a one-liner. Nothing real is touched.

Events per wave (all share source.ip + host + user so they correlate):
  stage 1 : 8x SSH auth FAIL   (auditd user_login/fail, terminal sshd)  -> rule 832
  stage 2 : 1x SSH login OK    (auditd user_start/success, sshd)        -> rule 833
  stage 3 : 3x recon commands  (whoami/id/uname executed)              -> rule 724

Usage:
  python3 inject_chain.py [waves] [gap_sec]      # default 1 wave
  ES_URL=... ES_AUTH=user:pass python3 inject_chain.py 5 120   # keep fresh ~10min
"""
import json, os, sys, time, base64, urllib.request, datetime

ES   = os.environ.get("ES_URL",  "http://10.10.10.60:9200")
AUTH = base64.b64encode(os.environ.get("ES_AUTH", "elastic:elasticpassword").encode()).decode()
DS   = os.environ.get("SIM_DS", "logs-updive.audit-simtest")
IP   = os.environ.get("SIM_IP",   "198.51.100.77")      # attacker (TEST-NET-2)
HOST = os.environ.get("SIM_HOST", "sim-victim-ssh.lab") # unique synthetic victim
USER = os.environ.get("SIM_USER", "svc-sim")
TAG  = "sim-manual-chain"

def iso(dt): return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def base(ts, mtype, result):
    return {"@timestamp": iso(ts), "@version": "1",
        "agent": {"name": HOST, "id": "sim-agent-01", "type": "updive-audit", "version": "9.3.0"},
        "agent_id": 0, "agent_token": "unknown", "ecs": {"version": "8.11.0"},
        "service": {"type": "auditd"},
        "data_stream": {"type": "logs", "dataset": "updive.audit", "namespace": "simtest"},
        "host": {"hostname": HOST, "name": HOST, "os": {"type": "linux", "family": "debian", "platform": "ubuntu"}, "architecture": "x86_64"},
        "network": {"direction": "ingress"}, "tags": ["beats_input_raw_event", TAG],
        "auditd": {"message_type": mtype, "result": result}}

def login_fail(ts):
    d = base(ts, "user_login", "fail"); d["source"] = {"ip": IP}
    d["process"] = {"executable": "/usr/sbin/sshd", "pid": 100001}
    d["auditd"]["data"] = {"op": "login", "terminal": "sshd", "acct": USER}
    d["event"] = {"kind": "event", "module": "auditd", "action": "logged-in",
                  "category": ["authentication"], "type": ["start"], "outcome": "failure"}
    d["user"] = {"effective": {"name": USER}}; d["related"] = {"user": [USER]}
    return d

def login_ok(ts):
    d = base(ts, "user_start", "success"); d["source"] = {"ip": IP}
    d["process"] = {"executable": "/usr/sbin/sshd", "pid": 100050}
    d["auditd"]["data"] = {"op": "PAM:session_open", "hostname": IP, "terminal": "ssh", "acct": USER}
    d["auditd"]["session"] = "900001"
    d["event"] = {"kind": "event", "module": "auditd", "action": "logged-in",
                  "category": ["authentication"], "type": ["start"], "outcome": "success"}
    d["user"] = {"effective": {"name": USER}}; d["related"] = {"user": [USER]}
    return d

def proc(ts, name):
    d = base(ts, "syscall", "success"); d["source"] = {"ip": IP}
    d["process"] = {"name": name, "args": [name], "title": name,
                    "executable": "/usr/bin/" + name, "pid": 200000, "parent": {"pid": 100050},
                    "working_directory": "/home/" + USER}
    d["auditd"]["data"] = {"syscall": "execve", "exit": "0", "arch": "x86_64", "tty": "pts0"}
    d["tags"] = ["exec", "beats_input_raw_event", TAG]
    d["event"] = {"kind": "event", "module": "auditd", "action": "executed",
                  "category": ["process"], "type": ["start"], "outcome": "success"}
    d["user"] = {"name": USER, "effective": {"name": USER}}; d["related"] = {"user": [USER]}
    return d

def wave(now):
    docs = [login_fail(now - datetime.timedelta(seconds=100 - i * 9)) for i in range(8)]
    docs.append(login_ok(now - datetime.timedelta(seconds=25)))
    for i, n in enumerate(["whoami", "id", "uname"]):
        docs.append(proc(now - datetime.timedelta(seconds=18 - i * 6), n))
    return docs

def bulk(docs):
    lines = []
    for d in docs:
        lines.append(json.dumps({"create": {"_index": DS}})); lines.append(json.dumps(d))
    body = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(ES.rstrip("/") + "/_bulk", data=body, method="POST",
          headers={"Content-Type": "application/x-ndjson", "Authorization": "Basic " + AUTH})
    return json.load(urllib.request.urlopen(req, timeout=60)).get("errors")

def main():
    waves = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    gap   = int(sys.argv[2]) if len(sys.argv) > 2 else 120
    for w in range(waves):
        now = datetime.datetime.now(datetime.timezone.utc)
        err = bulk(wave(now))
        print(f"wave {w+1}/{waves}: 12 docs -> {DS}  host={HOST} ip={IP}  now={iso(now)}  errors={err}")
        if w < waves - 1: time.sleep(gap)
    print("done. (rules run every 5m; keep injecting if you want data fresh across cycles)")

if __name__ == "__main__":
    main()
