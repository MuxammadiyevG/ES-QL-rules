#!/usr/bin/env python3
"""Inject a fresh-timestamped Linux SSH intrusion kill-chain (stages 1->2->3)
into the logs-updive.audit-simtest data stream so the SIEM correlation engine
assembles a COMPLETE 3-stage alert-chain.

All stages share the SAME entities (source.ip + host + user) so whatever field
the chain engine keys on, they collapse into one chain_key.

Rules targeted (loaded, enabled):
  832  c7683cc7... Stage1 SSH auth-failure burst  (corr freq=6 / 120s by source.ip)
  833  7afac640... Stage2 successful login         (chain depends_on 832, by source.ip)
  724  4b6f7d9a... Stage3 post-compromise command  (chain depends_on 833, by host.name)

Marker tag "sim-claude-chain" on every doc for clean teardown.
Usage: python3 inject_ssh_chain.py [n_waves] [sleep_sec]
"""
import json, os, sys, time, base64, urllib.request, datetime

ES   = os.environ.get("ES_URL", "http://10.10.10.60:9200")
AUTH = base64.b64encode(os.environ.get("ES_AUTH", "elastic:elasticpassword").encode()).decode()
DS   = "logs-updive.audit-simtest"          # matches rule pattern logs-updive.audit-*
TAG  = "sim-claude-chain"

ATT  = os.environ.get("SIM_IP",   "198.51.100.77")     # TEST-NET-2 attacker
VIC  = os.environ.get("SIM_HOST", "sim-victim-ssh.lab") # synthetic victim host
USER = os.environ.get("SIM_USER", "svc-sim")

def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"

def base(ts, mtype, result):
    return {
        "@timestamp": iso(ts), "@version": "1",
        "agent": {"name": VIC, "id": "sim-agent-0001", "type": "updive-audit", "version": "9.3.0"},
        "agent_id": 0, "agent_token": "unknown",
        "ecs": {"version": "8.11.0"},
        "service": {"type": "auditd"},
        "data_stream": {"type": "logs", "dataset": "updive.audit", "namespace": "simtest"},
        "host": {"hostname": VIC, "name": VIC, "os": {"type": "linux", "family": "debian",
                 "name": "Ubuntu", "platform": "ubuntu"}, "architecture": "x86_64"},
        "network": {"direction": "ingress"},
        "tags": ["beats_input_raw_event", TAG],
        "auditd": {"message_type": mtype, "result": result},
    }

def login_fail(ts):
    d = base(ts, "user_login", "fail")
    d["source"] = {"ip": ATT}
    d["process"] = {"executable": "/usr/sbin/sshd", "pid": 100001}
    d["auditd"]["data"] = {"op": "login", "terminal": "sshd", "acct": USER}
    d["auditd"]["summary"] = {"actor": {"primary": "unset", "secondary": USER},
                              "how": "/usr/sbin/sshd",
                              "object": {"type": "user-session", "primary": "sshd", "secondary": ATT}}
    d["related"] = {"user": [USER]}
    d["event"] = {"kind": "event", "module": "auditd", "action": "logged-in",
                  "category": ["authentication"], "type": ["start"], "outcome": "failure"}
    d["user"] = {"effective": {"name": USER}}
    return d

def login_success(ts):
    d = base(ts, "user_start", "success")
    d["source"] = {"ip": ATT}
    d["process"] = {"executable": "/usr/sbin/sshd", "pid": 100050}
    d["auditd"]["data"] = {"op": "PAM:session_open", "hostname": ATT, "terminal": "ssh",
                           "acct": USER, "grantors": "pam_unix,pam_systemd"}
    d["auditd"]["session"] = "900001"
    d["auditd"]["summary"] = {"actor": {"primary": USER, "secondary": USER},
                              "how": "/usr/sbin/sshd",
                              "object": {"type": "user-session", "primary": "ssh", "secondary": ATT}}
    d["related"] = {"user": [USER]}
    d["event"] = {"kind": "event", "module": "auditd", "action": "logged-in",
                  "category": ["authentication"], "type": ["start"], "outcome": "success"}
    d["user"] = {"effective": {"name": USER}}
    return d

def proc_exec(ts, name):
    d = base(ts, "syscall", "success")
    d["source"] = {"ip": ATT}                       # extra entity to force chain linkage
    d["process"] = {"name": name, "args": [name], "title": name,
                    "executable": "/usr/bin/" + name, "pid": 200000,
                    "working_directory": "/home/" + USER, "parent": {"pid": 100050}}
    d["auditd"]["data"] = {"syscall": "execve", "exit": "0", "arch": "x86_64", "tty": "pts0"}
    d["auditd"]["summary"] = {"actor": {"primary": "unset", "secondary": USER},
                              "how": "/usr/bin/" + name,
                              "object": {"type": "file", "primary": "/usr/bin/" + name}}
    d["tags"] = ["exec", "beats_input_raw_event", TAG]
    d["related"] = {"user": [USER]}
    d["event"] = {"kind": "event", "module": "auditd", "action": "executed",
                  "category": ["process"], "type": ["start"], "outcome": "success"}
    d["user"] = {"name": USER, "effective": {"name": USER}}
    return d

def build_wave(now):
    docs = []
    # Stage1: 8 SSH auth failures across ~70s (>=6 within 120s -> corr freq met)
    for i in range(8):
        docs.append(login_fail(now - datetime.timedelta(seconds=100 - i * 9)))
    # Stage2: one successful login after the burst
    docs.append(login_success(now - datetime.timedelta(seconds=25)))
    # Stage3: three distinct recon commands (check_diff wants distinct process.name)
    for i, n in enumerate(["whoami", "id", "uname"]):
        docs.append(proc_exec(now - datetime.timedelta(seconds=18 - i * 6), n))
    return docs

def bulk(docs):
    lines = []
    for d in docs:
        lines.append(json.dumps({"create": {"_index": DS}}))
        lines.append(json.dumps(d))
    body = ("\n".join(lines) + "\n").encode()
    req = urllib.request.Request(ES.rstrip("/") + "/_bulk", data=body, method="POST",
          headers={"Content-Type": "application/x-ndjson",
                   "Authorization": "Basic " + AUTH})
    r = json.load(urllib.request.urlopen(req, timeout=60))
    errs = [it for it in r.get("items", []) if list(it.values())[0].get("status", 200) >= 300]
    return r.get("errors"), errs

def main():
    waves = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    gap   = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    for w in range(waves):
        now = datetime.datetime.now(datetime.timezone.utc)
        docs = build_wave(now)
        errors, errs = bulk(docs)
        print(f"wave {w+1}/{waves}  {len(docs)} docs -> {DS}  now={iso(now)}  errors={errors}")
        if errs:
            print("  FAILED items:", json.dumps(errs[:2], indent=1)[:800])
            sys.exit(1)
        if w < waves - 1 and gap:
            time.sleep(gap)
    print("done.")

if __name__ == "__main__":
    main()
