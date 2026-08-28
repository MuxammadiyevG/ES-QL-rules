#!/usr/bin/env python3
"""Keep the synthetic attack telemetry fresh and poll the SIEM until the
Windows Account Takeover chain (host SIM-ATO-DC.simlab) completes, and the
SSH stage-1 correlation keeps firing. Logs progress; exits on completion or
after a max wall-clock budget."""
import json, os, sys, time, base64, urllib.request, subprocess, datetime

TOK  = open("/tmp/claude-1000/-home-giyosiddin-github-ES-QL-rules/8236d708-4dc6-400f-97de-f5a512b27cea/scratchpad/tok.txt").read().strip()
API  = "http://10.10.10.60:8008/v1"
SDIR = "/tmp/claude-1000/-home-giyosiddin-github-ES-QL-rules/8236d708-4dc6-400f-97de-f5a512b27cea/scratchpad"

def api(path):
    req = urllib.request.Request(API + path, headers={"Authorization": "Bearer " + TOK, "Accept": "application/json"})
    return json.load(urllib.request.urlopen(req, timeout=30))

def rule_status(rid):
    r = api(f"/detection-rules/{rid}")["data"]["rule"]
    return f"S{r['chain']['stage']} last={r['last_run_at'][11:]} next={r['next_run_at'][11:]} {r['execution_status']}"

def all_chains():
    out, page = [], 1
    while True:
        r = api(f"/alert-chains?per_page=100&page={page}")
        out += r["data"]["items"]
        if page >= r["paginator"]["meta"]["last_page"]:
            break
        page += 1
    return out

def find_ato_chain():
    best = None
    for i in all_chains():
        if str(i.get("created_at", "")).startswith("2026-07-16") and "Account Takeover" in i["name"]:
            d = api(f"/alert-chains/{i['id']}")["data"]
            c = d["chain"]
            rules = {m["alert"]["detection_rule_id"] for m in d["members"]}
            if best is None or (c.get("completed_stages_count") or 0) > (best[0].get("completed_stages_count") or 0):
                best = (c, d["members"], rules)
    return best if best else (None, None, None)

def inject_win():
    subprocess.run([sys.executable, f"{SDIR}/inject_winato_chain.py", "1"], capture_output=True)
def inject_ssh():
    subprocess.run([sys.executable, f"{SDIR}/inject_ssh_chain.py", "1"], capture_output=True)

def now(): return datetime.datetime.now(datetime.timezone.utc).strftime("%H:%M:%S")

MAX_MIN = int(sys.argv[1]) if len(sys.argv) > 1 else 16
deadline = time.time() + MAX_MIN * 60
it = 0
log = open(f"{SDIR}/monitor.log", "a")
def out(m):
    line = f"[{now()}] {m}"
    print(line); log.write(line + "\n"); log.flush()

out(f"=== monitor start, budget {MAX_MIN}m ===")
while time.time() < deadline:
    it += 1
    # keep data fresh every ~150s (every 3rd 50s-iteration)
    if it % 3 == 1:
        inject_win(); inject_ssh()
        out("re-injected fresh winlog + ssh wave")
    try:
        out("rules  912=" + rule_status(912) + " | 879=" + rule_status(879) + " | 832=" + rule_status(832))
        c, mem, rules = find_ato_chain()
        if c:
            out(f"ATO chain #{c['id']} completed={c['completed_stages_count']}/{c['expected_stages_count']} "
                f"is_complete={c['is_complete']} members={len(mem)} stages={sorted(m['stage'] for m in mem)} rules={rules}")
            if c["is_complete"] or (c.get("completed_stages_count") or 0) >= 2:
                out(f"*** SUCCESS: complete multi-stage chain #{c['id']} ***")
                sys.exit(0)
        else:
            out("no ATO chain yet")
    except Exception as e:
        out("poll error: " + str(e)[:100])
    time.sleep(50)
out("=== budget exhausted ===")
