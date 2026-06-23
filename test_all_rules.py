#!/usr/bin/env python3
# Barcha papkalardagi ES|QL rule'larni cluster'da sinaydi (syntax + data hit).
# Vaqt oynasini kengaytiradi (NOW() - N unit -> NOW() - WINDOW) chunki data eski.
# Natijani test_report.json ga yozadi.
#
#   ES_AUTH=elastic:elasticpassword python3 test_all_rules.py            # 100 days window
#   ES_AUTH=elastic:elasticpassword python3 test_all_rules.py "120 days"
import os, re, json, glob, base64, sys, urllib.request, urllib.error, yaml
from concurrent.futures import ThreadPoolExecutor, as_completed

ES = os.environ.get("ES_URL", "http://10.10.10.60:9200").rstrip("/") + "/_query"
AUTH = os.environ.get("ES_AUTH", "elastic:elasticpassword")
auth = base64.b64encode(AUTH.encode()).decode()
WINDOW = sys.argv[1] if len(sys.argv) > 1 else "100 days"
ROOT = os.path.dirname(os.path.abspath(__file__))
WORKERS = int(os.environ.get("WORKERS", "6"))
TIMEOUT = int(os.environ.get("TIMEOUT", "120"))
# WIDEN=1 (default): kengaytirilgan oyna (data hit tekshirish, sekin/og'ir).
# WIDEN=0: original oyna (faqat parse/field/index validatsiya, tez — ES|QL plan vaqtida tekshiradi).
WIDEN = os.environ.get("WIDEN", "1") != "0"

# NOW() - N unit  ->  NOW() - WINDOW   (vaqt oynasini kengaytirish)
# NOTE: optional trailing 's' via s? — do NOT list minute|minutes (ordered-alt eats the plural 's').
WIN_RE = re.compile(r"NOW\(\)\s*-\s*\d+\s*(?:second|minute|hour|day|week|month)s?")

ABS_START = os.environ.get("ABS_START")  # e.g. 2026-05-26T00:00:00Z -> efficacy data-hit window

def widen(q):
    if ABS_START:
        return WIN_RE.sub(f'"{ABS_START}"', q)
    return WIN_RE.sub(f"NOW() - {WINDOW}", q) if WIDEN else q

def run(q):
    try:
        r = urllib.request.Request(ES, data=json.dumps({"query": q}).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
        with urllib.request.urlopen(r, timeout=TIMEOUT) as x:
            d = json.load(x)
            return ("OK", len(d.get("values", [])), "")
    except urllib.error.HTTPError as e:
        try:
            j = json.load(e)
            rc = j.get("error", {}).get("root_cause", [{}])
            reason = (rc[0].get("reason") if rc else None) or j.get("error", {}).get("reason", "?")
        except Exception:
            reason = f"HTTP {e.code}"
        return ("ERR", 0, reason)
    except Exception as e:
        return ("ERR", 0, f"{type(e).__name__}: {str(e)[:200]}")

def collect():
    files = []
    for f in glob.glob(os.path.join(ROOT, "**", "*.yml"), recursive=True):
        files.append(f)
    return sorted(files)

def process(f):
    rel = os.path.relpath(f, ROOT)
    folder = rel.split(os.sep)[0]
    rec = {"file": rel, "folder": folder}
    try:
        doc = yaml.safe_load(open(f))
    except Exception as e:
        rec.update(status="YAML_ERR", rows=0, reason=str(e)[:200], index="", name="")
        return rec
    if not isinstance(doc, dict):
        rec.update(status="NOT_DICT", rows=0, reason="", index="", name="")
        return rec
    idx = doc.get("index")
    rec["index"] = ",".join(idx) if isinstance(idx, list) else str(idx)
    rec["name"] = doc.get("name", "")
    rec["enabled"] = bool(doc.get("enabled"))
    q = doc.get("query") or ""
    if not q.strip():
        rec.update(status="NO_QUERY", rows=0, reason="")
        return rec
    st, rows, reason = run(widen(q))
    rec.update(status=st, rows=rows, reason=reason)
    return rec

def main():
    files = collect()
    print(f"Testing {len(files)} rules | window={WINDOW} | workers={WORKERS} | timeout={TIMEOUT}s", flush=True)
    results = []
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        futs = {ex.submit(process, f): f for f in files}
        done = 0
        for fut in as_completed(futs):
            rec = fut.result()
            results.append(rec)
            done += 1
            mark = {"OK": "OK ", "ERR": "ERR", "YAML_ERR": "YML", "NO_QUERY": "NOQ", "NOT_DICT": "NOD"}.get(rec["status"], "???")
            extra = f" rows={rec['rows']}" if rec["status"] == "OK" else f" -> {rec.get('reason','')[:90]}"
            if done % 1 == 0:
                print(f"[{done:>3}/{len(files)}] {mark} {rec['file'][:70]:<70}{extra}", flush=True)
    results.sort(key=lambda r: (r["folder"], r["file"]))
    with open(os.path.join(ROOT, "test_report.json"), "w") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)
    # Summary
    by_status = {}
    for r in results:
        by_status[r["status"]] = by_status.get(r["status"], 0) + 1
    ok_data = sum(1 for r in results if r["status"] == "OK" and r["rows"] > 0)
    print("\n==== SUMMARY ====")
    for k, v in sorted(by_status.items()):
        print(f"  {k:10} {v}")
    print(f"  OK with data: {ok_data}")
    print("Report -> test_report.json")

if __name__ == "__main__":
    main()
