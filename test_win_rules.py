#!/usr/bin/env python3
# win_rules/ ichidagi barcha ES|QL rule'larni cluster'da sinaydi.
# Ishlatish:
#   ES_AUTH="elastic:PAROL" python3 test_win_rules.py            # 15 kunlik oyna (default)
#   ES_AUTH="elastic:PAROL" python3 test_win_rules.py "15 months"  # butun data
#   ES_URL="http://10.10.10.60:9200" ES_AUTH="elastic:PAROL" python3 test_win_rules.py "1 day"
import os, re, json, glob, base64, sys, urllib.request, urllib.error, yaml
ES = os.environ.get("ES_URL", "http://10.10.10.60:9200").rstrip("/") + "/_query"
AUTH = os.environ.get("ES_AUTH")
if not AUTH:
    sys.exit("ES_AUTH=user:pass o'rnating (masalan: ES_AUTH=elastic:parol python3 test_win_rules.py)")
auth = base64.b64encode(AUTH.encode()).decode()
WINDOW = sys.argv[1] if len(sys.argv) > 1 else "15 days"
FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "win_rules")

def run(q):
    try:
        r = urllib.request.Request(ES, data=json.dumps({"query": q}).encode(), method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Basic " + auth})
        with urllib.request.urlopen(r, timeout=180) as x:
            return ("OK", len(json.load(x).get("values", [])))
    except urllib.error.HTTPError as e:
        try: return ("ERR", json.load(e).get("error", {}).get("root_cause", [{}])[0].get("reason", "?")[:160])
        except Exception: return ("ERR", f"HTTP {e.code}")
    except Exception as e:
        return ("ERR", str(e)[:160])

ok = err = hits = 0; errors = []; fired = []
for f in sorted(glob.glob(FOLDER + "/*.yml")):
    doc = yaml.safe_load(open(f))
    q = (doc.get("query") or "").replace("NOW() - 15 minutes", f"NOW() - {WINDOW}")
    st, info = run(q); name = os.path.basename(f)
    en = "ON " if doc.get("enabled") else "off"
    if st == "OK":
        ok += 1
        if info > 0: hits += 1; fired.append((info, en, name))
        print(f"  OK  [{en}] {info:>4} rows  {name}")
    else:
        err += 1; errors.append((name, info)); print(f" ERR  [{en}]            {name}\n        -> {info}")
print(f"\n==== Jami: {ok+err} | OK: {ok} | ERROR: {err} | data ushlagan: {hits}  (oyna: {WINDOW}) ====")
if fired:
    print("\nData ushlagan rule'lar:")
    for c, en, n in sorted(fired, reverse=True): print(f"   {c:>4} [{en}] {n}")
if errors:
    print("\nXATOLAR:")
    for n, e in errors: print(f"   {n}: {e}")
