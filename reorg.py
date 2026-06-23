#!/usr/bin/env python3
# Rulelarni data-manba bo'yicha papkalarga qayta tartiblaydi (git mv).
# Dry-run default; EXECUTE=1 bilan haqiqiy ko'chiradi.
import glob, os, yaml, subprocess, sys, collections, uuid

ROOT = os.path.dirname(os.path.abspath(__file__))
EXECUTE = os.environ.get("EXECUTE") == "1"

TARGETS = [
    ("windows",   ["logs-winlog", "winlogbeat"]),
    ("linux",     ["logs-updive.audit", "auditbeat", "log-audit", "logs-linux.auth", "auth-log"]),
    ("fortigate", ["fortinet.fortigate", "fortigate"]),
    ("paloalto",  ["logs-panw", "paloalto", "palo-alto"]),
    ("checkpoint",["checkpoint"]),
    ("kerio",     ["kerio"]),
    ("nginx-waf", ["nginx.waf", "modsec", "uz_waf", "waf"]),
    ("nginx",     ["logs-nginx", "nginx-access", "filebeat-nginx"]),
    ("vmware",    ["vmware.esxi", "esxi"]),
    ("tomcat",    ["tomcat"]),
    ("postgres",  ["postgresql", "postgres"]),
    ("npm",       ["logs-npm", "npm.access"]),
    ("switch",    ["updive-syslog", "logs-switch", " switch"]),
    ("eset",      ["eset.protect", "eset"]),
    ("metrics",   ["metrics-updive", "metricbeat", "metric"]),
]
# Papkalar (allaqachon data-source) — bularni yangi struktura deb hisoblaymiz, tegmaymiz.
NEW_DIRS = {t for t, _ in TARGETS}

def target(idx_str, q):
    s = (idx_str or "").lower() + " " + (q or "").lower()
    for name, keys in TARGETS:
        if any(k in s for k in keys):
            return name
    return "UNKNOWN"

def git(*args):
    if EXECUTE:
        subprocess.run(["git", *args], cwd=ROOT, check=True)

moves = collections.Counter()
plan = []
for f in sorted(glob.glob(os.path.join(ROOT, "**", "*.yml"), recursive=True)):
    rel = os.path.relpath(f, ROOT)
    top = rel.split(os.sep)[0]
    if top in ("_archive", "reference"):
        continue
    try:
        doc = yaml.safe_load(open(f))
    except Exception:
        continue
    if not isinstance(doc, dict) or not doc.get("query"):
        continue  # reference docs handled separately
    idx = doc.get("index"); idx_s = ",".join(idx) if isinstance(idx, list) else str(idx)
    t = target(idx_s, doc.get("query", ""))
    dest_dir = os.path.join(ROOT, t)
    dest = os.path.join(dest_dir, os.path.basename(f))
    if os.path.abspath(f) == os.path.abspath(dest):
        continue  # already in place
    moves[f"{top} -> {t}"] += 1
    plan.append((rel, t, os.path.relpath(dest, ROOT)))

print(f"{'EXECUTE' if EXECUTE else 'DRY-RUN'}: {len(plan)} files to move\n")
print("=== source-folder -> target counts ===")
for k, v in sorted(moves.items(), key=lambda x: -x[1]):
    print(f"  {v:>4}  {k}")
# target totals
tt = collections.Counter(p[1] for p in plan)
print("\n=== rules arriving per target folder ===")
for k, v in tt.most_common():
    print(f"  {v:>4}  {k}/")

if EXECUTE:
    for t in NEW_DIRS:
        os.makedirs(os.path.join(ROOT, t), exist_ok=True)
    for rel, t, destrel in plan:
        git("mv", rel, destrel)
    print(f"\nMoved {len(plan)} files.")
