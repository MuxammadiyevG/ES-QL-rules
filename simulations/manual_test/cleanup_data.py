#!/usr/bin/env python3
"""cleanup_data.py — delete the synthetic telemetry injected by inject_chain.py.
Targets the unique synthetic host only; real data is never touched.
(Run control_rules.py cleanup separately to remove the control rules.)

Usage: ES_URL=... ES_AUTH=user:pass python3 cleanup_data.py
"""
import json, os, base64, urllib.request
ES   = os.environ.get("ES_URL", "http://10.10.10.60:9200")
AUTH = base64.b64encode(os.environ.get("ES_AUTH", "elastic:elasticpassword").encode()).decode()
HOST = os.environ.get("SIM_HOST", "sim-victim-ssh.lab")

def dbq(index, q):
    req = urllib.request.Request(
        f"{ES.rstrip('/')}/{index}/_delete_by_query?refresh=true&conflicts=proceed",
        data=json.dumps({"query": q}).encode(), method="POST",
        headers={"Content-Type": "application/json", "Authorization": "Basic " + AUTH})
    return json.load(urllib.request.urlopen(req, timeout=120)).get("deleted")

print("deleted synthetic audit docs:", dbq("logs-updive.audit-*", {"term": {"host.hostname": HOST}}))
print("done. (SIEM alert/chain rows persist as the test record — delete in UI if unwanted)")
