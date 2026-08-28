#!/usr/bin/env python3
"""Remove ALL synthetic simulation telemetry injected for the correlation-engine
test. Deletes by the unique synthetic entities so no real data is touched.
Does NOT delete SIEM alerts/chains (those are the audit trail of the test)."""
import json, os, base64, urllib.request

ES   = os.environ.get("ES_URL", "http://10.10.10.60:9200")
AUTH = base64.b64encode(os.environ.get("ES_AUTH", "elastic:elasticpassword").encode()).decode()

def dbq(index, query):
    body = json.dumps({"query": query}).encode()
    req = urllib.request.Request(f"{ES.rstrip('/')}/{index}/_delete_by_query?refresh=true&conflicts=proceed",
          data=body, method="POST",
          headers={"Content-Type": "application/json", "Authorization": "Basic " + AUTH})
    return json.load(urllib.request.urlopen(req, timeout=120))

# Linux SSH synthetic docs -> unique host sim-victim-ssh.lab
r1 = dbq("logs-updive.audit-*", {"term": {"host.hostname": "sim-victim-ssh.lab"}})
print("deleted linux audit sim docs:", r1.get("deleted"))
# Windows ATO synthetic docs -> unique host SIM-ATO-DC.simlab
r2 = dbq("logs-winlog*", {"term": {"winlog.computer_name": "SIM-ATO-DC.simlab"}})
print("deleted winlog sim docs:", r2.get("deleted"))
print("cleanup done.")
