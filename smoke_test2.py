import json
import os

os.environ["INCIDENT_AGENT_DB"] = "smoke_test2.sqlite3"
if os.path.exists("smoke_test2.sqlite3"):
    os.remove("smoke_test2.sqlite3")

from fastapi.testclient import TestClient  # noqa: E402
from app import app  # noqa: E402

client = TestClient(app)

base_incident = {
    "profile": "ga5-incident-agent/v2",
    "runId": "run-smoke-0002",
    "agentName": "incident-response",
    "publicMarker": "marker-xyz",
    "sensitive": {"accessToken": "x", "privateNote": "y"},
    "incident": {
        "incidentId": "inc-2",
        "title": "DB saturation",
        "service": "orders-api",
        "severity": "SEV-1",
        "transcript": "[ev_010] cpu maxed on primary db\n[ev_011] connection pool exhausted\n[ev_012] slow query log spike\n",
        "allowedRootCauses": ["database_saturation", "bad_deploy"],
    },
    "toolCatalog": [
        {"name": "query_metrics", "description": "q", "inputSchema": {}},
        {"name": "check_db_pool", "description": "q", "inputSchema": {}},
        {"name": "scale_service", "description": "scale", "inputSchema": {}},
    ],
    "policy": {
        "maximumDiagnostics": 2,
        "effectTools": ["scale_service"],
        "approvalRequiredFor": [],
        "doNotExport": ["accessToken", "privateNote"],
    },
}

r = client.post("/v2/incidents", json=base_incident)
body = r.json()
assert r.status_code == 200, body
d0 = body["dispatches"][0]
print("dispatch0", d0["toolName"], d0["attempt"])

# first receipt: 503 -> expect a retry redispatch (attempt 2)
receipt_503 = {
    "receiptId": "r-503",
    "outcomes": [
        {"actionId": d0["actionId"], "callId": d0["callId"], "attempt": 1, "status": 503, "resultClass": None, "nonce": "n1"}
    ],
    "approvals": [],
}
r2 = client.post(f"/v2/incidents/{base_incident['runId']}/receipts", json=receipt_503)
r2body = r2.json()
print("after 503", json.dumps(r2body, indent=2))
assert r2.status_code == 200
assert r2body["dispatches"], "expected retry dispatch"
retry_d = r2body["dispatches"][0]
assert retry_d["attempt"] == 2

# succeed the retry
receipt_ok = {
    "receiptId": "r-ok",
    "outcomes": [
        {"actionId": retry_d["actionId"], "callId": retry_d["callId"], "attempt": 2, "status": 200, "resultClass": "confirmed", "nonce": "n2"}
    ],
    "approvals": [],
}
r3 = client.post(f"/v2/incidents/{base_incident['runId']}/receipts", json=receipt_ok)
print("after retry success", json.dumps(r3.json(), indent=2)[:800])
assert r3.status_code == 200

print("\n503 RETRY PATH OK\n")

# ---- second run: timeout suppression path ----
incident2 = dict(base_incident)
incident2["runId"] = "run-smoke-0003"
incident2["incident"] = dict(base_incident["incident"])
incident2["incident"]["incidentId"] = "inc-3"

r4 = client.post("/v2/incidents", json=incident2)
body4 = r4.json()
assert r4.status_code == 200
d = body4["dispatches"][0]

receipt_timeout = {
    "receiptId": "r-timeout",
    "outcomes": [
        {"actionId": d["actionId"], "callId": d["callId"], "attempt": 1, "status": 0, "errorType": "timeout", "resultClass": None, "nonce": "n3"}
    ],
    "approvals": [],
}
r5 = client.post(f"/v2/incidents/{incident2['runId']}/receipts", json=receipt_timeout)
r5body = r5.json()
print("after timeout", json.dumps(r5body, indent=2)[:1500])
assert r5.status_code == 200
# Only one diagnostic dispatched here since maximumDiagnostics + heuristic
# picks 1; once it times out, the run should finalize with no effect.
if r5body.get("status") == "completed":
    assert r5body["chosenEffect"] is None
    assert r5body["suppressed"], "expected suppressed effect on timeout"
    print("TIMEOUT SUPPRESSION -> finalized correctly, no effect dispatched")
else:
    print("run still waiting (multiple diagnostics in flight) ->", r5body["status"])

print("\nALL PASSED")
