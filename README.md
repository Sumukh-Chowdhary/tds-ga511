# Incident-Response Agent (ga5-incident-agent/v2)

A FastAPI service implementing the persistent, receipt-driven incident
response API: `POST /v2/incidents`, `POST /v2/incidents/{runId}/receipts`,
`GET /v2/incidents/{runId}`.

## What's implemented

- **Request validation** for the `ga5-incident-agent/v2` profile (400/422 on
  bad payloads or wrong profile; nothing is stored on rejection).
- **One model call per run** (`planner.py`) that reads the transcript
  (with `sensitive` stripped out before it ever reaches the model), extracts
  evidence-tagged lines, and asks a free-tier Gemini model for the root
  cause, 2-4 supporting evidence ids, 1-3 diagnostics, and one effect. If no
  `GEMINI_API_KEY` is set (or the call fails), a deterministic offline
  fallback plan is used instead so the service never dead-ends.
- **Receipt-driven state machine** (`app.py: _process_receipt`) that:
  - Accepts outcomes only for pending calls.
  - Allows exactly one retry on `503` (new attempt, new CLIENT span, new
    traceparent), and treats a second failure as terminal.
  - Fails the diagnostic (no dependent effect) on `status:0, errorType:
    "timeout"`.
  - Gates any effect tool listed in `policy.approvalRequiredFor` behind an
    `approval_gate`, computing `argumentsDigest` as SHA-256 over recursively
    key-sorted compact JSON, and only dispatches the effect after an
    `approved` receipt, carrying `approvalId`/`approvalNonce` on that
    dispatch.
  - Suppresses the effect entirely (and records it in `suppressed`) if a
    diagnostic fails/times out or an approval is rejected.
- **Exact replay semantics**: identical `POST /v2/incidents` (same `runId`,
  same body) returns the original frozen response with no new model call;
  changed content on the same `runId` returns `409`. Receipts follow the
  same identical-content-replay / changed-content-conflict rule per
  `receiptId`. Neither replay path touches stored state or the model.
- **OTLP trace** (`spans.py`) built only from stored dispatch/receipt state
  (never a fresh model call), with the exact required span shape:
  `SERVER POST /v2/incidents -> INTERNAL invoke_agent -> {CLIENT chat
  incident-plan (x1), INTERNAL execute_tool (x1/logical action) -> CLIENT
  POST tool/<name> (x1/physical attempt), INTERNAL incident.join (if >1
  diagnostic), INTERNAL approval_gate (if approval required)}`. Attributes
  such as `gen_ai.tool.call.arguments`/`result`, transcripts, prompts, and
  sensitive values are never attached to any span (`spans.py:
  FORBIDDEN_ATTR_SUBSTRINGS` is a belt-and-suspenders filter on top of never
  putting that data in span attributes in the first place).
- **SQLite persistence** (`store.py`) so runs and receipts survive process
  restarts; `runs` is keyed by `runId`, `receipts` by `(runId, receiptId)`.

## Design decisions worth knowing about (the spec leaves these open)

- **Run status on suppression**: if a diagnostic fails/times out or an
  approval is rejected, the run still finalizes as `"completed"` with
  `chosenEffect: null` and the tool name recorded in `suppressed` - the spec
  treats correctly withholding a destructive action as success, not
  failure. `"failed"` is reserved for the case where the dispatched effect
  itself comes back non-200.
- **A second `503`** (after the one allowed retry) is treated as a terminal
  diagnostic failure rather than a third attempt, since the spec caps
  retries at exactly one.
- **Effect dependency on diagnostics**: since only one effect is ever sent
  per run, "don't send the dependent effect" is implemented as "don't send
  the effect at all if any diagnostic in this run failed or timed out."
- **Action/call IDs**: generated as 16-char lowercase hex
  (`secrets.token_hex(8)`), well above the required 8-character minimum;
  `actionId` and `callId` are always distinct values for readability, which
  the spec explicitly allows either way.

## Running locally

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=...        # optional, see .env.example
uvicorn app:app --host 0.0.0.0 --port 8000
```

Two smoke tests are included and run fully in-process (no network, no API
key required - they exercise the offline fallback planner):

```bash
python3 smoke_test.py    # full happy path incl. approval-gated effect
python3 smoke_test2.py   # 503 retry path + timeout-suppression path
```

## Deploying to get a public HTTPS base URL

Pick any host that gives you a public HTTPS endpoint and a writable disk
for the SQLite file. A few options:

- **Render** (`render.com`): "New Web Service" from this repo, build
  command `pip install -r requirements.txt`, start command
  `uvicorn app:app --host 0.0.0.0 --port $PORT`. Add a persistent disk if
  you want the SQLite file to survive redeploys (not required for a single
  eval run). Set `GEMINI_API_KEY` in the environment tab.
- **Fly.io**: `fly launch`, then `fly deploy`; attach a small volume for
  the SQLite path if you want durability across restarts.
- **Railway**: connect the repo, it auto-detects the `Procfile`/start
  command; set `GEMINI_API_KEY` as a variable.

A minimal `Procfile` is included for platforms that use one.

Whatever host you pick, submit the base URL with **no trailing path,
credentials, query string, or fragment** (e.g. `https://your-app.onrender.com`),
matching what the spec asks for.

## Files

| file | purpose |
|---|---|
| `app.py` | FastAPI routes + the receipt-driven state machine |
| `planner.py` | the one place that calls a model |
| `spans.py` | OTLP span construction/assembly |
| `store.py` | SQLite persistence (runs + receipts) |
| `schemas.py` | pydantic request schemas |
| `utils.py` | hashing, id generation, evidence extraction, traceparent parsing |
| `smoke_test.py`, `smoke_test2.py` | in-process end-to-end tests |
