from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

import planner
import store
from schemas import SUPPORTED_PROFILE, IncidentRequest, ReceiptRequest
from spans import (
    KIND_CLIENT,
    KIND_INTERNAL,
    KIND_SERVER,
    STATUS_ERROR,
    STATUS_OK,
    assemble_otlp,
    make_span,
)
from utils import (
    arguments_digest,
    build_traceparent,
    content_hash,
    new_hex_id,
    new_span_id,
    new_trace_id,
    parse_traceparent,
)

MAX_RESPONSE_BYTES = 768 * 1024

app = FastAPI(redirect_slashes=False)
store.init_db()


@app.get("/")
async def health():
    # Platform health checks (Render/Fly/etc default to GET /) must see a
    # 200 or the platform may treat the instance as unhealthy and restart
    # it mid-grading, which looks like every check failing at once.
    return {"status": "ok"}


def _json(payload: dict[str, Any], status_code: int = 200) -> JSONResponse:
    body = json.dumps(payload)
    if len(body.encode("utf-8")) > MAX_RESPONSE_BYTES:
        # Should not happen in practice; fail loudly rather than silently
        # truncate and risk an inconsistent stored/returned state.
        return JSONResponse({"error": "response too large"}, status_code=500)
    return JSONResponse(payload, status_code=status_code)


# --------------------------------------------------------------------------
# POST /v2/incidents
# --------------------------------------------------------------------------
@app.post("/v2/incidents")
async def create_incident(request: Request):
    raw = await request.json()
    try:
        parsed = IncidentRequest.model_validate(raw)
    except ValidationError:
        return _json({"error": "invalid request"}, status_code=400)

    if parsed.profile != SUPPORTED_PROFILE:
        return _json({"error": "unsupported profile"}, status_code=422)

    req_hash = content_hash(raw)
    existing = store.get_run(parsed.runId)
    if existing is not None:
        if existing["_request_hash"] == req_hash:
            return _json(existing["initialResponse"], status_code=200)
        return _json({"error": "runId exists with different content"}, status_code=409)

    incident_public = parsed.incident.model_dump()  # never includes `sensitive`
    tool_catalog = [t.model_dump() for t in parsed.toolCatalog]
    policy = parsed.policy.model_dump()

    plan = planner.plan(incident_public, tool_catalog, policy)

    incoming_tp = parse_traceparent(request.headers.get("traceparent"))
    incoming_ts = request.headers.get("tracestate")
    if incoming_tp:
        trace_id, incoming_parent_span_id = incoming_tp
    else:
        trace_id = new_trace_id()
        incoming_parent_span_id = None
        incoming_ts = None

    spans: list[dict[str, Any]] = []
    base_attrs = {"ga5.run.id": parsed.runId, "ga5.public.marker": parsed.publicMarker}

    server_span_id = new_span_id()
    spans.append(
        make_span(
            server_span_id,
            incoming_parent_span_id,
            "POST /v2/incidents",
            KIND_SERVER,
            {**base_attrs, "http.request.method": "POST", "http.route": "/v2/incidents"},
        )
    )

    agent_span_id = new_span_id()
    spans.append(
        make_span(
            agent_span_id,
            server_span_id,
            "invoke_agent incident-response",
            KIND_INTERNAL,
            {**base_attrs},
        )
    )

    chat_span_id = new_span_id()
    spans.append(
        make_span(
            chat_span_id,
            agent_span_id,
            "chat incident-plan",
            KIND_CLIENT,
            {
                **base_attrs,
                "gen_ai.operation.name": "chat",
                "gen_ai.request.model": plan.model_name,
            },
            status_code=STATUS_OK,
        )
    )

    actions: dict[str, Any] = {}
    action_order: list[str] = []
    action_log: list[dict[str, Any]] = []
    diagnostic_execute_span_ids: list[str] = []

    max_diag = policy.get("maximumDiagnostics", 3)
    for diag in plan.diagnostics[:max_diag][:3]:
        action_id = new_hex_id()
        call_id = new_hex_id()
        execute_span_id = new_span_id()
        spans.append(
            make_span(
                execute_span_id,
                agent_span_id,
                f"execute_tool {diag['toolName']}",
                KIND_INTERNAL,
                {
                    **base_attrs,
                    "ga5.action.id": action_id,
                    "gen_ai.tool.name": diag["toolName"],
                    "gen_ai.tool.call.id": call_id,
                    "gen_ai.operation.name": "execute_tool",
                },
            )
        )
        diagnostic_execute_span_ids.append(execute_span_id)

        client_span_id = new_span_id()
        spans.append(
            make_span(
                client_span_id,
                execute_span_id,
                f"POST tool/{diag['toolName']}",
                KIND_CLIENT,
                {
                    **base_attrs,
                    "ga5.action.id": action_id,
                    "ga5.attempt": 1,
                    "http.request.method": "POST",
                    "http.request.resend_count": 0,
                },
            )
        )
        traceparent = build_traceparent(trace_id, client_span_id)

        dispatch = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": diag["toolName"],
            "arguments": diag["arguments"],
            "evidence": diag["evidence"],
            "attempt": 1,
            "traceparent": traceparent,
        }
        action_log.append(dispatch)

        actions[action_id] = {
            "callId": call_id,
            "toolName": diag["toolName"],
            "phase": "diagnostic",
            "arguments": diag["arguments"],
            "evidence": diag["evidence"],
            "executeSpanId": execute_span_id,
            "currentStatus": "pending",
            "attempts": [
                {
                    "attempt": 1,
                    "clientSpanId": client_span_id,
                    "traceparent": traceparent,
                    "status": "pending",
                }
            ],
        }
        action_order.append(action_id)

    join_span_id = None
    if len(diagnostic_execute_span_ids) > 1:
        join_span_id = new_span_id()
        spans.append(
            make_span(
                join_span_id,
                agent_span_id,
                "incident.join",
                KIND_INTERNAL,
                {**base_attrs},
                links=[{"traceId": trace_id, "spanId": sid} for sid in diagnostic_execute_span_ids],
            )
        )

    diagnosis = {"rootCause": plan.root_cause, "evidence": plan.evidence}
    dispatches_for_response = [d for d in action_log]  # diagnostics only, at this point

    response = {
        "runId": parsed.runId,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": dispatches_for_response,
        "approvals": [],
    }

    run_state = {
        "runId": parsed.runId,
        "profile": parsed.profile,
        "agentName": parsed.agentName,
        "publicMarker": parsed.publicMarker,
        "incident": incident_public,  # kept internally only, never re-exported
        "toolCatalog": tool_catalog,
        "policy": policy,
        "traceId": trace_id,
        "incomingTraceState": incoming_ts,
        "serverSpanId": server_span_id,
        "agentSpanId": agent_span_id,
        "chatSpanId": chat_span_id,
        "joinSpanId": join_span_id,
        "diagnosis": diagnosis,
        "proposedEffect": plan.effect,
        "actions": actions,
        "actionOrder": action_order,
        "actionLog": action_log,
        "receiptLog": [],
        "spans": spans,
        "approval": None,
        "effectActionId": None,
        "effectDecided": False,
        "suppressed": [],
        "status": "waiting",
        "chosenEffect": None,
        "modelName": plan.model_name,
        "initialResponse": response,
        "currentResponse": response,
    }

    store.save_run(parsed.runId, req_hash, run_state)
    return _json(response, status_code=200)


# --------------------------------------------------------------------------
# POST /v2/incidents/{runId}/receipts
# --------------------------------------------------------------------------
@app.post("/v2/incidents/{runId}/receipts")
async def post_receipt(runId: str, request: Request):
    raw = await request.json()
    run = store.get_run(runId)
    if run is None:
        return _json({"error": "unknown runId"}, status_code=404)

    try:
        parsed = ReceiptRequest.model_validate(raw)
    except ValidationError:
        return _json({"error": "invalid receipt"}, status_code=400)

    receipt_hash = content_hash(raw)
    existing_receipt = store.get_receipt(runId, parsed.receiptId)
    if existing_receipt is not None:
        if existing_receipt["receipt_hash"] == receipt_hash:
            return _json(existing_receipt["response"], status_code=200)
        return _json({"error": "receiptId exists with different content"}, status_code=409)

    if run["status"] in ("completed", "failed"):
        # Terminal run: nothing left to accept, just hand back current state.
        return _json(run["currentResponse"], status_code=200)

    response = _process_receipt(run, parsed)

    run["currentResponse"] = response
    store.save_run(runId, run["_request_hash"], run)
    store.save_receipt(runId, parsed.receiptId, receipt_hash, response)
    return _json(response, status_code=200)


def _base_attrs(run: dict[str, Any]) -> dict[str, Any]:
    return {"ga5.run.id": run["runId"], "ga5.public.marker": run["publicMarker"]}


def _process_receipt(run: dict[str, Any], receipt: ReceiptRequest) -> dict[str, Any]:
    trace_id = run["traceId"]
    base_attrs = _base_attrs(run)
    new_dispatches: list[dict[str, Any]] = []
    new_approvals_out: list[dict[str, Any]] = []

    span_by_id = {s["spanId"]: s for s in run["spans"]}

    # ---- tool outcomes -------------------------------------------------
    for outcome in receipt.outcomes:
        action = run["actions"].get(outcome.actionId)
        if action is None or action["callId"] != outcome.callId:
            continue  # not a pending/known call - ignore
        if not action["attempts"]:
            continue
        last = action["attempts"][-1]
        if last["attempt"] != outcome.attempt or last["status"] != "pending":
            continue  # only accept outcomes for pending calls

        client_span = span_by_id.get(last["clientSpanId"])

        if outcome.status == 200:
            last["status"] = "success"
            action["currentStatus"] = "success"
            if client_span is not None:
                client_span["attributes"]["ga5.receipt.id"] = receipt.receiptId
                client_span["attributes"]["ga5.receipt.nonce"] = outcome.nonce
                client_span["attributes"]["http.response.status_code"] = 200
                client_span["statusCode"] = STATUS_OK
            run["receiptLog"].append(
                {
                    "receiptId": receipt.receiptId,
                    "actionId": outcome.actionId,
                    "callId": outcome.callId,
                    "attempt": outcome.attempt,
                    "status": 200,
                    "resultClass": outcome.resultClass,
                    "nonce": outcome.nonce,
                }
            )

        elif outcome.status == 503 and last["attempt"] == 1:
            last["status"] = "failed_retry"
            if client_span is not None:
                client_span["attributes"]["ga5.receipt.id"] = receipt.receiptId
                client_span["attributes"]["ga5.receipt.nonce"] = outcome.nonce
                client_span["attributes"]["error.type"] = "503"
                client_span["statusCode"] = STATUS_ERROR
            run["receiptLog"].append(
                {
                    "receiptId": receipt.receiptId,
                    "actionId": outcome.actionId,
                    "callId": outcome.callId,
                    "attempt": outcome.attempt,
                    "status": 503,
                    "resultClass": outcome.resultClass,
                    "nonce": outcome.nonce,
                }
            )
            # exactly one retry allowed
            new_attempt_no = 2
            new_client_span_id = new_span_id()
            run["spans"].append(
                make_span(
                    new_client_span_id,
                    action["executeSpanId"],
                    f"POST tool/{action['toolName']}",
                    KIND_CLIENT,
                    {
                        **base_attrs,
                        "ga5.action.id": outcome.actionId,
                        "ga5.attempt": new_attempt_no,
                        "http.request.method": "POST",
                        "http.request.resend_count": 1,
                    },
                )
            )
            span_by_id[new_client_span_id] = run["spans"][-1]
            new_traceparent = build_traceparent(trace_id, new_client_span_id)
            action["attempts"].append(
                {
                    "attempt": new_attempt_no,
                    "clientSpanId": new_client_span_id,
                    "traceparent": new_traceparent,
                    "status": "pending",
                }
            )
            redispatch = {
                "actionId": outcome.actionId,
                "callId": outcome.callId,
                "phase": action["phase"],
                "toolName": action["toolName"],
                "arguments": action["arguments"],
                "evidence": action.get("evidence", []),
                "attempt": new_attempt_no,
                "traceparent": new_traceparent,
            }
            run["actionLog"].append(redispatch)
            new_dispatches.append(redispatch)

        elif outcome.status == 0 and outcome.errorType == "timeout":
            last["status"] = "failed_timeout"
            action["currentStatus"] = "failed"
            if client_span is not None:
                client_span["attributes"]["ga5.receipt.id"] = receipt.receiptId
                client_span["attributes"]["ga5.receipt.nonce"] = outcome.nonce
                client_span["attributes"]["error.type"] = "timeout"
                client_span["statusCode"] = STATUS_ERROR
            run["receiptLog"].append(
                {
                    "receiptId": receipt.receiptId,
                    "actionId": outcome.actionId,
                    "callId": outcome.callId,
                    "attempt": outcome.attempt,
                    "status": 0,
                    "resultClass": outcome.resultClass,
                    "nonce": outcome.nonce,
                }
            )
            # Suppression of the dependent effect itself is recorded once
            # the diagnostics have all resolved and we know the effect's
            # name (see the finalization branch below) - we only mark the
            # diagnostic itself as failed here.

        else:
            # Any other terminal outcome (including a second 503) fails
            # the call without a further retry.
            last["status"] = "failed"
            action["currentStatus"] = "failed"
            if client_span is not None:
                client_span["attributes"]["ga5.receipt.id"] = receipt.receiptId
                client_span["attributes"]["ga5.receipt.nonce"] = outcome.nonce
                client_span["attributes"]["error.type"] = str(outcome.status)
                client_span["statusCode"] = STATUS_ERROR
            run["receiptLog"].append(
                {
                    "receiptId": receipt.receiptId,
                    "actionId": outcome.actionId,
                    "callId": outcome.callId,
                    "attempt": outcome.attempt,
                    "status": outcome.status,
                    "resultClass": outcome.resultClass,
                    "nonce": outcome.nonce,
                }
            )

    # ---- approval decisions ---------------------------------------------
    approval = run.get("approval")
    if approval is not None and approval["status"] == "pending":
        for dec in receipt.approvals:
            if dec.approvalId != approval["approvalId"]:
                continue
            approval["status"] = dec.decision
            approval["receiptId"] = receipt.receiptId
            approval["nonce"] = dec.nonce

            gate_span = span_by_id.get(approval["spanId"])
            if gate_span is not None:
                gate_span["attributes"]["ga5.approval.id"] = approval["approvalId"]
                gate_span["attributes"]["ga5.approval.receipt.nonce"] = dec.nonce
                gate_span["statusCode"] = STATUS_OK if dec.decision == "approved" else STATUS_ERROR

            run["receiptLog"].append(
                {
                    "receiptId": receipt.receiptId,
                    "approvalId": approval["approvalId"],
                    "decision": dec.decision,
                    "nonce": dec.nonce,
                }
            )

            if dec.decision == "approved":
                action_id = approval["actionId"]
                call_id = approval["callId"]
                client_span_id = new_span_id()
                run["spans"].append(
                    make_span(
                        client_span_id,
                        approval["executeSpanId"],
                        f"POST tool/{approval['toolName']}",
                        KIND_CLIENT,
                        {
                            **base_attrs,
                            "ga5.action.id": action_id,
                            "ga5.attempt": 1,
                            "http.request.method": "POST",
                            "http.request.resend_count": 0,
                        },
                    )
                )
                span_by_id[client_span_id] = run["spans"][-1]
                traceparent = build_traceparent(trace_id, client_span_id)

                run["actions"][action_id] = {
                    "callId": call_id,
                    "toolName": approval["toolName"],
                    "phase": "effect",
                    "arguments": approval["arguments"],
                    "evidence": [],
                    "executeSpanId": approval["executeSpanId"],
                    "currentStatus": "pending",
                    "attempts": [
                        {
                            "attempt": 1,
                            "clientSpanId": client_span_id,
                            "traceparent": traceparent,
                            "status": "pending",
                        }
                    ],
                }
                run["actionOrder"].append(action_id)
                run["effectActionId"] = action_id

                dispatch = {
                    "actionId": action_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": approval["toolName"],
                    "arguments": approval["arguments"],
                    "evidence": [],
                    "attempt": 1,
                    "traceparent": traceparent,
                    "approvalId": approval["approvalId"],
                    "approvalNonce": dec.nonce,
                }
                run["actionLog"].append(dispatch)
                new_dispatches.append(dispatch)
            else:
                run["suppressed"].append(approval["toolName"])
            break

    # ---- decide whether we can move the state machine forward -----------
    diagnostics_pending = any(
        a["phase"] == "diagnostic" and a["currentStatus"] == "pending"
        for a in run["actions"].values()
    )

    if not diagnostics_pending and not run["effectDecided"] and approval is None:
        diagnostics_failed = any(
            a["phase"] == "diagnostic" and a["currentStatus"] == "failed"
            for a in run["actions"].values()
        )
        proposed = run.get("proposedEffect")
        if diagnostics_failed or not proposed or not proposed.get("toolName"):
            if proposed and proposed.get("toolName"):
                run["suppressed"].append(proposed["toolName"])
            run["effectDecided"] = True
            return _finalize(run)

        effect_tool = proposed["toolName"]
        effect_args = proposed.get("arguments", {})
        if effect_tool in run["policy"].get("approvalRequiredFor", []):
            action_id = new_hex_id()
            call_id = new_hex_id()
            execute_span_id = new_span_id()
            run["spans"].append(
                make_span(
                    execute_span_id,
                    run["agentSpanId"],
                    f"execute_tool {effect_tool}",
                    KIND_INTERNAL,
                    {
                        **base_attrs,
                        "ga5.action.id": action_id,
                        "gen_ai.tool.name": effect_tool,
                        "gen_ai.tool.call.id": call_id,
                        "gen_ai.operation.name": "execute_tool",
                    },
                )
            )
            approval_id = new_hex_id()
            gate_span_id = new_span_id()
            run["spans"].append(
                make_span(
                    gate_span_id,
                    run["agentSpanId"],
                    "approval_gate",
                    KIND_INTERNAL,
                    {**base_attrs, "ga5.approval.id": approval_id},
                )
            )
            digest = arguments_digest(effect_args)
            run["approval"] = {
                "approvalId": approval_id,
                "actionId": action_id,
                "callId": call_id,
                "toolName": effect_tool,
                "arguments": effect_args,
                "argumentsDigest": digest,
                "status": "pending",
                "spanId": gate_span_id,
                "executeSpanId": execute_span_id,
            }
            run["effectDecided"] = True
            new_approvals_out.append(
                {
                    "approvalId": approval_id,
                    "actionId": action_id,
                    "toolName": effect_tool,
                    "argumentsDigest": digest,
                }
            )
        else:
            action_id = new_hex_id()
            call_id = new_hex_id()
            execute_span_id = new_span_id()
            run["spans"].append(
                make_span(
                    execute_span_id,
                    run["agentSpanId"],
                    f"execute_tool {effect_tool}",
                    KIND_INTERNAL,
                    {
                        **base_attrs,
                        "ga5.action.id": action_id,
                        "gen_ai.tool.name": effect_tool,
                        "gen_ai.tool.call.id": call_id,
                        "gen_ai.operation.name": "execute_tool",
                    },
                )
            )
            client_span_id = new_span_id()
            run["spans"].append(
                make_span(
                    client_span_id,
                    execute_span_id,
                    f"POST tool/{effect_tool}",
                    KIND_CLIENT,
                    {
                        **base_attrs,
                        "ga5.action.id": action_id,
                        "ga5.attempt": 1,
                        "http.request.method": "POST",
                        "http.request.resend_count": 0,
                    },
                )
            )
            traceparent = build_traceparent(trace_id, client_span_id)
            run["actions"][action_id] = {
                "callId": call_id,
                "toolName": effect_tool,
                "phase": "effect",
                "arguments": effect_args,
                "evidence": [],
                "executeSpanId": execute_span_id,
                "currentStatus": "pending",
                "attempts": [
                    {
                        "attempt": 1,
                        "clientSpanId": client_span_id,
                        "traceparent": traceparent,
                        "status": "pending",
                    }
                ],
            }
            run["actionOrder"].append(action_id)
            run["effectActionId"] = action_id
            run["effectDecided"] = True
            dispatch = {
                "actionId": action_id,
                "callId": call_id,
                "phase": "effect",
                "toolName": effect_tool,
                "arguments": effect_args,
                "evidence": [],
                "attempt": 1,
                "traceparent": traceparent,
            }
            run["actionLog"].append(dispatch)
            new_dispatches.append(dispatch)

    # If the effect action itself just resolved, finish the run.
    effect_action_id = run.get("effectActionId")
    if effect_action_id is not None:
        effect_action = run["actions"].get(effect_action_id)
        if effect_action is not None and effect_action["currentStatus"] in ("success", "failed"):
            return _finalize(run)

    if run.get("approval") is not None and run["approval"]["status"] == "rejected":
        return _finalize(run)

    return {
        "runId": run["runId"],
        "status": "waiting",
        "diagnosis": run["diagnosis"],
        "dispatches": new_dispatches,
        "approvals": new_approvals_out,
    }


def _finalize(run: dict[str, Any]) -> dict[str, Any]:
    effect_action_id = run.get("effectActionId")
    chosen_effect = None
    run_status = "completed"
    if effect_action_id is not None:
        effect_action = run["actions"].get(effect_action_id)
        if effect_action is not None:
            if effect_action["currentStatus"] == "success":
                chosen_effect = effect_action["toolName"]
            else:
                run_status = "failed"

    run["status"] = run_status
    run["chosenEffect"] = chosen_effect

    otlp = assemble_otlp(run["traceId"], run["spans"])

    final = {
        "runId": run["runId"],
        "status": run_status,
        "diagnosis": run["diagnosis"],
        "chosenEffect": chosen_effect,
        "suppressed": run["suppressed"],
        "actionLog": run["actionLog"],
        "receiptLog": run["receiptLog"],
        "otlp": otlp,
    }
    return final


# --------------------------------------------------------------------------
# GET /v2/incidents/{runId}
# --------------------------------------------------------------------------
@app.get("/v2/incidents/{runId}")
async def get_incident(runId: str):
    run = store.get_run(runId)
    if run is None:
        return _json({"error": "unknown runId"}, status_code=404)
    return _json(run["currentResponse"], status_code=200)
