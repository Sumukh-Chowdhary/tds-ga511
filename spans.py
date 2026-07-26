"""OTLP span construction.

We keep an internal, simplified representation of each span as we build up
a run (plain dict with plain-python attribute values), and only convert to
the wire OTLP JSON shape once, at the very end, in `assemble_otlp`. Nothing
here ever calls a model - trace construction only ever reads stored state.
"""
from __future__ import annotations

from typing import Any, Optional

KIND_INTERNAL = 1
KIND_SERVER = 2
KIND_CLIENT = 3

STATUS_UNSET = 0
STATUS_OK = 1
STATUS_ERROR = 2

# Attributes we must never export under any circumstances.
FORBIDDEN_ATTR_SUBSTRINGS = (
    "transcript",
    "prompt",
    "sensitive",
    "arguments",
    "tool.call.arguments",
    "tool.call.result",
    "authorization",
    "accesstoken",
    "privatenote",
)


def _redact_check(attributes: dict[str, Any]) -> dict[str, Any]:
    clean = {}
    for k, v in attributes.items():
        lk = k.lower()
        if any(bad in lk for bad in FORBIDDEN_ATTR_SUBSTRINGS):
            continue
        clean[k] = v
    return clean


def make_span(
    span_id: str,
    parent_span_id: Optional[str],
    name: str,
    kind: int,
    attributes: dict[str, Any],
    status_code: int = STATUS_UNSET,
    status_message: Optional[str] = None,
    links: Optional[list[dict[str, str]]] = None,
) -> dict[str, Any]:
    return {
        "spanId": span_id,
        "parentSpanId": parent_span_id,
        "name": name,
        "kind": kind,
        "attributes": _redact_check(attributes),
        "statusCode": status_code,
        "statusMessage": status_message,
        "links": links or [],
    }


def _attr_kv(key: str, value: Any) -> dict[str, Any]:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def assemble_otlp(trace_id: str, spans: list[dict[str, Any]], scope_name: str = "incident-response-agent") -> dict[str, Any]:
    otlp_spans = []
    for s in spans:
        span_obj: dict[str, Any] = {
            "traceId": trace_id,
            "spanId": s["spanId"],
            "name": s["name"],
            "kind": s["kind"],
            "attributes": [_attr_kv(k, v) for k, v in s["attributes"].items()],
            "status": {"code": s.get("statusCode", STATUS_UNSET)},
        }
        if s.get("parentSpanId"):
            span_obj["parentSpanId"] = s["parentSpanId"]
        if s.get("statusMessage"):
            span_obj["status"]["message"] = s["statusMessage"]
        if s.get("links"):
            span_obj["links"] = [
                {"traceId": link["traceId"], "spanId": link["spanId"]} for link in s["links"]
            ]
        otlp_spans.append(span_obj)

    return {
        "resourceSpans": [
            {
                "resource": {"attributes": []},
                "scopeSpans": [
                    {
                        "scope": {"name": scope_name},
                        "spans": otlp_spans,
                    }
                ],
            }
        ]
    }
