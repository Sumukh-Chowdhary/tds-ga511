"""Shared low-level helpers: canonical hashing, id generation, evidence
extraction from transcripts, and W3C traceparent parsing/generation.

Nothing in this module ever calls a model and nothing here is allowed to
leak sensitive request data - callers are responsible for only passing in
already-redacted structures.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets
from typing import Optional, Tuple

TRACEPARENT_RE = re.compile(
    r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$"
)
# Evidence tags look like "[ev_something] the rest of the line ..."
EVIDENCE_LINE_RE = re.compile(r"^\s*\[([A-Za-z0-9_\-]+)\]")


def canonical_json(obj) -> str:
    """Recursively key-sorted, compact JSON. Used both for content hashing
    (replay/conflict detection) and for the argumentsDigest SHA-256 input.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def content_hash(obj) -> str:
    """Stable hash of a request body, used to detect 'same id, changed
    content' conflicts. Never stored or returned in plaintext form."""
    return sha256_hex(canonical_json(obj))


def arguments_digest(arguments: dict) -> str:
    return sha256_hex(canonical_json(arguments))


def new_hex_id(nbytes: int = 8) -> str:
    """Opaque nonempty id, >= 8 chars, lowercase hex."""
    return secrets.token_hex(nbytes)


def new_trace_id() -> str:
    return secrets.token_hex(16)  # 32 hex chars, nonzero w/ overwhelming prob


def new_span_id() -> str:
    return secrets.token_hex(8)  # 16 hex chars


def parse_traceparent(value: Optional[str]) -> Optional[Tuple[str, str]]:
    """Return (trace_id, parent_span_id) if valid, else None."""
    if not value:
        return None
    m = TRACEPARENT_RE.match(value.strip())
    if not m:
        return None
    trace_id, parent_span_id, _flags = m.groups()
    if trace_id == "0" * 32 or parent_span_id == "0" * 16:
        return None
    return trace_id, parent_span_id


def build_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    flags = "01" if sampled else "00"
    return f"00-{trace_id}-{span_id}-{flags}"


def extract_evidence_ids(transcript: str) -> list[str]:
    """Pull every leading bracketed evidence id from the transcript, in
    order of first appearance, de-duplicated."""
    seen: list[str] = []
    seen_set = set()
    for line in transcript.splitlines():
        m = EVIDENCE_LINE_RE.match(line)
        if m:
            eid = m.group(1)
            if eid not in seen_set:
                seen_set.add(eid)
                seen.append(eid)
    return seen


def evidence_lines_by_id(transcript: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in transcript.splitlines():
        m = EVIDENCE_LINE_RE.match(line)
        if m:
            out.setdefault(m.group(1), line.strip())
    return out
