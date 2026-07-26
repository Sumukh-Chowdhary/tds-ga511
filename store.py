"""Durable persistence for runs and receipts.

Everything about a run is kept as one JSON blob in the `runs` table, keyed
by runId. Receipts are logged separately keyed by (runId, receiptId) so we
can detect replays vs conflicts without re-deriving anything or calling the
model again.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
from typing import Any, Optional

DB_PATH = os.environ.get("INCIDENT_AGENT_DB", "incident_agent.sqlite3")

_lock = threading.RLock()


def _connect() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


_conn = _connect()


def init_db() -> None:
    with _lock:
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS runs (
                run_id TEXT PRIMARY KEY,
                request_hash TEXT NOT NULL,
                state_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            )
            """
        )
        _conn.execute(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                run_id TEXT NOT NULL,
                receipt_id TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (run_id, receipt_id)
            )
            """
        )
        _conn.commit()


def get_run(run_id: str) -> Optional[dict[str, Any]]:
    with _lock:
        cur = _conn.execute(
            "SELECT request_hash, state_json FROM runs WHERE run_id = ?",
            (run_id,),
        )
        row = cur.fetchone()
        if row is None:
            return None
        request_hash, state_json = row
        state = json.loads(state_json)
        state["_request_hash"] = request_hash
        return state


def save_run(run_id: str, request_hash: str, state: dict[str, Any]) -> None:
    import time

    payload = {k: v for k, v in state.items() if k != "_request_hash"}
    blob = json.dumps(payload)
    now = time.time()
    with _lock:
        _conn.execute(
            """
            INSERT INTO runs (run_id, request_hash, state_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id) DO UPDATE SET
                state_json = excluded.state_json,
                updated_at = excluded.updated_at
            """,
            (run_id, request_hash, blob, now, now),
        )
        _conn.commit()


def get_receipt(run_id: str, receipt_id: str) -> Optional[dict[str, Any]]:
    with _lock:
        cur = _conn.execute(
            "SELECT receipt_hash, response_json FROM receipts WHERE run_id = ? AND receipt_id = ?",
            (run_id, receipt_id),
        )
        row = cur.fetchone()
        if row is None:
            return None
        receipt_hash, response_json = row
        return {"receipt_hash": receipt_hash, "response": json.loads(response_json)}


def save_receipt(run_id: str, receipt_id: str, receipt_hash: str, response: dict[str, Any]) -> None:
    import time

    with _lock:
        _conn.execute(
            """
            INSERT INTO receipts (run_id, receipt_id, receipt_hash, response_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(run_id, receipt_id) DO NOTHING
            """,
            (run_id, receipt_id, receipt_hash, json.dumps(response), time.time()),
        )
        _conn.commit()
