"""`genie-setup`: a Genie agent over the posture (and, when present, ingress / egress) tables in a
`--uc-schema`, so admins can ask "what does our posture look like?" in plain English.

What it writes: CREATE OR REPLACE VIEW statements in that schema (the *_latest views and the
inbound_network events view) and one Genie space (created, or updated in place when one with the same
title exists). It never shares the space, grants access, or touches policies, settings or tokens.

The agent's files live in `dbx_nwp_helper/genie/` (shipped with the package): `instructions.md`,
`trusted_queries.sql` (one `-- Q:` block per example question) and `sample_questions.md`.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from ..config import (
    UC_DAILY_TABLE,
    UC_EGRESS_DAILY_TABLE,
    UC_EGRESS_SUGGESTIONS_TABLE,
    UC_POSTURE_DAILY_TABLE,
    UC_POSTURE_FINDINGS_TABLE,
    UC_POSTURE_TOKENS_TABLE,
    UC_POSTURE_WORKSPACES_TABLE,
    UC_SUGGESTIONS_TABLE,
)

ASSETS = Path(__file__).resolve().parent.parent / "genie"
DEFAULT_TITLE = "Databricks Security Posture"
DESCRIPTION = (
    "Ask about your Databricks security posture: who reaches the workspaces and account console and from "
    "where, what network policies allow or would block, which personal access tokens to revoke, and what "
    "to fix first. Built by dbx-nwp-helper."
)
INBOUND_VIEW = "dbx_nwp_inbound_events"
PARAM_DEFAULTS = {"lookback_days": "30"}
# The latest-run views, and the snapshot table each reads.
LATEST_VIEWS = {
    "dbx_nwp_posture_findings_latest": UC_POSTURE_FINDINGS_TABLE,
    "dbx_nwp_posture_latest": UC_POSTURE_WORKSPACES_TABLE,
    "dbx_nwp_posture_tokens_latest": UC_POSTURE_TOKENS_TABLE,
}
REQUIRED = (UC_POSTURE_FINDINGS_TABLE, UC_POSTURE_TOKENS_TABLE, UC_POSTURE_WORKSPACES_TABLE)
# Agent data source → description. Sources that don't exist in the schema are left out.
SOURCES = {
    INBOUND_VIEW: "CBI denials (DENIED) and dry-run would-be denials (DRY_RUN_DENIAL), last 90 days.",
    UC_DAILY_TABLE: "ingress: per-day source-IP aggregate of system.access.audit.",
    UC_EGRESS_DAILY_TABLE: "egress: serverless destinations per day from system.access.outbound_network.",
    UC_EGRESS_SUGGESTIONS_TABLE: "egress: destinations each run proposed, and what became of them.",
    UC_POSTURE_DAILY_TABLE: "Daily rollup of system.access.audit (SUM events); workspace '0' = account.",
    UC_POSTURE_WORKSPACES_TABLE: "Every posture snapshot per workspace (history: trends by run_at).",
    UC_SUGGESTIONS_TABLE: "ingress: rules each ingress run proposed, and what became of them.",
    "dbx_nwp_posture_findings_latest": "Latest posture findings: severity, recommendation, next step.",
    "dbx_nwp_posture_latest": "Latest posture per workspace: maturity, mode, IP ACLs, PrivateLink, PATs.",
    "dbx_nwp_posture_tokens_latest": "PATs worth revoking (latest run), with owners and reasons.",
}
_TABLE_REF = re.compile(r"\bdbx_nwp_[a-z_]+\b")


class _Ids:
    """32-char lowercase hex ids that sort in creation order (the API rejects unsorted collections)."""

    def __init__(self):
        self.base, self.n = time.time_ns() // 100, 0

    def __call__(self) -> str:
        self.n += 1
        return f"{self.base:016x}{self.n:016x}"


def _lines(text: str) -> list[str]:
    parts = text.strip("\n").split("\n")
    return [p + "\n" for p in parts[:-1]] + [parts[-1]]


def parse_trusted_queries(text: str) -> list[tuple[str, str]]:
    """[(question, sql)] from `-- Q: <question>` blocks."""
    out, q, buf = [], None, []
    for line in text.splitlines() + ["-- Q:"]:
        if line.startswith("-- Q:"):
            if q and "".join(buf).strip():
                out.append((q, "\n".join(buf).strip().rstrip(";")))
            q, buf = line[5:].strip(), []
        elif q is not None:
            buf.append(line)
    return out


def sample_questions(text: str) -> list[str]:
    return [line[2:].strip() for line in text.splitlines() if line.startswith("- ")]


def view_statements(prefix: str, available: set[str]) -> list[tuple[str, str]]:
    """[(view, CREATE OR REPLACE VIEW …)] for the schema `prefix` (`catalog`.`schema`), only over
    snapshot tables that exist. The inbound_network view is always attempted (best-effort)."""
    from .. import queries

    out = [
        (view, queries.posture_latest_view(f"{prefix}.`{view}`", f"{prefix}.`{table}`"))
        for view, table in sorted(LATEST_VIEWS.items())
        if table in available
    ]
    return out + [(INBOUND_VIEW, queries.inbound_events_view(f"{prefix}.`{INBOUND_VIEW}`"))]


def build_space(prefix: str, sources: set[str], inline_params: bool = False) -> dict:
    """The serialized Genie space (version 2) over `sources` (short names present in the schema).
    Example queries that read a missing source are left out."""
    ids = _Ids()
    examples = []
    for q, sql in parse_trusted_queries((ASSETS / "trusted_queries.sql").read_text()):
        if not set(_TABLE_REF.findall(sql)) <= sources:
            continue
        used = [p for p in PARAM_DEFAULTS if f":{p}" in sql]
        if inline_params:
            for p in used:
                sql = sql.replace(f":{p}", PARAM_DEFAULTS[p])
            used = []
        ex = {"id": ids(), "question": [q], "sql": _lines(sql)}
        if used:
            ex["parameters"] = [
                {
                    "default_value": {"values": [PARAM_DEFAULTS[p]]},
                    "description": ["Days to look back"],
                    "name": p,
                    "type_hint": "INTEGER",
                }
                for p in used
            ]
        examples.append(ex)
    questions = sample_questions((ASSETS / "sample_questions.md").read_text())
    return {
        "config": {"sample_questions": [{"id": ids(), "question": [q]} for q in questions]},
        "data_sources": {
            "tables": [
                {"description": [SOURCES[t]], "identifier": f"{prefix}.`{t}`".replace("`", "")}
                for t in sorted(sources)
                if t in SOURCES
            ]
        },
        "instructions": {
            "example_question_sqls": examples,
            "text_instructions": [{"content": _lines((ASSETS / "instructions.md").read_text()), "id": ids()}],
        },
        "version": 2,
    }


@dataclass
class SetupResult:
    space_id: str
    updated: bool
    url: str
    sources: list[str]
    views: list[str]


def find_existing(w, title: str):
    token = None
    while True:
        resp = w.genie.list_spaces(page_token=token)
        for s in resp.spaces or []:
            if (s.title or "") == title:
                return s
        token = resp.next_page_token
        if not token:
            return None


def send(w, space: dict, warehouse_id: str, title: str, existing, parent_path: str | None):
    body = json.dumps(space)
    if existing is not None:
        return w.genie.update_space(
            existing.space_id,
            serialized_space=body,
            warehouse_id=warehouse_id,
            description=DESCRIPTION,
            title=title,
        )
    return w.genie.create_space(
        warehouse_id, body, title=title, description=DESCRIPTION, parent_path=parent_path
    )
