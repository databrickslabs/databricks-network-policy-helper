#!/usr/bin/env python3
"""Create (or update) the "CBI Security Posture" Genie agent in one step.

1. Creates the Genie views in --schema (CREATE OR REPLACE VIEW only; genie/views.sql).
2. Builds the agent from genie/instructions.md, genie/trusted_queries.sql and the sample questions in
   genie/README.md.
3. Creates the agent, or updates the one with the same title, and prints its link.

This WRITES to the workspace (views in your schema, and a Genie agent), so the skill asks before running
it. It never creates warehouses, never grants access and never shares the agent. --print-only writes the
payload to a file and changes nothing.

Prerequisite: the collector has run once with --uc-schema <same schema> (the notebook's `uc_schema`
widget), so the snapshot tables exist.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import cbi_posture  # noqa: E402

DEFAULT_TITLE = "CBI Security Posture"
DESCRIPTION = ("Ask about context-based ingress (CBI) posture: who reaches the workspaces and account console, "
               "from where, what policies allow or would block, and what to fix first.")
SNAPSHOT_TABLES = ("cbi_posture_findings", "cbi_posture_workspaces")
TABLES = {  # agent data source -> description
    "cbi_audit_access": "One row per audited request, rolling 90 days. workspace_id '0' is the account console / account APIs.",
    "cbi_findings_latest": "Findings from the latest posture run, with severity, layer, recommendation and next step.",
    "cbi_inbound_events": "CBI policy denials (DENIED) and dry-run would-be denials (DRY_RUN_DENIAL), with the rule that matched.",
    "cbi_posture_latest": "Latest posture snapshot per workspace: maturity level, policy mode, IP ACLs, PrivateLink, PAT exposure.",
    "cbi_posture_workspaces": "Every posture snapshot per workspace (history; use for trends over time).",
}
PARAM_DEFAULTS = {"lookback_days": "30"}
SCHEMA_RE = re.compile(r"^[A-Za-z0-9_`-]+\.[A-Za-z0-9_`-]+$")


def find_genie_dir(start: Path) -> Path:
    for d in [start, *start.parents]:
        if (d / "genie" / "instructions.md").exists():
            return d / "genie"
    raise FileNotFoundError("genie/instructions.md not found above this script; pass --genie-dir")


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
    out, q, buf = [], None, []
    for line in text.splitlines():
        if line.startswith("-- Q:"):
            if q and "".join(buf).strip():
                out.append((q, "\n".join(buf).strip().rstrip(";")))
            q, buf = line[5:].strip(), []
        elif q is not None:
            buf.append(line)
    if q and "".join(buf).strip():
        out.append((q, "\n".join(buf).strip().rstrip(";")))
    return out


def parse_sample_questions(readme: str) -> list[str]:
    m = re.search(r"## Sample questions\n(.*?)(\n## |\Z)", readme, re.S)
    return [l[2:].strip() for l in (m.group(1) if m else "").splitlines() if l.startswith("- ")]


def general_instructions(md: str) -> str:
    return md.split("\n---\n", 1)[1].strip() if "\n---\n" in md else md.strip()


def build_space(schema: str, genie_dir: Path, inline_params: bool = False) -> dict:
    ids = _Ids()
    examples = []
    for q, sql in parse_trusted_queries((genie_dir / "trusted_queries.sql").read_text()):
        used = [p for p in PARAM_DEFAULTS if f":{p}" in sql]
        if inline_params:
            for p in used:
                sql = sql.replace(f":{p}", PARAM_DEFAULTS[p])
            used = []
        ex = {"id": ids(), "question": [q], "sql": _lines(sql)}
        if used:
            ex["parameters"] = [{"name": p, "type_hint": "INTEGER", "description": ["Days to look back"],
                                 "default_value": {"values": [PARAM_DEFAULTS[p]]}} for p in used]
        examples.append(ex)
    return {
        "version": 2,
        "config": {"sample_questions": [{"id": ids(), "question": [q]}
                                        for q in parse_sample_questions((genie_dir / "README.md").read_text())]},
        "data_sources": {"tables": [{"identifier": f"{schema}.{t}", "description": [d]}
                                    for t, d in sorted(TABLES.items())]},
        "instructions": {
            "text_instructions": [{"id": ids(), "content": _lines(general_instructions(
                (genie_dir / "instructions.md").read_text()))}],
            "example_question_sqls": examples,
        },
    }


def view_statements(schema: str, genie_dir: Path) -> list[str]:
    sql = (genie_dir / "views.sql").read_text().replace("<catalog>.<schema>", schema)
    stmts = [s.strip() for s in re.split(r";\s*\n", sql)]
    out = []
    for s in stmts:
        m = re.search(r"^\s*CREATE OR REPLACE VIEW", s, re.M | re.I)
        if m:
            out.append(s[m.start():].strip())  # drop leading comments
    return out


def pick_warehouse(w, log) -> str:
    """Use an existing warehouse (never creates one): prefer running serverless, then any serverless/pro."""
    whs = list(w.warehouses.list())
    def score(x):
        running = str(getattr(x.state, "value", x.state)) == "RUNNING"
        return (bool(x.enable_serverless_compute), running, str(getattr(x.warehouse_type, "value", "")) == "PRO")
    whs = [x for x in whs if x.enable_serverless_compute or str(getattr(x.warehouse_type, "value", "")) == "PRO"]
    if not whs:
        raise SystemExit("No serverless or Pro SQL warehouse found. Pass --warehouse-id (Genie needs one; this "
                         "script never creates warehouses).")
    best = max(whs, key=score)
    log(f"Using SQL warehouse {best.name} ({best.id}). Pass --warehouse-id to choose another.")
    return best.id


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


def main(argv: list[str] | None = None, spark=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--schema", required=True, help="catalog.schema holding the snapshot tables (the --uc-schema used)")
    ap.add_argument("--warehouse-id", help="SQL warehouse for the agent (default: an existing serverless/Pro one)")
    ap.add_argument("--workspace-profile", help="CLI profile (default: notebook / environment auth)")
    ap.add_argument("--title", default=DEFAULT_TITLE)
    ap.add_argument("--parent-path", help="workspace folder for the agent (default: your home folder)")
    ap.add_argument("--new", action="store_true", help="always create a new agent, even if one has this title")
    ap.add_argument("--skip-views", action="store_true", help="don't (re)create the views")
    ap.add_argument("--genie-dir", type=Path, help="folder with instructions.md, trusted_queries.sql, views.sql")
    ap.add_argument("--print-only", type=Path, metavar="FILE", help="write the agent payload to FILE; change nothing")
    args = ap.parse_args(argv)
    log = lambda m: print(m, file=sys.stderr)  # noqa: E731

    if not SCHEMA_RE.match(args.schema):
        raise SystemExit(f"--schema must be catalog.schema, got {args.schema!r}")
    genie_dir = args.genie_dir or find_genie_dir(Path(__file__).resolve().parent)
    space = build_space(args.schema, genie_dir)
    if args.print_only:
        args.print_only.write_text(json.dumps(space, indent=2))
        log(f"Wrote {args.print_only} ({len(space['instructions']['example_question_sqls'])} example queries). "
            "Nothing was changed.")
        return 0

    from databricks.sdk import WorkspaceClient

    w = WorkspaceClient(profile=args.workspace_profile) if args.workspace_profile else WorkspaceClient()
    spark = spark or cbi_posture._active_spark()
    wh = args.warehouse_id or pick_warehouse(w, log)
    execute = cbi_posture.spark_executor(spark, 30) if spark else cbi_posture.warehouse_executor(w, wh, 30)

    have = {str(r.get("tableName") or r.get("table_name") or "").lower()
            for r in execute(f"SHOW TABLES IN {args.schema}", params=False)}
    missing = [t for t in SNAPSHOT_TABLES if t not in have]
    if missing:
        raise SystemExit(f"{args.schema} has no {', '.join(missing)}. Run the collector once with "
                         f"--uc-schema {args.schema} (notebook widget `uc_schema`), then re-run this.")

    if not args.skip_views:
        stmts = view_statements(args.schema, genie_dir)
        for s in stmts:
            execute(s, params=False)
        log(f"Created or replaced {len(stmts)} views in {args.schema}.")

    existing = None if args.new else find_existing(w, args.title)
    def send(payload: dict):
        body = json.dumps(payload)
        if existing:
            return w.genie.update_space(existing.space_id, serialized_space=body, warehouse_id=wh,
                                        description=DESCRIPTION, title=args.title)
        return w.genie.create_space(wh, body, title=args.title, description=DESCRIPTION, parent_path=args.parent_path)
    try:
        res = send(space)
    except Exception as e:  # noqa: BLE001
        if "param" not in str(e).lower():
            raise
        log(f"Example-query parameters were rejected ({e}); retrying with lookback_days fixed at 30.")
        res = send(build_space(args.schema, genie_dir, inline_params=True))
    sid = res.space_id or (existing.space_id if existing else "")
    url = f"{w.config.host.rstrip('/')}/genie/rooms/{sid}"
    log(f"{'Updated' if existing else 'Created'} Genie agent '{args.title}': {url}")
    log("Not shared with anyone. Share it (CAN RUN); viewers also need SELECT on the views, because Genie "
        "runs queries as the person asking.")
    print(json.dumps({"space_id": sid, "url": url, "updated": bool(existing), "warehouse_id": wh}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
