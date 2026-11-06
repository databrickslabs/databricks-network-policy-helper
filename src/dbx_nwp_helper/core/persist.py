"""Persist the ingress analysis to Unity Catalog (`--uc-schema catalog.schema`).

Two fixed-name Delta tables are created in the supplied schema:

  * `dbx_nwp_ingress_daily` — a per-(event_date, workspace, source IP, outcome) aggregate of
    system.access.audit. It is maintained **incrementally**: each run finds the table's date bounds and
    only aggregates the days it lacks (plus the two most recent days, re-read to absorb late-arriving
    audit rows), entirely server-side via INSERT … SELECT. The candidate / denied views are then
    re-aggregated from this table instead of re-scanning the audit log — the slow part for a large
    environment. `--refresh-persisted` rebuilds it from scratch.
  * `dbx_nwp_ingress_suggestions` — a snapshot of every run's proposed rules (owner group, CIDRs,
    recommendation) and what became of each: kept as a named rule, folded into a consolidated rule,
    dropped by a policy cap, deselected by the operator, or excluded (threat-matched / partner / no
    resolvable identities). This is the durable record of "what the tool found" the customer asked for.

`egress --uc-schema` does the same with `dbx_nwp_egress_daily` (per-day destination aggregate of
system.access.outbound_network) and `dbx_nwp_egress_suggestions`.

Everything here goes through the same SQL-warehouse connection the analysis uses; the caller needs
CREATE TABLE / MODIFY on the schema.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from ..config import (
    UC_DAILY_TABLE,
    UC_EGRESS_DAILY_TABLE,
    UC_EGRESS_SUGGESTIONS_TABLE,
    UC_SUGGESTIONS_TABLE,
    EgressConfig,
    IngressConfig,
)

Note = Callable[[str], None]

# How many of the most recent persisted days are re-aggregated on every run. Audit rows can land a day
# or so late, so the newest days are always refreshed rather than trusted as complete.
REREAD_TAIL_DAYS = 2
_INSERT_BATCH = 200


@dataclass(frozen=True)
class PersistedSource:
    """Fully-qualified, backtick-quoted table names under the --uc-schema."""

    daily_table: str
    suggestions_table: str
    egress_daily_table: str = ""
    egress_suggestions_table: str = ""


def _quote(part: str) -> str:
    part = part.strip()
    if part.startswith("`") and part.endswith("`"):
        return part
    return f"`{part}`"


def tables(uc_schema: str) -> PersistedSource:
    """Resolve `catalog.schema` (validated by config.validate_uc_schema) to the two table names."""
    catalog, schema = uc_schema.strip().rsplit(".", 1)
    prefix = f"{_quote(catalog)}.{_quote(schema)}"
    return PersistedSource(
        daily_table=f"{prefix}.{_quote(UC_DAILY_TABLE)}",
        suggestions_table=f"{prefix}.{_quote(UC_SUGGESTIONS_TABLE)}",
        egress_daily_table=f"{prefix}.{_quote(UC_EGRESS_DAILY_TABLE)}",
        egress_suggestions_table=f"{prefix}.{_quote(UC_EGRESS_SUGGESTIONS_TABLE)}",
    )


def ensure_tables(sql_conn, src: PersistedSource, direction: str = "ingress") -> None:
    """Create the direction's two tables if they don't exist yet."""
    from .. import queries, sql

    if direction == "egress":
        sql.execute(sql_conn, queries.egress_daily_table_ddl(src.egress_daily_table))
        sql.execute(sql_conn, queries.egress_suggestions_table_ddl(src.egress_suggestions_table))
    else:
        sql.execute(sql_conn, queries.daily_table_ddl(src.daily_table))
        sql.execute(sql_conn, queries.suggestions_table_ddl(src.suggestions_table))


def _as_date(value) -> dt.date | None:
    if value is None:
        return None
    if isinstance(value, dt.datetime):
        return value.date()
    if isinstance(value, dt.date):
        return value
    try:
        if value != value:  # NaN / NaT
            return None
    except TypeError:
        pass
    to_py = getattr(value, "to_pydatetime", None)
    if callable(to_py):
        return to_py().date()
    return dt.date.fromisoformat(str(value)[:10])


def plan_sync(
    lo: dt.date | None, hi: dt.date | None, today: dt.date, lookback_days: int, refresh: bool
) -> tuple[list[tuple[dt.date, dt.date]], dt.date | None]:
    """Decide which inclusive date windows to (re)aggregate given the table's current bounds.

    Returns (windows, delete_from): `delete_from` is the first date whose existing rows must be
    removed before inserting (None = nothing to delete). Windows never overlap and together cover
    exactly the dates the run's lookback needs that the table doesn't already hold reliably."""
    window_start = today - dt.timedelta(days=lookback_days)
    if refresh or lo is None or hi is None:
        # Empty table or forced rebuild (the caller has already cleared the table): one full window.
        return [(window_start, today)], None
    windows: list[tuple[dt.date, dt.date]] = []
    if lo > window_start:
        # Backfill older days the table doesn't have yet (the lookback grew).
        windows.append((window_start, lo - dt.timedelta(days=1)))
    tail_start = max(hi - dt.timedelta(days=REREAD_TAIL_DAYS - 1), window_start)
    windows.append((tail_start, today))
    return windows, tail_start


def sync_daily(
    sql_conn,
    table: str,
    *,
    lookback_days: int,
    refresh: bool,
    insert_sql: Callable[[str, str], str],
    note: Note,
    source_label: str,
) -> dict:
    """Bring a persisted daily table up to date for this run's lookback window. `insert_sql(start,
    end)` returns the INSERT … SELECT that aggregates the source rows for an inclusive ISO date window.
    Returns a small dict for the progress line: {"rows_before", "windows": [(start, end), …],
    "refreshed": bool}."""
    from .. import queries, sql

    bounds = sql.query(sql_conn, queries.daily_table_bounds(table))
    row = bounds.iloc[0] if not bounds.empty else {}
    lo, hi = _as_date(row.get("lo")), _as_date(row.get("hi"))
    rows_before = int(row.get("rows") or 0)
    today = _as_date(sql.query(sql_conn, queries.server_today()).iloc[0]["today"]) or dt.date.today()

    if refresh and rows_before:
        note(f"--refresh-persisted: clearing {rows_before:,} row(s) from {table} and rebuilding.")
        sql.execute(sql_conn, f"DELETE FROM {table}")
        lo = hi = None
    windows, delete_from = plan_sync(lo, hi, today, lookback_days, refresh)
    if delete_from is not None and not refresh:
        sql.execute(sql_conn, queries.daily_table_delete_from(table, delete_from.isoformat()))
    for start, end in windows:
        if start > end:
            continue
        note(f"Aggregating {source_label} {start} → {end} into {table}…")
        sql.execute(sql_conn, insert_sql(start.isoformat(), end.isoformat()))
    covered = f"{lo} → {hi}" if lo and hi else "(empty)"
    n_windows = len([w for w in windows if w[0] <= w[1]])
    note(
        f"Persisted daily table had {rows_before:,} row(s) covering {covered}; "
        f"synced {n_windows} window(s) for a {lookback_days}-day lookback."
    )
    return {"rows_before": rows_before, "windows": windows, "refreshed": bool(refresh)}


def sync_ingress_daily(
    sql_conn, src: PersistedSource, cfg: IngressConfig, use_inet: bool, note: Note
) -> dict:
    from .. import queries

    return sync_daily(
        sql_conn,
        src.daily_table,
        lookback_days=cfg.lookback_days,
        refresh=cfg.refresh_persisted,
        insert_sql=lambda a, b: queries.daily_table_insert(src.daily_table, a, b, use_inet=use_inet),
        note=note,
        source_label="system.access.audit",
    )


def sync_egress_daily(sql_conn, src: PersistedSource, cfg: EgressConfig, note: Note) -> dict:
    from .. import queries

    return sync_daily(
        sql_conn,
        src.egress_daily_table,
        lookback_days=cfg.lookback_days,
        refresh=cfg.refresh_persisted,
        insert_sql=lambda a, b: queries.egress_daily_table_insert(src.egress_daily_table, a, b),
        note=note,
        source_label="system.access.outbound_network",
    )


# ------------------------------------------------------------------------------ suggestions snapshot
def _lit(value) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "TRUE" if value else "FALSE"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        if not value:
            return "CAST(array() AS ARRAY<STRING>)"
        return "array(" + ", ".join(_lit(str(v)) for v in value) + ")"
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def snapshot_rows(
    analysis,
    cfg: IngressConfig,
    policies: dict,
    *,
    suggestion_rows_full: list[dict],
    framing_col: str,
    group_label: Callable[[dict], str],
) -> list[dict]:
    """One row per owner group the analysis proposed, with the fate of each in the final policy.
    `suggestion_rows_full` is the pre-selection list (so deselected groups are recorded too);
    `analysis.suggestion_rows` is the post-selection list."""
    selected = {(r["policy_target"], r["rdap_owner"]) for r in analysis.suggestion_rows}
    kept: dict = {}
    folded: dict = {}
    for tgt, p in policies.items():
        for s in p["allow"]:
            kept[(tgt, s["label"])] = s
            for src_label in s.get("consolidated_from") or []:
                folded[(tgt, src_label)] = s["label"]
    out = []
    for r in suggestion_rows_full:
        key = (r["policy_target"], r["rdap_owner"])
        label = group_label(r)
        tgt = r["policy_target"]
        consolidated_into = None
        if key not in selected:
            status = "deselected"
        elif not r.get("databricks_owned") and r.get("threat_feeds"):
            status = "excluded_threat"
        elif r.get("partners") and cfg.exclude_partner_cidrs:
            status = "excluded_partner"
        elif (tgt, label) in kept:
            status = "kept"
        elif (tgt, label) in folded:
            status, consolidated_into = "consolidated", folded[(tgt, label)]
        elif cfg.scope_identity and not r.get("databricks_owned") and tgt in policies:
            # Selected, not flagged, yet absent → identity scoping excluded it or a cap dropped it; the
            # cap case is reported via truncations, so attribute to the cap only when one happened.
            status = "dropped" if analysis.truncations else "excluded_unresolved"
        else:
            status = "dropped"
        out.append(
            {
                "policy_target": str(tgt),
                "rule_label": label,
                "rdap_owner": r["rdap_owner"],
                "recommendation": r.get("recommendation"),
                "distinct_ips": int(r.get("distinct_ips") or 0),
                "total_events": int(r.get("total_events") or 0),
                "cidrs": list(r.get(framing_col) or r.get("minimal_cidrs") or []),
                "status": status,
                "consolidated_into": consolidated_into,
            }
        )
    return out


def _insert_rows(sql_conn, table: str, cols: str, value_rows: list[list[str]]) -> None:
    """Batched literal INSERTs (a few hundred rows at most per run)."""
    from .. import sql

    for i in range(0, len(value_rows), _INSERT_BATCH):
        values = ["(" + ", ".join(r) + ")" for r in value_rows[i : i + _INSERT_BATCH]]
        sql.execute(sql_conn, f"INSERT INTO {table} ({cols}) VALUES\n" + ",\n".join(values))


def write_suggestions(
    sql_conn,
    src: PersistedSource,
    rows: list[dict],
    *,
    cfg: IngressConfig,
    workspace_id,
    policy_name: str,
    written: bool,
    run_id: str | None = None,
) -> str:
    """Insert the ingress snapshot rows. Returns the run id stamped on every row."""
    run_id = run_id or uuid.uuid4().hex[:12]
    cols = (
        "run_id, run_at, workspace_id, policy_name, policy_mode, policy_framing, policy_target, rule_label, "
        "rdap_owner, recommendation, distinct_ips, total_events, cidrs, status, consolidated_into, written"
    )
    value_rows = [
        [
            _lit(run_id),
            "current_timestamp()",
            _lit(str(workspace_id) if workspace_id is not None else None),
            _lit(policy_name),
            _lit(cfg.policy_mode),
            _lit(cfg.policy_framing),
            _lit(r["policy_target"]),
            _lit(r["rule_label"]),
            _lit(r["rdap_owner"]),
            _lit(r["recommendation"]),
            _lit(r["distinct_ips"]),
            _lit(r["total_events"]),
            _lit(r["cidrs"]),
            _lit(r["status"]),
            _lit(r["consolidated_into"]),
            _lit(written),
        ]
        for r in rows
    ]
    _insert_rows(sql_conn, src.suggestions_table, cols, value_rows)
    return run_id


# ------------------------------------------------------------------------- egress snapshot
def egress_snapshot_rows(analysis, cfg: EgressConfig, blocks: dict, *, targets_full: dict) -> list[dict]:
    """One row per observed egress destination (and per cross-workspace / blocked entry) with its fate
    in the final policy. `targets_full` is the pre-selection copy of analysis.targets so deselected
    destinations are recorded too; `blocks` is build_blocks() output for the final policy."""
    from . import egress as eg

    out: list[dict] = []

    def _allowed_sets(tgt):
        blk = blocks.get(tgt)
        na = getattr(blk, "network_access", None) if blk is not None else None
        inet = {d.destination for d in (getattr(na, "allowed_internet_destinations", None) or [])}
        stor = set()
        for d in getattr(na, "allowed_storage_destinations", None) or []:
            if d.bucket_name and d.region:
                stor.add(("s3", (d.bucket_name, d.region)))
            elif d.bucket_name:
                stor.add(("gcs", d.bucket_name))
            elif d.azure_storage_account:
                stor.add(("azure", (d.azure_storage_account, d.azure_storage_service)))
        xws = set()
        for d in getattr(na, "allowed_databricks_destinations", None) or []:
            xws.update(int(w) for w in (d.workspace_ids or []))
        return inet, stor, xws

    excluded_inet = {f: "excluded_nonglobal" for f, _ip, _r in analysis.skipped_nonglobal_fqdns}
    excluded_stor = {name: "excluded_cross_cloud" for _label, name in analysis.skipped_cross_cloud_storage}

    for tgt, full in targets_full.items():
        inet, stor, xws = _allowed_sets(tgt)
        now = analysis.targets.get(tgt) or eg._new_target()
        for fqdn, events in sorted(full["internet"].items(), key=lambda kv: -kv[1]):
            if fqdn in inet:
                status = "allowed"
            elif fqdn in excluded_inet:
                status = excluded_inet[fqdn]
            elif fqdn not in now["internet"]:
                status = "deselected"
            else:
                status = "capped"
            out.append(_erow(tgt, "internet", fqdn, analysis.fqdn_owner.get(fqdn), events, status))
        for kind in ("s3", "gcs", "azure"):
            for key, events in sorted(full[kind].items(), key=lambda kv: -kv[1]):
                name, detail = _storage_name_detail(kind, key)
                if (kind, key) in stor:
                    status = "allowed"
                elif eg._storage_display_name(kind, key) in excluded_stor:
                    status = "excluded_cross_cloud"
                elif key not in now[kind]:
                    status = "deselected"
                else:
                    status = "capped"
                out.append(_erow(tgt, kind, name, detail, events, status))
        if analysis.xws is not None:
            for wid, info in sorted(analysis.xws.resolved.items()):
                status = (
                    "allowed"
                    if wid in xws
                    else ("deselected" if wid not in analysis.xws_selected else "excluded")
                )
                out.append(
                    _erow(
                        tgt,
                        "databricks_workspace",
                        str(wid),
                        ", ".join(info["hosts"]),
                        info["events"],
                        status,
                    )
                )
    for bucket in analysis.dropped_s3_no_region:
        out.append(_erow("__ALL__", "s3", bucket, None, 0, "excluded_no_region"))
    for host, reason in analysis.skipped_invalid_hosts:
        out.append(_erow("__ALL__", "internet", host, reason, 0, "excluded_invalid_host"))
    if analysis.xws is not None:
        for host, reason in analysis.xws.unresolved:
            out.append(
                _erow(
                    "__ALL__",
                    "databricks_workspace",
                    host,
                    reason,
                    analysis.databricks_hosts.get(host, 0),
                    "unresolved_workspace",
                )
            )
    for domain in analysis.blocked_domains:
        out.append(_erow("__ALL__", "blocked_domain", domain, None, 0, "blocked"))
    return out


def _storage_name_detail(kind: str, key) -> tuple[str, str | None]:
    if kind == "s3":
        return key[0], key[1]
    if kind == "azure":
        return key[0], key[1]
    return key, None


def _erow(tgt, kind, destination, detail, events, status) -> dict:
    return {
        "policy_target": str(tgt),
        "kind": kind,
        "destination": str(destination),
        "detail": detail,
        "events": int(events or 0),
        "status": status,
    }


def write_egress_suggestions(
    sql_conn,
    src: PersistedSource,
    rows: list[dict],
    *,
    cfg: EgressConfig,
    workspace_id,
    policy_name: str,
    written: bool,
    run_id: str | None = None,
) -> str:
    run_id = run_id or uuid.uuid4().hex[:12]
    cols = (
        "run_id, run_at, workspace_id, policy_name, policy_mode, policy_target, kind, destination, detail, "
        "events, status, written"
    )
    value_rows = [
        [
            _lit(run_id),
            "current_timestamp()",
            _lit(str(workspace_id) if workspace_id is not None else None),
            _lit(policy_name),
            _lit(cfg.policy_mode),
            _lit(r["policy_target"]),
            _lit(r["kind"]),
            _lit(r["destination"]),
            _lit(r["detail"]),
            _lit(r["events"]),
            _lit(r["status"]),
            _lit(written),
        ]
        for r in rows
    ]
    _insert_rows(sql_conn, src.egress_suggestions_table, cols, value_rows)
    return run_id
