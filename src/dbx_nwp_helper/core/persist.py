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

Everything here goes through the same SQL-warehouse connection the analysis uses; the caller needs
CREATE TABLE / MODIFY on the schema.
"""

from __future__ import annotations

import datetime as dt
import uuid
from collections.abc import Callable
from dataclasses import dataclass

from ..config import UC_DAILY_TABLE, UC_SUGGESTIONS_TABLE, IngressConfig

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
    )


def ensure_tables(sql_conn, src: PersistedSource) -> None:
    from .. import queries, sql

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


def sync_daily(sql_conn, src: PersistedSource, cfg: IngressConfig, use_inet: bool, note: Note) -> dict:
    """Bring the daily table up to date for this run's lookback window. Returns a small dict for the
    progress line: {"rows_before", "windows": [(start, end), …], "refreshed": bool}."""
    from .. import queries, sql

    bounds = sql.query(sql_conn, queries.daily_table_bounds(src.daily_table))
    row = bounds.iloc[0] if not bounds.empty else {}
    lo, hi = _as_date(row.get("lo")), _as_date(row.get("hi"))
    rows_before = int(row.get("rows") or 0)
    today = _as_date(sql.query(sql_conn, queries.server_today()).iloc[0]["today"]) or dt.date.today()

    if cfg.refresh_persisted and rows_before:
        note(f"--refresh-persisted: clearing {rows_before:,} row(s) from {src.daily_table} and rebuilding.")
        sql.execute(sql_conn, f"DELETE FROM {src.daily_table}")
        lo = hi = None
    windows, delete_from = plan_sync(lo, hi, today, cfg.lookback_days, cfg.refresh_persisted)
    if delete_from is not None and not cfg.refresh_persisted:
        sql.execute(sql_conn, queries.daily_table_delete_from(src.daily_table, delete_from.isoformat()))
    for start, end in windows:
        if start > end:
            continue
        note(f"Aggregating system.access.audit {start} → {end} into {src.daily_table}…")
        sql.execute(
            sql_conn,
            queries.daily_table_insert(
                src.daily_table, start.isoformat(), end.isoformat(), use_inet=use_inet
            ),
        )
    covered = f"{lo} → {hi}" if lo and hi else "(empty)"
    n_windows = len([w for w in windows if w[0] <= w[1]])
    note(
        f"Persisted daily table had {rows_before:,} row(s) covering {covered}; "
        f"synced {n_windows} window(s) for a {cfg.lookback_days}-day lookback."
    )
    return {"rows_before": rows_before, "windows": windows, "refreshed": bool(cfg.refresh_persisted)}


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
    """Insert the snapshot rows (batched literal INSERTs — a few hundred rows at most). Returns the
    run id stamped on every row."""
    from .. import sql

    run_id = run_id or uuid.uuid4().hex[:12]
    cols = (
        "run_id, run_at, workspace_id, policy_name, policy_mode, policy_framing, policy_target, rule_label, "
        "rdap_owner, recommendation, distinct_ips, total_events, cidrs, status, consolidated_into, written"
    )
    for i in range(0, len(rows), _INSERT_BATCH):
        values = []
        for r in rows[i : i + _INSERT_BATCH]:
            values.append(
                "("
                + ", ".join(
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
                )
                + ")"
            )
        sql.execute(sql_conn, f"INSERT INTO {src.suggestions_table} ({cols}) VALUES\n" + ",\n".join(values))
    return run_id
