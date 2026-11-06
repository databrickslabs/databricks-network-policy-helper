"""SQL warehouse resolution + query execution.

The CLI needs a running SQL warehouse to query the system tables. This module:
  1. Resolves the warehouse http_path — an explicit `--warehouse-http-path`, else it reuses an
     existing warehouse by name, else it creates a small serverless one (and starts it).
  2. Connects with `databricks-sql-connector`, authenticating via the SDK's unified auth (so the
     same profile/env drives both the SDK and the SQL connection — no separate token handling).
  3. Runs a query and returns a pandas DataFrame, with Spark `array<>` columns coming back as plain
     Python lists (the connector already does this via Arrow).
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterator

import pandas as pd
from databricks import sql as dbsql
from databricks.sdk.service.sql import (
    CreateWarehouseRequestWarehouseType,
    EndpointInfoWarehouseType,
    State,
)

from . import auth
from .config import Connection
from .console import banner, status


def _http_path_for(warehouse_id: str) -> str:
    return f"/sql/1.0/warehouses/{warehouse_id}"


def _resize_warehouse(w, existing, cluster_size: str):
    """Edit an existing warehouse to `cluster_size`, preserving its other settings, then return the
    refreshed warehouse. Editing an *active* warehouse restarts it, so we wait for it to come back
    RUNNING; a stopped one just gets the new config (it's started by the caller). Best-effort: if the
    edit fails (e.g. no permission), warn and keep the current size rather than aborting the run."""
    from databricks.sdk.service.sql import EditWarehouseRequestWarehouseType

    was_active = existing.state in (State.RUNNING, State.STARTING)
    banner(
        "info",
        f"Resizing warehouse '{existing.name}' from {existing.cluster_size} to {cluster_size} "
        f"(honouring --warehouse-size)…",
    )
    # Re-send the warehouse's own settings so only the size changes (the edit API treats omitted
    # fields as defaults). warehouse_type uses a different enum on edit — convert by value.
    kw = {
        "cluster_size": cluster_size,
        "name": existing.name,
        "auto_stop_mins": existing.auto_stop_mins,
        "min_num_clusters": existing.min_num_clusters,
        "max_num_clusters": existing.max_num_clusters,
        "enable_photon": existing.enable_photon,
        "enable_serverless_compute": existing.enable_serverless_compute,
        "spot_instance_policy": existing.spot_instance_policy,
        "channel": existing.channel,
        "tags": existing.tags,
        "instance_profile_arn": existing.instance_profile_arn,
    }
    if existing.warehouse_type is not None:
        kw["warehouse_type"] = EditWarehouseRequestWarehouseType(existing.warehouse_type.value)
    kw = {k: v for k, v in kw.items() if v is not None}
    try:
        with status(f"Resizing warehouse to {cluster_size}…"):
            wait = w.warehouses.edit(id=existing.id, **kw)
            # Only wait for RUNNING when it was already active (edit restarts it); a stopped warehouse
            # stays stopped after an edit, and the caller starts it.
            if was_active:
                wait.result()
    except Exception as e:  # noqa: BLE001 - resize is best-effort; fall back to the current size
        detail = " ".join(str(e).split())[:200] or type(e).__name__
        banner(
            "warn",
            f"Couldn't resize the warehouse to {cluster_size} — {detail}. Using its current size "
            f"({existing.cluster_size}).",
        )
    return w.warehouses.get(existing.id)


def resolve_warehouse(conn: Connection) -> str:
    """Return an http_path to a usable SQL warehouse, creating/starting one if needed.

    Precedence: an explicit http_path on the connection wins; otherwise reuse a warehouse whose
    name matches `conn.warehouse_name`; otherwise create a serverless warehouse with that name."""
    if conn.warehouse_http_path:
        return conn.warehouse_http_path

    w = auth.workspace_client(conn)
    existing = None
    for wh in w.warehouses.list():
        if wh.name == conn.warehouse_name:
            existing = wh
            break

    if existing is not None:
        # Reusing a same-named warehouse — but honour --warehouse-size: if it differs, resize before
        # use rather than silently running at the old size.
        if existing.cluster_size and existing.cluster_size != conn.warehouse_size:
            existing = _resize_warehouse(w, existing, conn.warehouse_size)
        banner("info", f"Reusing SQL warehouse '{existing.name}' ({existing.id}, {existing.cluster_size}).")
        if existing.state not in (State.RUNNING, State.STARTING):
            with status(f"Starting warehouse '{existing.name}'…"):
                w.warehouses.start(existing.id).result()
        return _http_path_for(existing.id)

    banner(
        "info",
        f"No warehouse named '{conn.warehouse_name}' — creating a serverless one ({conn.warehouse_size}).",
    )
    with status(f"Creating + starting serverless SQL warehouse ({conn.warehouse_size})…"):
        created = w.warehouses.create(
            name=conn.warehouse_name,
            cluster_size=conn.warehouse_size,
            max_num_clusters=1,
            auto_stop_mins=10,
            enable_serverless_compute=True,
            warehouse_type=CreateWarehouseRequestWarehouseType.PRO,
        ).result()
    banner("success", f"Created warehouse '{conn.warehouse_name}' ({created.id}).")
    return _http_path_for(created.id)


@contextlib.contextmanager
def connection(conn: Connection, http_path: str) -> Iterator[dbsql.client.Connection]:
    """Open a databricks-sql-connector connection authenticated via unified auth."""
    cfg = auth.workspace_client(conn).config
    hostname = cfg.host.replace("https://", "").replace("http://", "").rstrip("/")
    c = dbsql.connect(
        server_hostname=hostname,
        http_path=http_path,
        # cfg.authenticate is a header factory; the connector calls it per-request.
        credentials_provider=lambda: cfg.authenticate,
    )
    try:
        yield c
    finally:
        c.close()


def query(c: dbsql.client.Connection, sql_text: str) -> pd.DataFrame:
    """Run a query and return a pandas DataFrame (Arrow-backed; array columns become lists)."""
    with c.cursor() as cur:
        cur.execute(sql_text)
        return cur.fetchall_arrow().to_pandas()


def execute(c: dbsql.client.Connection, sql_text: str) -> None:
    """Run a statement for its side effect (DDL / INSERT / DELETE) and discard any result."""
    with c.cursor() as cur:
        cur.execute(sql_text)


def warehouse_is_serverless(wh) -> bool:
    """Best-effort check used only for display."""
    return getattr(wh, "warehouse_type", None) in (
        EndpointInfoWarehouseType.PRO,
        CreateWarehouseRequestWarehouseType.PRO,
    ) and bool(getattr(wh, "enable_serverless_compute", False))
