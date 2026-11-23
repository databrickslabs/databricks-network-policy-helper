"""Runs the audit queries over a cached rollup of synthetic audit events in a real (local) Spark session.

Checks that each rollup query (what the collector runs on notebook compute, via
spark.sql(query, cbi_rollup=<cached DataFrame>)) returns exactly the rows of its direct query over the raw
events. Skipped when pyspark or Java isn't installed.
"""

import datetime as dt
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".claude/skills/cbi-posture/scripts"))
pyspark = pytest.importorskip("pyspark")
if not shutil.which("java"):
    pytest.skip("java not installed", allow_module_level=True)

import cbi_sql  # noqa: E402

SCHEMA = (
    "event_date DATE, event_time TIMESTAMP, workspace_id STRING, service_name STRING, action_name STRING, "
    "user_identity STRUCT<email: STRING, subject_name: STRING>, source_ip_address STRING, user_agent STRING, "
    "response STRUCT<status_code: INT>, request_params MAP<STRING, STRING>"
)


@pytest.fixture(scope="module")
def spark():
    from pyspark.sql import SparkSession

    s = (
        SparkSession.builder.master("local[1]")
        .appName("cbi-cache-test")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "1")
        .getOrCreate()
    )
    yield s
    s.stop()


def _rows():
    today = dt.date.today()
    now = dt.datetime.now()
    r = []
    for d in range(0, 20, 3):
        day = today - dt.timedelta(days=d)
        r += [
            (
                day,
                now,
                "1234567890123456",
                "notebook",
                "runCommand",
                ("alex@example.com", None),
                "44.192.10.7",
                "Mozilla/5.0 Chrome",
                (200,),
                None,
            ),
            (
                day,
                now,
                "1234567890123456",
                "sql",
                "executeStatement",
                (None, "6f1c2a9e-0000-4000-8000-000000000001"),
                "35.160.4.9",
                "PowerBI/2.1",
                (200,),
                None,
            ),
            (
                day,
                now,
                "1234567890123456",
                "accounts",
                "IpAccessDenied",
                ("bob@example.com", None),
                "18.204.20.11",
                "curl/8",
                (403,),
                None,
            ),
            (
                day,
                now,
                "0",
                "accounts",
                "login",
                ("admin@example.com", None),
                "44.192.10.8",
                "Mozilla/5.0",
                (200,),
                None,
            ),
            (
                day,
                now,
                "1234567890123456",
                "workspace",
                "workspaceConfEdit",
                ("admin@example.com", None),
                "10.0.0.5",
                "Mozilla/5.0",
                (200,),
                {"workspaceConfKeys": "enableVerboseAuditLogs", "workspaceConfValues": "false"},
            ),
        ]
    # no source IP, IPv6, private, a brand-new public IP today, a second user agent, verbose-off long ago
    r += [
        (
            today,
            now,
            "1234567890123456",
            "jobs",
            "runNow",
            ("alex@example.com", None),
            None,
            "Mozilla/5.0",
            (200,),
            None,
        ),
        (
            today,
            now,
            "1234567890123456",
            "jobs",
            "runNow",
            ("alex@example.com", None),
            " ",
            "Mozilla/5.0",
            (200,),
            None,
        ),
        (
            today,
            now,
            "1234567890123456",
            "sql",
            "executeStatement",
            ("alex@example.com", None),
            "2600:1f18::5",
            "databricks-cli/0.2",
            (200,),
            None,
        ),
        (
            today,
            now,
            "1234567890123456",
            "notebook",
            "runCommand",
            ("alex@example.com", None),
            "52.10.20.30",
            "Mozilla/5.0 Chrome",
            (200,),
            None,
        ),
        (
            today,
            now,
            "1234567890123456",
            "notebook",
            "runCommand",
            ("alex@example.com", None),
            "52.10.20.30",
            "Mozilla/5.0 Chrome",
            (500,),
            None,
        ),
        (
            today - dt.timedelta(days=4),
            now,
            "1234567890123456",
            "unityCatalog",
            "getTable",
            ("bob@example.com", None),
            "44.192.10.7",
            "Tableau/2024",
            (200,),
            None,
        ),
        (
            today - dt.timedelta(days=9),
            now - dt.timedelta(days=9),
            "1234567890123456",
            "workspace",
            "workspaceConfEdit",
            ("admin@example.com", None),
            "44.192.10.7",
            "Mozilla/5.0",
            (200,),
            {"workspaceConfKeys": "enableVerboseAuditLogs", "workspaceConfValues": "FALSE"},
        ),
        (
            today - dt.timedelta(days=2),
            now,
            "0",
            "accounts",
            "tokenLogin",
            (None, "6f1c2a9e-0000-4000-8000-000000000001"),
            "35.160.4.9",
            "databricks-sdk-py/0.30",
            (200,),
            None,
        ),
        (
            today,
            now,
            "7777777777777777",
            "notebook",
            "runCommand",
            ("carol@example.com", None),
            "44.192.10.7",
            "Mozilla/5.0",
            (200,),
            None,
        ),
    ]
    return r


def _canon(rows):
    return sorted(repr(sorted(r.asDict(recursive=True).items())) for r in rows)


def _direct(q, scope):
    return (
        cbi_sql.scope(q, scope)
        .replace(cbi_sql.AUDIT_SOURCE, "FROM audit_src")
        .replace(":lookback_days", "30")
    )


@pytest.fixture(scope="module")
def rollup(spark):
    spark.createDataFrame(_rows(), SCHEMA).createOrReplaceTempView("audit_src")
    out = {}
    for scope in (None, ["1234567890123456"]):
        sel = cbi_sql.rollup_select(30, scope).replace(cbi_sql.AUDIT_SOURCE, "FROM audit_src")
        df = spark.sql(sel).cache()
        assert df.count() > 0 and (df.storageLevel.useMemory or df.storageLevel.useDisk)
        out[None if scope is None else "one"] = (scope, df)
    yield out
    for _s, df in out.values():
        df.unpersist()


@pytest.mark.parametrize("which", [None, "one"])
def test_rollup_queries_return_the_direct_query_rows(spark, rollup, which):
    scope, df = rollup[which]
    ref = "{" + cbi_sql.DF_SOURCE + "}"
    for name in cbi_sql.ROLLUP_QUERIES:
        direct = spark.sql(_direct(cbi_sql.QUERIES[name][1], scope)).collect()
        over = spark.sql(cbi_sql.over_rollup(name, ref), **{cbi_sql.DF_SOURCE: df}).collect()
        assert _canon(over) == _canon(direct), name
        if name in (
            "traffic_by_ip_class",
            "top_public_source_ips",
            "audit_visibility",
            "source_ips_by_workspace",
            "new_source_identity_combinations",
            "ip_access_list_denials",
            "account_level_public_access",
        ):
            assert direct, name  # the synthetic data exercises this query
    vis = spark.sql(cbi_sql.over_rollup("audit_visibility", ref), **{cbi_sql.DF_SOURCE: df}).collect()
    assert any(r["verbose_audit_disabled_events"] > 0 and r["last_verbose_audit_disabled"] for r in vis)


def test_repeated_events_collapse_into_one_rollup_row(spark, rollup):
    # real traffic is the same principal / IP / client over and over: 20 copies of each event, one rollup row
    _scope, df = rollup[None]
    spark.createDataFrame(_rows() * 20, SCHEMA).createOrReplaceTempView("audit_src_x20")
    sel = cbi_sql.rollup_select(30).replace(cbi_sql.AUDIT_SOURCE, "FROM audit_src_x20")
    big = spark.sql(sel)
    assert big.count() == df.count()
    assert big.agg({"events": "sum"}).collect()[0][0] == 20 * len(_rows())
    assert "user_agent" not in df.columns and "request_params" not in df.columns


def test_rollup_queries_run_concurrently(spark, rollup):
    # run_sql submits the audit queries to a thread pool; the shared session and cached rollup must cope
    from concurrent.futures import ThreadPoolExecutor

    _scope, df = rollup[None]
    ref = "{" + cbi_sql.DF_SOURCE + "}"
    qs = {n: cbi_sql.over_rollup(n, ref) for n in cbi_sql.ROLLUP_QUERIES}
    serial = {n: _canon(spark.sql(q, cbi_rollup=df).collect()) for n, q in qs.items()}
    with ThreadPoolExecutor(4) as pool:
        par = dict(
            zip(
                qs,
                pool.map(lambda q: _canon(spark.sql(q, cbi_rollup=df).collect()), qs.values()),
                strict=True,
            )
        )
    assert par == serial


def test_staged_rollup_queries_read_the_table():
    q = cbi_sql.over_rollup("audit_visibility", "main.cbi.cbi_stage_audit_x")
    assert "FROM main.cbi.cbi_stage_audit_x" in q and "system.access.audit" not in q
    st = cbi_sql.stage_statement("main.cbi.t", 30, ["1234567890123456"])
    assert st.startswith("CREATE OR REPLACE TABLE main.cbi.t") and "'1234567890123456', '0'" in st
