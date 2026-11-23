"""Write a `posture` run to disk: report.md, findings.csv, maturity.csv, tokens-to-revoke.csv and
posture.json (the raw snapshot, so a report can be re-rendered or re-scored offline)."""

from __future__ import annotations

import csv
import datetime as dt
import json
from pathlib import Path

from . import tokens
from .posture import SEVERITY_ORDER, Finding, findings_as_dicts, summarise_policy

# Above this many workspaces the report rolls findings up by check (the CSVs keep every row).
ROLLUP_MIN_WORKSPACES = 10
ROLLUP_LIST = 15
_FINDING_COLS = ["id", "severity", "title", "detail", "recommendation", "workspace_id", "next_step", "docs"]
_TOKEN_COLS = [
    "workspace_id",
    "token_id",
    "owner",
    "created",
    "expires",
    "last_used",
    "scopes",
    "reasons",
    "revoke_command",
    "decision (revoke / keep)",
]
_MATURITY_COLS = ["workspace_id", "workspace_name", "effective_policy_id", "mode", "level", "label", "why"]


def maturity_rows(posture: dict, maturity: dict) -> list[dict]:
    rows = []
    for ws in posture.get("workspaces") or []:
        wid = str(ws["workspace_id"])
        m = maturity.get(wid, {})
        rows.append(
            {
                "effective_policy_id": ws.get("effective_policy_id") or "",
                "label": m.get("label", ""),
                "level": "" if m.get("level") is None else m["level"],
                "mode": (
                    "unknown"
                    if ws.get("policy_error")
                    else summarise_policy(ws.get("policy"))["mode"] or "open"
                ),
                "why": m.get("why", ""),
                "workspace_id": wid,
                "workspace_name": ws.get("workspace_name") or "",
            }
        )
    return rows


def _finding_md(f: Finding, where: str) -> list[str]:
    out = [
        f"### [{f.severity.upper()}] {f.id}: {f.title}  ·  {where}",
        "",
        f.detail,
        "",
        f"**Recommendation:** {f.recommendation}",
    ]
    if f.next_step:
        out += ["", "```bash", f.next_step, "```"]
    if f.docs:
        out += ["", f"Docs: {f.docs}"]
    return out + [""]


def render_markdown(posture: dict, findings: list[Finding], maturity: dict) -> str:
    L = [
        "# Security posture report: ingress (CBI) and personal access tokens",
        "",
        f"_Generated {posture['generated_at']} by `dbx-nwp-helper posture`. Lookback "
        f"{posture['lookback_days']} days. Read-only assessment: no policy, assignment or setting was "
        "changed._",
        "",
        "_Commands for a workspace other than the one the run used say `<profile-for-workspace-<id>>`: "
        "substitute that workspace's own profile._",
        "",
    ]
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = " · ".join(f"**{k}**: {counts[k]}" for k in sorted(counts, key=lambda k: SEVERITY_ORDER[k]))
    L += ["## Summary", "", summary or "No findings.", ""]
    wss = posture.get("workspaces") or []
    names = {str(ws["workspace_id"]): ws.get("workspace_name") or "" for ws in wss}
    rows = maturity_rows(posture, maturity)
    head = ["| Workspace | Name | Policy | Mode | Level | Why |", "|---|---|---|---|---|---|"]

    def line(r: dict) -> str:
        lvl = "?" if r["level"] == "" else f"L{r['level']}"
        return (
            f"| {r['workspace_id']} | {r['workspace_name']} | {r['effective_policy_id'] or '—'} | "
            f"{r['mode']} | {lvl} {r['label']} | {r['why']} |"
        )

    rollup = len(wss) > ROLLUP_MIN_WORKSPACES
    if rollup:
        dist: dict[str, int] = {}
        for r in rows:
            key = ("?" if r["level"] == "" else f"L{r['level']}") + " " + r["label"]
            dist[key] = dist.get(key, 0) + 1
        notable = [r for r in rows if r["mode"] != "open" or (r["level"] or 0) >= 1]
        L += [
            "## Maturity across the account",
            "",
            f"{len(wss)} workspaces. Per-workspace detail: `maturity.csv` and `findings.csv`.",
            "",
            "| Level | Workspaces |",
            "|---|---|",
        ]
        L += [f"| {k} | {v} |" for k, v in sorted(dist.items(), key=lambda kv: -kv[1])]
        L += ["", f"### Workspaces with a CBI policy or a perimeter ({len(notable)})", ""]
        L += (head + [line(r) for r in notable]) if notable else ["None."]
    else:
        L += ["## Maturity by workspace", ""] + head + [line(r) for r in rows]
    L += [
        "",
        "Levels: **L0 Open** → **L1 Legacy perimeter** (IP access lists) → **L2 Observing** (CBI dry-run) "
        "→ **L3 Enforced** (CBI enforced, or private-only) → **L4 Hardened** (L3 with no high/medium "
        "findings).",
        "",
        "## Findings",
        "",
    ]
    if rollup:
        L += ["Grouped by check; one example per group. Every finding is in `findings.csv`.", ""]
        groups: dict[tuple, list[Finding]] = {}
        for f in findings:
            groups.setdefault((f.severity, f.id, f.title), []).append(f)
        for (_sev, _fid, _title), fl in sorted(
            groups.items(), key=lambda kv: (SEVERITY_ORDER[kv[0][0]], -len(kv[1]), kv[0][1])
        ):
            ids = [f.workspace_id for f in fl]
            shown = ", ".join(
                f"`{i}`" + (f" ({names[i]})" if names.get(i) else "") for i in ids[:ROLLUP_LIST]
            )
            more = f", and {len(ids) - ROLLUP_LIST} more" if len(ids) > ROLLUP_LIST else ""
            L += _finding_md(fl[0], f"{len(fl)} workspace(s)")[:-1] + ["", f"**Where:** {shown}{more}", ""]
    else:
        for f in findings:
            L += _finding_md(f, f"workspace `{f.workspace_id}`")
    gaps = _collection_gaps(posture)
    if gaps:
        L += ["## Collection gaps", ""] + [f"- {g}" for g in gaps] + [""]
    L += [
        "## Next steps",
        "",
        "Every command above is propose-only (writes nothing). Add `--create-policy` (dry-run by default) "
        "only after reviewing the preview, and `--policy-mode enforce` only once dry-run denials are clean. "
        "`ingress --review-pack <dir>` turns a proposal into a test plan and review sheet for the owners. "
        "`tokens-to-revoke.csv` lists the tokens worth revoking, with the command an owner would run; "
        "nothing was revoked.",
        "",
    ]
    return "\n".join(L)


def token_rows(posture: dict) -> list[dict]:
    """Tokens worth an owner's review, across the workspaces whose tokens were read."""
    today = dt.date.fromisoformat(str(posture.get("generated_at") or dt.date.today().isoformat())[:10])
    rows = []
    for ws in posture.get("workspaces") or []:
        for r in tokens.revocation_rows(ws.get("pat"), today, ws.get("profile"), tokens.TokenThresholds()):
            rows.append({"workspace_id": str(ws["workspace_id"]), **r})
    return rows


def _collection_gaps(posture: dict) -> list[str]:
    gaps = [
        f"`{k}`: {v['error']}"
        for k, v in sorted((posture.get("sql") or {}).items())
        if isinstance(v, dict) and "error" in v
    ]
    acct = posture.get("account") or {}
    for k in ("error", "workspaces_error"):
        if acct.get(k):
            gaps.append(f"account API: {acct[k]}")
    for ws in posture.get("workspaces") or []:
        for k in ("config_error", "permissions_error", "tokens_error"):
            if (ws.get("pat") or {}).get(k):
                gaps.append(f"tokens {ws['workspace_id']}: {ws['pat'][k]}")
    gaps += [
        f"policy {ws['workspace_id']}: {ws['policy_error']}"
        for ws in posture.get("workspaces") or []
        if ws.get("policy_error")
    ]
    return gaps + list(posture.get("collection_notes") or [])


def write(out_dir: str, posture: dict, findings: list[Finding], maturity: dict) -> Path:
    """Write the four files into `out_dir` (created if needed) and return the report path."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "posture.json").write_text(json.dumps(posture, indent=2, sort_keys=True, default=str) + "\n")
    with (out / "findings.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_FINDING_COLS)
        w.writeheader()
        w.writerows(findings_as_dicts(findings))
    with (out / "maturity.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_MATURITY_COLS)
        w.writeheader()
        w.writerows(maturity_rows(posture, maturity))
    with (out / "tokens-to-revoke.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=_TOKEN_COLS)
        w.writeheader()
        w.writerows(token_rows(posture))
    report = out / "report.md"
    report.write_text(render_markdown(posture, findings, maturity))
    return report
