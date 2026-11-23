import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / ".claude/skills/cbi-posture/scripts"))
import cbi_genie_setup as gs  # noqa: E402

GENIE = Path(__file__).resolve().parents[2] / ".claude/skills/cbi-posture/genie"


def test_payload_matches_the_genie_format():
    sp = gs.build_space("main.cbi", GENIE)
    assert sp["version"] == 2
    tables = [t["identifier"] for t in sp["data_sources"]["tables"]]
    assert tables == sorted(tables) and all(t.startswith("main.cbi.") for t in tables) and len(tables) == 5
    ids = (
        [q["id"] for q in sp["config"]["sample_questions"]]
        + [t["id"] for t in sp["instructions"]["text_instructions"]]
        + [e["id"] for e in sp["instructions"]["example_question_sqls"]]
    )
    assert all(re.fullmatch(r"[0-9a-f]{32}", i) for i in ids) and len(set(ids)) == len(ids)
    for coll in (sp["config"]["sample_questions"], sp["instructions"]["example_question_sqls"]):
        assert [x["id"] for x in coll] == sorted(x["id"] for x in coll)
    assert len(sp["instructions"]["text_instructions"]) == 1
    ex = sp["instructions"]["example_question_sqls"]
    assert len(ex) == len(gs.parse_trusted_queries((GENIE / "trusted_queries.sql").read_text())) >= 10
    assert all(e["question"][0] and "SELECT" in "".join(e["sql"]).upper() for e in ex)
    assert any(e.get("parameters") for e in ex)
    assert len(sp["config"]["sample_questions"]) >= 10


def test_inline_params_removes_placeholders():
    sp = gs.build_space("main.cbi", GENIE, inline_params=True)
    body = json.dumps(sp)
    assert ":lookback_days" not in body and '"parameters"' not in body


def test_views_are_create_or_replace_only_and_schema_substituted():
    stmts = gs.view_statements("main.cbi", GENIE)
    assert len(stmts) == 4 and all(s.upper().startswith("CREATE OR REPLACE VIEW MAIN.CBI.") for s in stmts)
    assert not any("<catalog>" in s for s in stmts)


def test_print_only_changes_nothing(tmp_path):
    out = tmp_path / "agent.json"
    assert gs.main(["--schema", "main.cbi", "--print-only", str(out)]) == 0
    assert json.loads(out.read_text())["version"] == 2


def test_rejects_bad_schema():
    import pytest

    with pytest.raises(SystemExit):
        gs.main(["--schema", "main.cbi; DROP TABLE x", "--print-only", "/dev/null"])
