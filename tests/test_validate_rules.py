import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from validate_rules import (
    load_rule_files,
    render_simulate_report_json,
    render_validate_report_json,
    simulate,
    validate,
)

RULES_DIR = PROJECT_ROOT / "rules"
WEB_LOG = PROJECT_ROOT / "sample_logs" / "web_access_sample.log"
HOST_LOG = PROJECT_ROOT / "sample_logs" / "host_events_sample.log"


def test_all_rule_files_well_formed():
    rules, parse_errors = load_rule_files(str(RULES_DIR))
    assert parse_errors == []
    assert len(rules) > 0


def test_rule_ids_unique_and_in_range():
    rules, parse_errors = load_rule_files(str(RULES_DIR))
    findings = validate(rules, parse_errors)
    errors = [f for f in findings if f["severity"] == "ERROR"]
    assert errors == []


def test_malformed_xml_detected(tmp_path):
    bad_dir = tmp_path / "rules"
    bad_dir.mkdir()
    (bad_dir / "broken.xml").write_text("<group><rule id=\"100099\" level=\"5\"><description>oops</group>")

    rules, parse_errors = load_rule_files(str(bad_dir))
    assert len(parse_errors) == 1

    findings = validate(rules, parse_errors)
    errors = [f for f in findings if f["severity"] == "ERROR"]
    assert any("parse error" in f["message"].lower() for f in errors)


def test_simulate_sqli_detected():
    rules, _ = load_rule_files(str(RULES_DIR))
    matches = simulate(rules, str(WEB_LOG))
    rule_ids = {m["rule_id"] for m in matches}
    assert "100020" in rule_ids

    benign_matches = [m for m in matches if "GET /index.html" in m["line"]]
    assert benign_matches == []


def test_simulate_powershell_detected():
    rules, _ = load_rule_files(str(RULES_DIR))
    matches = simulate(rules, str(HOST_LOG))
    rule_ids = {m["rule_id"] for m in matches}
    assert "100030" in rule_ids
    assert "100031" in rule_ids


def test_simulate_excludes_correlated_rules():
    rules, _ = load_rule_files(str(RULES_DIR))
    matches = simulate(rules, str(WEB_LOG)) + simulate(rules, str(HOST_LOG))
    rule_ids = {m["rule_id"] for m in matches}
    assert rule_ids.isdisjoint({"100010", "100011", "100012"})


def test_validate_report_json_shape():
    rules, parse_errors = load_rule_files(str(RULES_DIR))
    findings = validate(rules, parse_errors)
    payload = json.loads(render_validate_report_json(findings))
    assert payload["result"] == "PASS"
    assert payload["error_count"] == 0
    assert isinstance(payload["findings"], list) and payload["findings"]


def test_simulate_report_json_shape():
    rules, _ = load_rule_files(str(RULES_DIR))
    matches = simulate(rules, str(WEB_LOG))
    payload = json.loads(render_simulate_report_json(matches, str(WEB_LOG)))
    assert payload["log_path"] == str(WEB_LOG)
    assert payload["match_count"] == len(matches)
    assert any(m["rule_id"] == "100020" for m in payload["matches"])
