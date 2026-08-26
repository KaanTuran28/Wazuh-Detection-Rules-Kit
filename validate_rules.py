import argparse
import glob
import json
import os
import re
import xml.etree.ElementTree as ET

MIN_CUSTOM_ID = 100000
MAX_CUSTOM_ID = 119999
MIN_LEVEL = 0
MAX_LEVEL = 16


def load_rule_files(rules_dir):
    rules = []
    parse_errors = []
    for path in sorted(glob.glob(os.path.join(rules_dir, "*.xml"))):
        try:
            tree = ET.parse(path)
        except ET.ParseError as exc:
            parse_errors.append({"file": path, "message": f"XML parse error: {exc}"})
            continue

        root = tree.getroot()
        for rule_el in root.findall(".//rule"):
            desc_el = rule_el.find("description")
            group_el = rule_el.find("group")
            has_correlation = (
                rule_el.find("if_sid") is not None
                or rule_el.find("if_matched_sid") is not None
                or rule_el.get("frequency") is not None
            )
            patterns = []
            for match_el in rule_el.findall("match"):
                if match_el.text:
                    patterns.append({"kind": "match", "text": match_el.text})
            for regex_el in rule_el.findall("regex"):
                if regex_el.text:
                    patterns.append({"kind": "regex", "text": regex_el.text})

            rules.append(
                {
                    "id": rule_el.get("id"),
                    "level": rule_el.get("level"),
                    "description": desc_el.text.strip() if desc_el is not None and desc_el.text else "",
                    "group": group_el.text.strip() if group_el is not None and group_el.text else "",
                    "has_correlation": has_correlation,
                    "patterns": patterns,
                    "file": path,
                }
            )
    return rules, parse_errors


def validate(rules, parse_errors):
    findings = []

    for err in parse_errors:
        findings.append({"severity": "ERROR", "message": f"{err['file']}: {err['message']}"})

    seen_ids = {}
    for rule in rules:
        rid_raw = rule["id"]
        location = f"{rule['file']} (id={rid_raw})"

        if rid_raw is None or not rid_raw.isdigit():
            findings.append({"severity": "ERROR", "message": f"{location}: missing or non-numeric id"})
        else:
            rid = int(rid_raw)
            if rid in seen_ids:
                findings.append(
                    {
                        "severity": "ERROR",
                        "message": f"{location}: duplicate rule id, also used in {seen_ids[rid]}",
                    }
                )
            else:
                seen_ids[rid] = rule["file"]
            if not (MIN_CUSTOM_ID <= rid <= MAX_CUSTOM_ID):
                findings.append(
                    {
                        "severity": "ERROR",
                        "message": f"{location}: id {rid} outside custom rule range {MIN_CUSTOM_ID}-{MAX_CUSTOM_ID}",
                    }
                )

        level_raw = rule["level"]
        if level_raw is None or not level_raw.isdigit() or not (MIN_LEVEL <= int(level_raw) <= MAX_LEVEL):
            findings.append({"severity": "ERROR", "message": f"{location}: invalid level '{level_raw}'"})

        if not rule["description"]:
            findings.append({"severity": "ERROR", "message": f"{location}: missing description"})

    if not findings:
        findings.append({"severity": "OK", "message": f"All {len(rules)} rules passed validation."})

    return findings


def simulate(rules, log_path):
    with open(log_path, encoding="utf-8") as fh:
        lines = fh.readlines()

    simulatable = [r for r in rules if not r["has_correlation"] and r["patterns"]]
    matches = []
    for line_no, line in enumerate(lines, start=1):
        line = line.rstrip("\n")
        for rule in simulatable:
            for pattern in rule["patterns"]:
                if pattern["kind"] == "match":
                    hit = pattern["text"] in line
                else:
                    hit = re.search(pattern["text"], line) is not None
                if hit:
                    matches.append(
                        {
                            "line_no": line_no,
                            "line": line,
                            "rule_id": rule["id"],
                            "description": rule["description"],
                        }
                    )
                    break
    return matches


def render_validate_report(findings):
    lines = ["# Wazuh Rule Validation Report", ""]
    errors = [f for f in findings if f["severity"] == "ERROR"]
    lines.append(f"**Result:** {'FAIL' if errors else 'PASS'} ({len(errors)} error(s))")
    lines.append("")
    lines.append("| Severity | Message |")
    lines.append("|---|---|")
    for f in findings:
        lines.append(f"| {f['severity']} | {f['message']} |")
    return "\n".join(lines) + "\n"


def render_simulate_report(matches, log_path):
    lines = [f"# Rule Simulation Report — `{log_path}`", ""]
    lines.append(
        "> Only standalone regex/match rules (no `if_sid`/`if_matched_sid`/`frequency` correlation) "
        "are simulated. Correlated rules require a real Wazuh manager's event-state engine."
    )
    lines.append("")
    if not matches:
        lines.append("No rules matched any line in this log.")
        return "\n".join(lines) + "\n"

    lines.append("| Line | Rule ID | Description | Log Line |")
    lines.append("|---|---|---|---|")
    for m in matches:
        snippet = m["line"] if len(m["line"]) <= 100 else m["line"][:97] + "..."
        lines.append(f"| {m['line_no']} | {m['rule_id']} | {m['description']} | `{snippet}` |")
    return "\n".join(lines) + "\n"


def render_validate_report_json(findings):
    errors = [f for f in findings if f["severity"] == "ERROR"]
    payload = {"result": "FAIL" if errors else "PASS", "error_count": len(errors), "findings": findings}
    return json.dumps(payload, indent=2) + "\n"


def render_simulate_report_json(matches, log_path):
    payload = {"log_path": log_path, "match_count": len(matches), "matches": matches}
    return json.dumps(payload, indent=2) + "\n"


def main():
    parser = argparse.ArgumentParser(description="Validate and simulate Wazuh custom detection rules.")
    parser.add_argument("--mode", choices=["validate", "simulate"], default="validate")
    parser.add_argument("--rules-dir", default="rules")
    parser.add_argument("--log", help="Log file to simulate rules against (required for --mode simulate)")
    parser.add_argument("--output", default="sample_report.md")
    parser.add_argument("--format", choices=["markdown", "json"], default="markdown")
    args = parser.parse_args()

    rules, parse_errors = load_rule_files(args.rules_dir)

    if args.mode == "validate":
        findings = validate(rules, parse_errors)
        errors = [f for f in findings if f["severity"] == "ERROR"]
        report = (
            render_validate_report_json(findings)
            if args.format == "json"
            else render_validate_report(findings)
        )
        print(report)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)
        raise SystemExit(1 if errors else 0)
    else:
        if not args.log:
            parser.error("--log is required for --mode simulate")
        matches = simulate(rules, args.log)
        report = (
            render_simulate_report_json(matches, args.log)
            if args.format == "json"
            else render_simulate_report(matches, args.log)
        )
        print(report)
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(report)


if __name__ == "__main__":
    main()
