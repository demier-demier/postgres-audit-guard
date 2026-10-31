"""Evaluate the authored scenario labels without treating them as real crime labels."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument(
        "--expected", type=Path, default=Path("examples/financial-crime/expected.json")
    )
    args = parser.parse_args()
    report = json.loads(args.report.read_text())
    expected = json.loads(args.expected.read_text())
    if report["input_records"] != expected["records"]:
        raise ValueError("Unexpected record count")
    alerts = report["alerts"]
    if len(alerts) != expected["expected_summary"]["findings"]:
        raise ValueError("Unexpected alert count")
    results = []
    used = set()
    for scenario in expected["scenarios"]:
        ids = set(scenario["transaction_ids"])
        found = []
        for index, alert in enumerate(alerts):
            evidence_ids = set(alert["source_record_ids"])
            if evidence_ids & ids:
                if not evidence_ids <= ids:
                    raise ValueError("Alert mixes independent fixture scenarios")
                found.append(alert)
                used.add(index)
        if sorted(x["rule_id"] for x in found) != sorted(scenario["expected_rule_ids"]):
            raise ValueError(f"Unexpected policy match in {scenario['id']}")
        if found and any(
            set(x["source_record_ids"])
            != set(scenario["expected_pattern_transaction_ids"])
            for x in found
        ):
            raise ValueError(f"Unexpected evidence set in {scenario['id']}")
        results.append(
            {
                "scenario": scenario["id"],
                "authored_label": scenario["status"],
                "alerts": len(found),
                "intentional_benign_alert": scenario["status"] == "benign"
                and bool(found),
            }
        )
    if len(used) != len(alerts):
        raise ValueError("Unattributed alert")
    print(
        json.dumps(
            {
                "scenario_checks_passed": len(results),
                "alerts": len(alerts),
                "benign_scenarios_with_alert": sum(
                    x["intentional_benign_alert"] for x in results
                ),
                "scope": "Authored synthetic scenario checks, not general precision/recall or proof of crime.",
                "results": results,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
