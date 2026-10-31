"""Check detector evidence against known outcomes of the isolated PostgreSQL lab."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    args = parser.parse_args()
    observed = {}
    for line in (args.bundle / "records.jsonl").read_text().splitlines():
        payload = json.loads(line)["payload"]
        event = payload["event"]
        app = event["application_name"]
        observed.setdefault(app, []).extend(payload["findings"])
    expected = {
        "case-role-attempt": "DB001",
        "case-sensitive-export": "DB004",
        "case-disable-logging": "DB005",
        "case-permission-denied": "DB006",
    }
    for app, rule in expected.items():
        if rule not in [f["rule_id"] for f in observed.get(app, [])]:
            raise ValueError(f"Missing expected rule {rule} for {app}")
    for app in ["control-benign", "control-literal"]:
        if app not in observed or observed[app]:
            raise ValueError(f"Unexpected/missing benign control: {app}")
    for findings in observed.values():
        for f in findings:
            if f["outcome"] not in ["unknown", "failure_observed"]:
                raise ValueError("Unsupported success inference")
    print(
        json.dumps(
            {
                "scenario_checks_passed": 6,
                "inferred_successes": 0,
                "scope": "Four positive scenarios and two benign controls, not a general precision/recall estimate.",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
