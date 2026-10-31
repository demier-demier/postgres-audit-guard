//! Independent adversarial checks at the public transfer-triage command boundary.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_postgres-audit-guard"))
}

fn triage(input: &Path, output: &Path) -> Output {
    binary()
        .arg("triage-transfers")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

fn verify(input: &Path, report: &Path, anchor: &str) -> Output {
    binary()
        .arg("verify-transfer-report")
        .arg("--input")
        .arg(input)
        .arg("--report")
        .arg(report)
        .arg("--anchor")
        .arg(anchor)
        .output()
        .unwrap()
}

fn transfer(id: &str, minute: u32, from: &str, to: &str, amount: u64, currency: &str) -> Value {
    json!({
        "id": id,
        "timestamp": format!("2026-10-31T10:{minute:02}:00Z"),
        "from_account": from,
        "to_account": to,
        "amount_minor": amount,
        "currency": currency,
    })
}

fn ndjson(rows: &[Value]) -> Vec<u8> {
    rows.iter()
        .flat_map(|row| format!("{row}\n").into_bytes())
        .collect()
}

fn cycle() -> Vec<Value> {
    vec![
        transfer("z-first", 0, "synthetic-A", "synthetic-B", 10000, "USD"),
        transfer("a-second", 5, "synthetic-B", "synthetic-C", 9000, "USD"),
        transfer("m-third", 10, "synthetic-C", "synthetic-A", 8100, "USD"),
    ]
}

fn successful_report(rows: &[Value]) -> (TempDir, Value, Output) {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("transfers.jsonl");
    let output = temp.path().join("report.json");
    fs::write(&input, ndjson(rows)).unwrap();
    let result = triage(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = serde_json::from_slice(&fs::read(&output).unwrap()).unwrap();
    (temp, report, result)
}

fn anchor(output: &Output) -> String {
    let summary: Value = serde_json::from_slice(&output.stdout).unwrap();
    summary["report_sha256"].as_str().unwrap().into()
}

#[test]
fn dirty_input_leaves_no_report_or_temporary_artifacts() {
    let mut valid_then_bad = ndjson(&cycle());
    valid_then_bad.extend_from_slice(b"{\"id\":");
    for input_bytes in [valid_then_bad, vec![0xff], vec![b' '; 16 * 1024 * 1024 + 1]] {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("transfers.jsonl");
        let report = temp.path().join("report.json");
        fs::write(&input, input_bytes).unwrap();
        let result = triage(&input, &report);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!report.exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
}

#[test]
fn malformed_private_values_do_not_leak_in_diagnostics() {
    let secret = "private-secret-value-canary";
    let mut bad_amount = cycle()[0].clone();
    bad_amount["amount_minor"] = secret.into();
    let mut bad_timestamp = cycle()[0].clone();
    bad_timestamp["timestamp"] = secret.into();
    let mut bad_unknown_field = cycle()[0].clone();
    bad_unknown_field[secret] = true.into();
    for row in [bad_amount, bad_timestamp, bad_unknown_field] {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("transfers.jsonl");
        let report = temp.path().join("report.json");
        fs::write(&input, ndjson(&[row])).unwrap();
        let result = triage(&input, &report);
        assert!(!result.status.success());
        assert!(!String::from_utf8_lossy(&result.stderr).contains(secret));
        assert!(result.stdout.is_empty());
        assert!(!report.exists());
    }
}

#[test]
fn verifier_requires_external_anchor_and_detects_changed_report_and_source() {
    let (temp, _report, result) = successful_report(&cycle());
    let input = temp.path().join("transfers.jsonl");
    let path = temp.path().join("report.json");
    let trusted = anchor(&result);
    assert!(verify(&input, &path, &trusted).status.success());
    assert!(!verify(&input, &path, &"0".repeat(64)).status.success());

    let original = fs::read(&path).unwrap();
    let mut modified = original.clone();
    modified.push(b' ');
    fs::write(&path, modified).unwrap();
    assert!(!verify(&input, &path, &trusted).status.success());
    fs::write(&path, original).unwrap();

    let mut changed_source = cycle();
    changed_source[0]["amount_minor"] = 10001.into();
    fs::write(&input, ndjson(&changed_source)).unwrap();
    assert!(!verify(&input, &path, &trusted).status.success());
}

#[test]
fn fresh_anchor_cannot_make_ambiguous_or_noncanonical_reports_pass_replay() {
    let (temp, _report, _result) = successful_report(&cycle());
    let input = temp.path().join("transfers.jsonl");
    let path = temp.path().join("report.json");
    let original = fs::read_to_string(&path).unwrap();
    let duplicate = original.replacen(
        '{',
        "{\"alerts\":[{\"misleading\":\"must-not-be-accepted\"}],",
        1,
    );
    // serde_json::Value would silently keep the later, legitimate `alerts` key.
    assert_eq!(
        serde_json::from_str::<Value>(&duplicate).unwrap(),
        serde_json::from_str::<Value>(&original).unwrap()
    );
    for changed in [duplicate, format!("{original} ")] {
        let fresh_anchor = hex::encode(Sha256::digest(changed.as_bytes()));
        fs::write(&path, changed).unwrap();
        let result = verify(&input, &path, &fresh_anchor);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn ordered_evidence_is_stable_under_input_shuffle_and_is_for_human_review() {
    let rows = cycle();
    let (_temp, report, result) = successful_report(&rows);
    let mut reversed = rows;
    reversed.reverse();
    let (_other, shuffled, _) = successful_report(&reversed);
    assert_eq!(report["alerts"], shuffled["alerts"]);
    let alerts = report["alerts"].as_array().unwrap();
    let cycle_alert = alerts.iter().find(|a| a["rule_id"] == "TF002").unwrap();
    assert_eq!(
        cycle_alert["source_record_ids"],
        json!(["z-first", "a-second", "m-third"])
    );
    let interpretation = cycle_alert["interpretation"]
        .as_str()
        .unwrap()
        .to_lowercase();
    assert!(interpretation.contains("review"));
    assert!(!interpretation.contains("confirmed laundering"));
    let stdout = String::from_utf8_lossy(&result.stdout);
    for account in ["synthetic-A", "synthetic-B", "synthetic-C"] {
        assert!(!stdout.contains(account));
    }
}

#[test]
fn cross_currency_and_simultaneous_paths_do_not_imply_a_cycle() {
    let mut other_currency = cycle();
    other_currency[1]["currency"] = "EUR".into();
    let mut simultaneous = cycle();
    simultaneous[1]["timestamp"] = simultaneous[0]["timestamp"].clone();
    for rows in [other_currency, simultaneous] {
        let (_temp, report, _) = successful_report(&rows);
        assert!(report["alerts"].as_array().unwrap().is_empty());
    }
}

#[test]
fn fan_in_requires_distinct_senders_and_sufficient_same_currency_outflow() {
    let incoming = vec![
        transfer("in-1", 0, "sender-1", "hub", 10000, "USD"),
        transfer("in-2", 5, "sender-2", "hub", 10000, "USD"),
        transfer("in-3", 10, "sender-3", "hub", 10000, "USD"),
        transfer("in-4", 15, "sender-4", "hub", 10000, "USD"),
    ];
    let mut positive = incoming.clone();
    positive.push(transfer("out-1", 20, "hub", "merchant", 35000, "USD"));
    let (_temp, report, _) = successful_report(&positive);
    assert!(report["alerts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|alert| alert["rule_id"] == "TF001"));

    let mut ordinary = incoming.clone();
    ordinary.push(transfer("out-1", 20, "hub", "merchant", 10000, "USD"));
    let mut other_currency = incoming;
    other_currency.push(transfer("out-1", 20, "hub", "merchant", 35000, "EUR"));
    let mut same_sender = positive;
    for row in &mut same_sender[..4] {
        row["from_account"] = "single-sender".into();
    }
    for rows in [ordinary, other_currency, same_sender] {
        let (_temp, report, _) = successful_report(&rows);
        assert!(report["alerts"].as_array().unwrap().is_empty());
    }
}

#[test]
fn self_transfers_and_duplicate_ids_fail_closed() {
    let self_transfer = vec![transfer(
        "self",
        0,
        "same-account",
        "same-account",
        10000,
        "USD",
    )];
    let mut duplicate_ids = cycle();
    duplicate_ids[1]["id"] = duplicate_ids[0]["id"].clone();
    for rows in [self_transfer, duplicate_ids] {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("transfers.jsonl");
        let report = temp.path().join("report.json");
        fs::write(&input, ndjson(&rows)).unwrap();
        let result = triage(&input, &report);
        assert!(!result.status.success());
        assert!(!report.exists());
    }
}

#[test]
fn production_work_budget_stops_dense_paths_without_publishing_a_partial_report() {
    let rows: Vec<_> = (0..2500)
        .flat_map(|i| {
            [
                transfer(&format!("in-{i}"), 0, "source", "hub", 100, "USD"),
                transfer(&format!("out-{i}"), 1, "hub", "destination", 100, "USD"),
            ]
        })
        .collect();
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("transfers.jsonl");
    let report = temp.path().join("report.json");
    fs::write(&input, ndjson(&rows)).unwrap();
    let result = triage(&input, &report);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("work limit exceeded"));
    assert!(result.stdout.is_empty());
    assert!(!report.exists());
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
}

#[test]
fn alert_order_uses_actual_instants_including_fractional_seconds() {
    let mut rows = cycle();
    for (position, mut row) in cycle().into_iter().enumerate() {
        row["id"] = format!("fractional-{position}").into();
        row["from_account"] = format!("other-{}", row["from_account"].as_str().unwrap()).into();
        row["to_account"] = format!("other-{}", row["to_account"].as_str().unwrap()).into();
        row["timestamp"] = row["timestamp"]
            .as_str()
            .unwrap()
            .replace("00Z", "00.100Z")
            .into();
        rows.push(row);
    }
    let (_temp, report, _) = successful_report(&rows);
    let alerts = report["alerts"].as_array().unwrap();
    assert_eq!(alerts.len(), 2);
    let first =
        chrono::DateTime::parse_from_rfc3339(alerts[0]["window_start"].as_str().unwrap()).unwrap();
    let second =
        chrono::DateTime::parse_from_rfc3339(alerts[1]["window_start"].as_str().unwrap()).unwrap();
    assert!(first < second);
}

#[test]
fn existing_report_is_never_overwritten() {
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("transfers.jsonl");
    let report = temp.path().join("report.json");
    fs::write(&input, ndjson(&cycle())).unwrap();
    fs::write(&report, b"existing human-reviewed report").unwrap();
    assert!(!triage(&input, &report).status.success());
    assert_eq!(
        fs::read(&report).unwrap(),
        b"existing human-reviewed report"
    );
}

#[cfg(unix)]
#[test]
fn dangling_symlink_output_is_not_followed_or_replaced() {
    use std::os::unix::fs::symlink;
    let temp = TempDir::new().unwrap();
    let input = temp.path().join("transfers.jsonl");
    let report = temp.path().join("report.json");
    let target = temp.path().join("must-not-create");
    fs::write(&input, ndjson(&cycle())).unwrap();
    symlink(&target, &report).unwrap();
    assert!(!triage(&input, &report).status.success());
    assert!(!target.exists());
    assert!(fs::symlink_metadata(&report)
        .unwrap()
        .file_type()
        .is_symlink());
}
