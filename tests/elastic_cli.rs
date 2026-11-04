//! Black-box validation of the boundary before external log shipping.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

fn prepare(input: &Path, output: &Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_postgres-audit-guard"))
        .args(["prepare-elastic", "--input"])
        .arg(input)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}

fn first() -> Value {
    serde_json::from_str(
        include_str!("../examples/observed/alerts.ndjson")
            .lines()
            .next()
            .unwrap(),
    )
    .unwrap()
}

fn line(value: &Value) -> Vec<u8> {
    format!("{value}\n").into_bytes()
}

fn rejects_without_publish(bytes: &[u8]) {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.ndjson");
    let output = dir.path().join("prepared.ndjson");
    fs::write(&input, bytes).unwrap();
    let result = prepare(&input, &output);
    assert!(!result.status.success(), "unexpectedly accepted input");
    assert!(result.stdout.is_empty());
    assert!(!output.exists());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    assert!(!String::from_utf8_lossy(&result.stderr).contains("secret-synthetic-token"));
    assert_eq!(fs::read(&input).unwrap(), bytes);
}

#[test]
fn export_prepare_and_replay_work_at_process_boundary() {
    let dir = TempDir::new().unwrap();
    let raw = dir.path().join("raw.jsonl");
    // All current rule metadata flows through the real detector and exporter.
    let commands = [
        "ALTER ROLE synthetic_reader SUPERUSER",
        "GRANT pg_read_all_data TO synthetic_reader",
        "COPY bank_accounts TO PROGRAM 'synthetic-command-never-executed'",
        "SET log_statement='none'",
        "DO $$ BEGIN NULL; END $$",
    ];
    let mut rows = String::new();
    for statement in commands {
        rows.push_str(&format!(
            "{}\n",
            json!({"timestamp":"2026-11-04T12:00:00Z", "message":format!("statement: {statement}"), "error_severity":"ERROR", "state_code":"42501"})
        ));
    }
    fs::write(&raw, rows).unwrap();
    let exported = dir.path().join("export.ndjson");
    let result = Command::new(env!("CARGO_BIN_EXE_postgres-audit-guard"))
        .args(["export-ecs", "--input"])
        .arg(&raw)
        .arg("--output")
        .arg(&exported)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let prepared = dir.path().join("prepared.ndjson");
    let result = prepare(&exported, &prepared);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    let bytes = fs::read(&prepared).unwrap();
    assert_eq!(summary["schema"], "elastic-prepare-result/v1");
    assert_eq!(summary["sealed"], false);
    assert_eq!(summary["duplicate_records"], 0);
    assert_eq!(
        summary["output_sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    let mut rules = std::collections::BTreeSet::new();
    for doc in String::from_utf8(bytes.clone()).unwrap().lines() {
        let doc: Value = serde_json::from_str(doc).unwrap();
        rules.insert(doc["rule"]["id"].as_str().unwrap().to_owned());
        assert_eq!(doc["event"]["outcome"], "failure");
    }
    assert_eq!(rules.len(), 7);
    let replayed = dir.path().join("replayed.ndjson");
    assert!(prepare(&prepared, &replayed).status.success());
    assert_eq!(fs::read(&replayed).unwrap(), bytes);
}

#[test]
fn semantic_duplicates_deduplicate_but_conflicting_id_payloads_fail() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.ndjson");
    let output = dir.path().join("out.ndjson");
    let value = first();
    // Leading spaces, CRLF and key order do not change the validated payload.
    let reverse = format!(
        "{{\"rule\":{},\"postgres_audit_guard\":{},\"event\":{},\"ecs\":{},\"@timestamp\":{}}}",
        value["rule"],
        value["postgres_audit_guard"],
        value["event"],
        value["ecs"],
        value["@timestamp"]
    );
    let bytes = format!("{value}\n  {reverse} \r\n{value}").into_bytes();
    fs::write(&input, &bytes).unwrap();
    let result = prepare(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let summary: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(summary["input_records"], 3);
    assert_eq!(summary["unique_documents"], 1);
    assert_eq!(summary["duplicate_records"], 2);
    assert_eq!(summary["input_sha256"], hex::encode(Sha256::digest(&bytes)));
    assert_eq!(fs::read(output).unwrap(), line(&value));

    let mut conflicting = value.clone();
    conflicting["@timestamp"] = json!("2026-11-04T12:00:00Z");
    rejects_without_publish(&[line(&value), line(&conflicting)].concat());
}

#[test]
fn field_injection_type_confusion_and_policy_mismatches_fail_without_echoing_values() {
    let mutations = [
        ("/event/id", json!("0".repeat(64))),
        ("/event/hash", json!("F".repeat(64))),
        ("/event/action", json!("DB005")),
        ("/event/outcome", json!("success")),
        ("/event/kind", json!("event")),
        (
            "/event/category",
            json!(["database", "secret-synthetic-token"]),
        ),
        ("/event/type", json!("info")),
        ("/event/module", json!("other")),
        ("/event/dataset", json!("other")),
        ("/rule/id", json!("DB999")),
        ("/rule/name", json!("secret-synthetic-token")),
        ("/rule/version", json!("9.0.0")),
        ("/rule/license", json!("other")),
        ("/ecs/version", json!("9.0.0")),
        ("/@timestamp", json!("secret-synthetic-token")),
        ("/postgres_audit_guard/severity", json!("critical")),
        ("/postgres_audit_guard/raw_sql_included", json!(true)),
        ("/postgres_audit_guard/schema", json!("ecs-export/v9")),
        (
            "/postgres_audit_guard/scope",
            json!("secret-synthetic-token"),
        ),
        (
            "/postgres_audit_guard/sqlstate",
            json!("secret-synthetic-token"),
        ),
    ];
    for (path, replacement) in mutations {
        let mut value = first();
        *value.pointer_mut(path).unwrap() = replacement;
        rejects_without_publish(&line(&value));
    }
    // Unknown fields at every object level cannot leak into the shipping spool.
    for object in ["", "/ecs", "/event", "/rule", "/postgres_audit_guard"] {
        let mut value = first();
        value
            .pointer_mut(object)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "secret-synthetic-token".into(),
                json!("secret-synthetic-token"),
            );
        rejects_without_publish(&line(&value));
    }
}

#[test]
fn duplicate_json_fields_are_rejected_at_every_object_level() {
    let valid = first().to_string();
    for (from, to) in [
        (
            "\"@timestamp\":",
            "\"@timestamp\":\"secret-synthetic-token\",\"@timestamp\":",
        ),
        (
            "\"ecs\":{",
            "\"ecs\":{\"version\":\"secret-synthetic-token\",",
        ),
        (
            "\"event\":{",
            "\"event\":{\"id\":\"secret-synthetic-token\",",
        ),
        (
            "\"rule\":{",
            "\"rule\":{\"name\":\"secret-synthetic-token\",",
        ),
        (
            "\"postgres_audit_guard\":{",
            "\"postgres_audit_guard\":{\"scope\":\"secret-synthetic-token\",",
        ),
    ] {
        assert!(valid.contains(from));
        rejects_without_publish(valid.replacen(from, to, 1).as_bytes());
    }
}

#[test]
fn malformed_tail_and_resource_failure_leave_no_output() {
    for tail in [
        b"{\"secret-synthetic-token\":\n".as_slice(),
        b"\n",
        b"[]\n",
        b"\xff\n",
    ] {
        rejects_without_publish(&[line(&first()), tail.to_vec()].concat());
    }
    rejects_without_publish(&vec![
        b' ';
        postgres_audit_guard::elastic::MAX_INPUT_BYTES + 1
    ]);
    rejects_without_publish(&vec![
        b' ';
        postgres_audit_guard::elastic::MAX_RECORD_BYTES + 1
    ]);
}

#[test]
fn existing_output_and_source_are_never_replaced() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.ndjson");
    let output = dir.path().join("out.ndjson");
    fs::write(&input, line(&first())).unwrap();
    fs::write(&output, b"preserve me").unwrap();
    assert!(!prepare(&input, &output).status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve me");
    assert!(!prepare(&input, &input).status.success());
    assert_eq!(fs::read(&input).unwrap(), line(&first()));
}

#[cfg(unix)]
#[test]
fn symlink_input_and_output_are_refused_and_permissions_are_private() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("input.ndjson");
    let linked = dir.path().join("linked.ndjson");
    let output = dir.path().join("out.ndjson");
    fs::write(&input, line(&first())).unwrap();
    symlink(&input, &linked).unwrap();
    assert!(!prepare(&linked, &output).status.success());
    assert!(!output.exists());
    symlink(dir.path().join("does-not-exist"), &output).unwrap();
    assert!(!prepare(&input, &output).status.success());
    assert!(fs::symlink_metadata(&output)
        .unwrap()
        .file_type()
        .is_symlink());
    fs::remove_file(&output).unwrap();
    assert!(prepare(&input, &output).status.success());
    assert_eq!(
        fs::metadata(output).unwrap().permissions().mode() & 0o777,
        0o600
    );
}
