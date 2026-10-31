//! Black-box tests of the command boundary: no SQL execution and no partial public output.
use serde_json::{json, Value};
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use tempfile::TempDir;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_postgres-audit-guard"))
}
fn log(sql: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "timestamp":"2026-10-31 19:00:00.123 UTC",
        "message":format!("statement: {sql}"),
        "user":"private-synthetic-user", "dbname":"private-synthetic-db",
        "application_name":"private-synthetic-app",
        "error_severity":"LOG", "state_code":"00000",
        "session_id":"1234.5678", "line_num":1
    }))
    .unwrap()
}
fn scan(input: &Path, bundle: &Path) -> Output {
    binary()
        .arg("scan")
        .arg("--input")
        .arg(input)
        .arg("--bundle")
        .arg(bundle)
        .output()
        .unwrap()
}
fn verify(bundle: &Path, anchor: &str) -> Output {
    binary()
        .arg("verify")
        .arg("--bundle")
        .arg(bundle)
        .arg("--anchor")
        .arg(anchor)
        .output()
        .unwrap()
}
fn export(input: &Path, output: &Path) -> Output {
    binary()
        .arg("export-ecs")
        .arg("--input")
        .arg(input)
        .arg("--output")
        .arg(output)
        .output()
        .unwrap()
}
fn anchor(output: &Output) -> String {
    let parsed: Value = serde_json::from_slice(&output.stdout).unwrap();
    parsed["anchor"]["manifest_sha256"]
        .as_str()
        .unwrap()
        .to_string()
}

#[test]
fn scan_verify_and_raw_preservation_work_through_process_boundary() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let bundle = dir.path().join("evidence");
    let bytes = [
        log("COPY public.bank_accounts TO STDOUT"),
        b"\r\n".to_vec(),
        log("SELECT 1"),
    ]
    .concat();
    fs::write(&input, &bytes).unwrap();
    let result = scan(&input, &bundle);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(bundle.join("raw.bin")).unwrap(), bytes);
    let parsed: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(parsed["records"], 2);
    assert!(verify(&bundle, &anchor(&result)).status.success());
    assert!(!verify(&bundle, &"0".repeat(64)).status.success());
    fs::write(bundle.join("raw.bin"), b"replaced evidence").unwrap();
    assert!(!verify(&bundle, &anchor(&result)).status.success());
}

#[test]
fn malformed_tail_never_finalizes_partial_evidence() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let bundle = dir.path().join("evidence");
    fs::write(
        &input,
        [log("COPY public.bank_accounts TO STDOUT"), b"\n{".to_vec()].concat(),
    )
    .unwrap();
    let result = scan(&input, &bundle);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(!bundle.join("manifest.json").exists());
    assert!(bundle.join(".incomplete").exists());
    assert!(!verify(&bundle, &"0".repeat(64)).status.success());
}

#[test]
fn evidence_directory_is_never_overwritten() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let bundle = dir.path().join("evidence");
    fs::write(&input, log("SELECT 1")).unwrap();
    fs::create_dir(&bundle).unwrap();
    fs::write(bundle.join("sentinel"), b"preserve me").unwrap();
    assert!(!scan(&input, &bundle).status.success());
    assert_eq!(fs::read(bundle.join("sentinel")).unwrap(), b"preserve me");
    assert_eq!(fs::read_dir(&bundle).unwrap().count(), 1);
}

#[test]
fn ecs_omits_sql_and_identity_and_preserves_unknown_outcome() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let output = dir.path().join("alerts.jsonl");
    fs::write(
        &input,
        log("COPY public.bank_accounts TO STDOUT; -- private-literal-token"),
    )
    .unwrap();
    let result = export(&input, &output);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let alerts = fs::read_to_string(&output).unwrap();
    assert!(!alerts.is_empty());
    for secret in [
        "private-synthetic-user",
        "private-synthetic-db",
        "private-synthetic-app",
        "private-literal-token",
        "COPY public.bank_accounts",
    ] {
        assert!(!alerts.contains(secret));
    }
    for line in alerts.lines() {
        let event: Value = serde_json::from_str(line).unwrap();
        assert_eq!(event["event"]["outcome"], "unknown");
        assert_eq!(event["postgres_audit_guard"]["raw_sql_included"], false);
        assert_eq!(event["@timestamp"], "2026-10-31T19:00:00.123+00:00");
    }
}

#[test]
fn failed_ecs_export_leaves_no_partial_output_or_temporary_files() {
    for tail in [b"\n{".to_vec(), b"\n\xff".to_vec()] {
        let dir = TempDir::new().unwrap();
        let input = dir.path().join("capture.jsonl");
        let output = dir.path().join("alerts.jsonl");
        fs::write(
            &input,
            [log("COPY public.bank_accounts TO STDOUT"), tail].concat(),
        )
        .unwrap();
        let result = export(&input, &output);
        assert!(!result.status.success());
        assert!(result.stdout.is_empty());
        assert!(!output.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

#[test]
fn ecs_output_is_not_replaced() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let output = dir.path().join("alerts.jsonl");
    fs::write(&input, log("COPY public.bank_accounts TO STDOUT")).unwrap();
    fs::write(&output, b"preserve existing report").unwrap();
    assert!(!export(&input, &output).status.success());
    assert_eq!(fs::read(&output).unwrap(), b"preserve existing report");
}

#[test]
fn unsupported_alert_timestamp_fails_without_publishing_partial_ecs() {
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let output = dir.path().join("alerts.jsonl");
    let mut bad: Value =
        serde_json::from_slice(&log("COPY public.bank_accounts TO STDOUT")).unwrap();
    bad["timestamp"] = "2026-10-31 19:00:00 CST".into();
    fs::write(
        &input,
        [
            log("COPY public.bank_accounts TO STDOUT"),
            b"\n".to_vec(),
            serde_json::to_vec(&bad).unwrap(),
        ]
        .concat(),
    )
    .unwrap();
    assert!(!export(&input, &output).status.success());
    assert!(!output.exists());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_output_is_not_followed_or_replaced() {
    use std::os::unix::fs::symlink;
    let dir = TempDir::new().unwrap();
    let input = dir.path().join("capture.jsonl");
    let output = dir.path().join("alerts.jsonl");
    let target = dir.path().join("must-not-create");
    fs::write(&input, log("COPY public.bank_accounts TO STDOUT")).unwrap();
    symlink(&target, &output).unwrap();
    assert!(!export(&input, &output).status.success());
    assert!(!target.exists());
    assert!(fs::symlink_metadata(&output)
        .unwrap()
        .file_type()
        .is_symlink());
}
