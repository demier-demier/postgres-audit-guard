//! Process-boundary acceptance and hostile-input checks for human case review.
//! Only original, checked-in synthetic transfers are used; no external service.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const START: &str = "2026-11-03T12:00:00.900Z";
const NOTE: &str = "Synthetic merchant settlement reviewed with the authored business context; no crime conclusion.";

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn binary(command: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_postgres-audit-guard"));
    cmd.arg(command);
    cmd
}
fn success(result: Output) -> Value {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}
fn rejected(result: Output) {
    assert!(
        !result.status.success(),
        "unexpected success: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(
        result.stdout.is_empty(),
        "failed operation emitted a success result"
    );
}
fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

struct Fixture {
    temp: TempDir,
    input: PathBuf,
    report: PathBuf,
    reason: PathBuf,
    report_anchor: String,
    alert_index: usize,
    source_bytes: Vec<u8>,
    report_bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let input = temp.path().join("transfers.jsonl");
        let report = temp.path().join("report.json");
        let reason = temp.path().join("note.txt");
        let source_bytes = include_bytes!("../examples/financial-crime/transfers.jsonl").to_vec();
        fs::write(&input, &source_bytes).unwrap();
        fs::write(&reason, NOTE).unwrap();
        let result = success(
            binary("triage-transfers")
                .arg("--input")
                .arg(&input)
                .arg("--output")
                .arg(&report)
                .output()
                .unwrap(),
        );
        let report_bytes = fs::read(&report).unwrap();
        let report_value: Value = serde_json::from_slice(&report_bytes).unwrap();
        assert_eq!(report_value["alerts"].as_array().unwrap().len(), 4);
        let alert_index = report_value["alerts"]
            .as_array()
            .unwrap()
            .iter()
            .position(|a| {
                a["source_record_ids"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v == "merchant-01")
            })
            .unwrap();
        Self {
            temp,
            input,
            report,
            reason,
            report_anchor: result["report_sha256"].as_str().unwrap().into(),
            alert_index,
            source_bytes,
            report_bytes,
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.temp.path().join(name)
    }
    fn source_command(&self, verb: &str) -> Command {
        let mut command = binary(verb);
        command
            .arg("--input")
            .arg(&self.input)
            .arg("--report")
            .arg(&self.report)
            .arg("--report-anchor")
            .arg(&self.report_anchor);
        command
    }
    fn open_command(&self, output: &Path) -> Command {
        let mut cmd = self.source_command("open-analyst-case");
        cmd.arg("--case-id")
            .arg("synthetic-merchant-review")
            .arg("--alert-index")
            .arg(self.alert_index.to_string())
            .arg("--actor")
            .arg("analyst-alpha")
            .arg("--at")
            .arg(START)
            .arg("--reason-file")
            .arg(&self.reason)
            .arg("--evidence-ref")
            .arg("merchant-01")
            .arg("--output")
            .arg(output);
        cmd
    }
    fn open(&self) -> (PathBuf, String) {
        let path = self.path("case-v1.json");
        let out = success(self.open_command(&path).output().unwrap());
        let anchor = out["case_sha256"].as_str().unwrap().to_owned();
        assert_eq!(anchor, hash(&fs::read(&path).unwrap()));
        (path, anchor)
    }
    fn verify(&self, case: &Path, anchor: &str) -> Output {
        self.source_command("verify-analyst-case")
            .arg("--case")
            .arg(case)
            .arg("--case-anchor")
            .arg(anchor)
            .output()
            .unwrap()
    }
    fn revision(
        &self,
        case: &Path,
        anchor: &str,
        output: &Path,
        at: &str,
        disposition: &str,
        refs: &[&str],
    ) -> Command {
        let mut cmd = self.source_command("revise-analyst-case");
        cmd.arg("--case")
            .arg(case)
            .arg("--case-anchor")
            .arg(anchor)
            .arg("--disposition")
            .arg(disposition)
            .arg("--actor")
            .arg("analyst-beta")
            .arg("--at")
            .arg(at)
            .arg("--reason-file")
            .arg(&self.reason)
            .arg("--output")
            .arg(output);
        for id in refs {
            cmd.arg("--evidence-ref").arg(id);
        }
        cmd
    }
    fn assert_sources_unchanged(&self) {
        assert_eq!(fs::read(&self.input).unwrap(), self.source_bytes);
        assert_eq!(fs::read(&self.report).unwrap(), self.report_bytes);
    }
}

#[test]
fn merchant_false_positive_can_be_explained_and_reopened_without_erasing_detection() {
    let f = Fixture::new();
    let (v1, a1) = f.open();
    let original = fs::read(&v1).unwrap();
    assert_eq!(success(f.verify(&v1, &a1))["verified"], true);
    let v2 = f.path("case-v2.json");
    let s2 = success(
        f.revision(
            &v1,
            &a1,
            &v2,
            "2026-11-03T09:00:01-03:00",
            "closed-explained",
            &["merchant-01", "merchant-04"],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(s2["revision"], 2);
    assert_eq!(s2["disposition"], "closed_explained");
    let a2 = s2["case_sha256"].as_str().unwrap();
    assert_eq!(success(f.verify(&v2, a2))["verified"], true);
    let v3 = f.path("case-v3.json");
    let s3 = success(
        f.revision(
            &v2,
            a2,
            &v3,
            "2026-11-03T12:00:01.001Z",
            "open",
            &["merchant-02"],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(s3["revision"], 3);
    assert_eq!(s3["disposition"], "open");
    let body = read_json(&v3);
    let revisions = body["revisions"].as_array().unwrap();
    assert_eq!(revisions.len(), 3);
    assert_eq!(revisions[0]["disposition"], "open");
    assert_eq!(revisions[1]["disposition"], "closed_explained");
    assert_eq!(revisions[2]["disposition"], "open");
    assert_eq!(fs::read(&v1).unwrap(), original);
    assert_eq!(read_json(&f.report)["alerts"].as_array().unwrap().len(), 4);
    f.assert_sources_unchanged();
}

#[test]
fn independently_retained_anchors_reject_changed_case_report_and_input() {
    let f = Fixture::new();
    let (case, anchor) = f.open();
    for bad in ["0".repeat(64), "A".repeat(64), "short".to_owned()] {
        rejected(f.verify(&case, &bad));
    }
    rejected(
        binary("verify-analyst-case")
            .arg("--input")
            .arg(&f.input)
            .arg("--report")
            .arg(&f.report)
            .arg("--report-anchor")
            .arg("0".repeat(64))
            .arg("--case")
            .arg(&case)
            .arg("--case-anchor")
            .arg(&anchor)
            .output()
            .unwrap(),
    );
    let mut source = f.source_bytes.clone();
    source.push(b' ');
    fs::write(&f.input, source).unwrap();
    rejected(f.verify(&case, &anchor));
    fs::write(&f.input, &f.source_bytes).unwrap();
    let mut report = f.report_bytes.clone();
    report.push(b' ');
    fs::write(&f.report, report).unwrap();
    rejected(f.verify(&case, &anchor));
    rejected(
        binary("verify-analyst-case")
            .arg("--input")
            .arg(&f.input)
            .arg("--report")
            .arg(&f.report)
            .arg("--report-anchor")
            .arg(hash(&fs::read(&f.report).unwrap()))
            .arg("--case")
            .arg(&case)
            .arg("--case-anchor")
            .arg(&anchor)
            .output()
            .unwrap(),
    );
    fs::write(&f.report, &f.report_bytes).unwrap();
    let bytes = fs::read(&case).unwrap();
    let mutated = String::from_utf8(bytes.clone())
        .unwrap()
        .replace("analyst-alpha", "analyst-gamma");
    assert_ne!(mutated.as_bytes(), &bytes);
    fs::write(&case, mutated).unwrap();
    rejected(f.verify(&case, &anchor));
    f.assert_sources_unchanged();
}

#[test]
fn rehashed_malformed_case_cannot_bypass_schema_or_revision_structure() {
    let f = Fixture::new();
    let (case, _) = f.open();
    let original = fs::read(&case).unwrap();
    let text = String::from_utf8(original.clone()).unwrap();
    let mutations = [
        text.replace("\"version\": 1", "\"version\": 7"),
        text.replace(
            "\"disposition\": \"open\"",
            "\"disposition\": \"closed_explained\"",
        ),
        text.replace(
            "\"actor\": \"analyst-alpha\"",
            "\"actor\": \"analyst-alpha\", \"actor\": \"analyst-beta\"",
        ),
        text.replacen('{', "{\"unrecognized_field\": true,", 1),
        text.replace("merchant-01", "circle-01"),
    ];
    for mutation in mutations {
        assert_ne!(mutation.as_bytes(), original);
        fs::write(&case, &mutation).unwrap();
        rejected(f.verify(&case, &hash(mutation.as_bytes())));
    }
    f.assert_sources_unchanged();
}

#[test]
fn no_clobber_preserves_every_input_and_leaves_no_temporary_success_file() {
    let f = Fixture::new();
    let (case, anchor) = f.open();
    let original = fs::read(&case).unwrap();
    let file_count = fs::read_dir(f.temp.path()).unwrap().count();
    rejected(f.open_command(&case).output().unwrap());
    rejected(
        f.revision(
            &case,
            &anchor,
            &case,
            "2026-11-03T12:00:02Z",
            "needs-information",
            &["merchant-01"],
        )
        .output()
        .unwrap(),
    );
    let sentinel = f.path("existing.json");
    fs::write(&sentinel, b"retain me").unwrap();
    rejected(
        f.revision(
            &case,
            &anchor,
            &sentinel,
            "2026-11-03T12:00:02Z",
            "needs-information",
            &["merchant-01"],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(fs::read(&case).unwrap(), original);
    assert_eq!(fs::read(&sentinel).unwrap(), b"retain me");
    assert_eq!(fs::read_dir(f.temp.path()).unwrap().count(), file_count + 1);
    f.assert_sources_unchanged();
}

#[test]
fn refs_must_belong_to_selected_alert_and_cannot_repeat() {
    let f = Fixture::new();
    let (case, anchor) = f.open();
    let before = fs::read_dir(f.temp.path()).unwrap().count();
    let output = f.path("rejected.json");
    for refs in [
        &["circle-01"][..],
        &["merchant-05"][..],
        &["merchant-01", "merchant-01"][..],
        &["does-not-exist"][..],
    ] {
        rejected(
            f.revision(
                &case,
                &anchor,
                &output,
                "2026-11-03T12:00:02Z",
                "needs-information",
                refs,
            )
            .output()
            .unwrap(),
        );
        assert!(!output.exists());
    }
    assert_eq!(fs::read_dir(f.temp.path()).unwrap().count(), before);
    f.assert_sources_unchanged();
}

#[test]
fn revision_time_uses_instants_and_requires_strict_increase() {
    let f = Fixture::new();
    let (case, anchor) = f.open();
    let output = f.path("revision.json");
    for at in [
        "2026-11-03T09:00:00.9-03:00",
        "2026-11-03T12:00:00.899Z",
        "2026-11-03T13:00:00+01:00",
        "not-a-time",
    ] {
        rejected(
            f.revision(
                &case,
                &anchor,
                &output,
                at,
                "needs-information",
                &["merchant-01"],
            )
            .output()
            .unwrap(),
        );
        assert!(!output.exists());
    }
    let out = success(
        f.revision(
            &case,
            &anchor,
            &output,
            "2026-11-03T09:00:01-03:00",
            "needs-information",
            &["merchant-01"],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(
        success(f.verify(&output, out["case_sha256"].as_str().unwrap()))["verified"],
        true
    );
}

#[test]
fn invalid_private_notes_do_not_leak_or_publish_partial_cases() {
    let f = Fixture::new();
    let output = f.path("rejected.json");
    let before = fs::read_dir(f.temp.path()).unwrap().count();
    let canary = "private-note-canary-92";
    for bytes in [
        vec![0xff],
        vec![],
        format!("{canary}\nsecond paragraph").into_bytes(),
        format!("{canary}{}", "x".repeat(2049)).into_bytes(),
        format!("{canary}\u{1b}[31m").into_bytes(),
    ] {
        fs::write(&f.reason, bytes).unwrap();
        let result = f.open_command(&output).output().unwrap();
        assert!(!String::from_utf8_lossy(&result.stderr).contains(canary));
        rejected(result);
        assert!(!output.exists());
    }
    assert_eq!(fs::read_dir(f.temp.path()).unwrap().count(), before);
    f.assert_sources_unchanged();
}

#[test]
fn truncated_reordered_and_ambiguous_histories_are_rejected() {
    let f = Fixture::new();
    let (v1, a1) = f.open();
    let v2 = f.path("case-v2.json");
    let out = success(
        f.revision(
            &v1,
            &a1,
            &v2,
            "2026-11-03T12:00:02Z",
            "needs-information",
            &["merchant-01"],
        )
        .output()
        .unwrap(),
    );
    let trusted = out["case_sha256"].as_str().unwrap();
    let original = fs::read(&v2).unwrap();
    let mut value = read_json(&v2);
    value["revisions"].as_array_mut().unwrap().reverse();
    let changed = serde_json::to_vec_pretty(&value).unwrap();
    fs::write(&v2, &changed).unwrap();
    rejected(f.verify(&v2, trusted));
    rejected(f.verify(&v2, &hash(&changed)));
    fs::write(&v2, &original[..original.len() / 2]).unwrap();
    rejected(f.verify(&v2, &hash(&original[..original.len() / 2])));
    // A historical valid snapshot can still verify against its own anchor. The tool must not claim it is latest.
    assert_eq!(success(f.verify(&v1, &a1))["revision"], json!(1));
}

#[cfg(unix)]
#[test]
fn symlink_notes_and_case_files_are_refused_and_private_outputs_stay_owner_only() {
    use std::os::unix::{fs::symlink, fs::PermissionsExt};
    let f = Fixture::new();
    let (case, anchor) = f.open();
    assert_eq!(fs::metadata(&case).unwrap().permissions().mode() & 0o077, 0);
    let link = f.path("case-link.json");
    symlink(&case, &link).unwrap();
    rejected(f.verify(&link, &anchor));
    let saved = f.path("note-original.txt");
    fs::rename(&f.reason, &saved).unwrap();
    symlink(&saved, &f.reason).unwrap();
    let output = f.path("rejected.json");
    rejected(f.open_command(&output).output().unwrap());
    assert!(!output.exists());
}

#[test]
fn two_human_revisions_can_branch_and_require_an_external_latest_head_registry() {
    let f = Fixture::new();
    let (case, anchor) = f.open();
    let left = f.path("branch-left.json");
    let right = f.path("branch-right.json");
    let l = success(
        f.revision(
            &case,
            &anchor,
            &left,
            "2026-11-03T12:00:02Z",
            "closed-explained",
            &["merchant-01"],
        )
        .output()
        .unwrap(),
    );
    let r = success(
        f.revision(
            &case,
            &anchor,
            &right,
            "2026-11-03T12:00:03Z",
            "needs-information",
            &["merchant-02"],
        )
        .output()
        .unwrap(),
    );
    assert_ne!(l["case_sha256"], r["case_sha256"]);
    assert_eq!(
        success(f.verify(&left, l["case_sha256"].as_str().unwrap()))["verified"],
        true
    );
    assert_eq!(
        success(f.verify(&right, r["case_sha256"].as_str().unwrap()))["verified"],
        true
    );
    let a = read_json(&left);
    let b = read_json(&right);
    assert_eq!(a["revisions"][1]["previous_snapshot_sha256"], anchor);
    assert_eq!(
        a["revisions"][1]["previous_snapshot_sha256"],
        b["revisions"][1]["previous_snapshot_sha256"]
    );
    f.assert_sources_unchanged();
}

#[test]
fn captured_example_snapshots_replay_with_their_exact_recorded_byte_digests() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let examples = root.join("examples/analyst-cases");
    let input = root.join("examples/financial-crime/observed/postgres-transfers.jsonl");
    let report = root.join("examples/financial-crime/observed/report.json");
    let observed = read_json(&examples.join("workflow-result.json"));
    let report_anchor = observed["report_sha256"].as_str().unwrap();
    assert_eq!(hash(&fs::read(&input).unwrap()), observed["input_sha256"]);
    assert_eq!(hash(&fs::read(&report).unwrap()), report_anchor);

    let mut snapshots: Vec<(PathBuf, String)> = observed["merchant_timeline"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| {
            (
                examples.join(entry["file"].as_str().unwrap()),
                entry["sha256"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(snapshots.len(), 4);
    let referral = &observed["referral"];
    let referral_v2 = examples.join(referral["file"].as_str().unwrap());
    let referral_body = read_json(&referral_v2);
    snapshots.push((
        examples.join("referral-v1.json"),
        referral_body["revisions"][1]["previous_snapshot_sha256"]
            .as_str()
            .unwrap()
            .to_owned(),
    ));
    snapshots.push((referral_v2, referral["sha256"].as_str().unwrap().to_owned()));
    assert_eq!(snapshots.len(), 6);

    // No newline/encoding normalization is permitted. A checkout that rewrites
    // these anchored artifacts must fail instead of silently generating new hashes.
    for (case, anchor) in snapshots {
        assert_eq!(hash(&fs::read(&case).unwrap()), anchor);
        let checked = success(
            binary("verify-analyst-case")
                .arg("--input")
                .arg(&input)
                .arg("--report")
                .arg(&report)
                .arg("--report-anchor")
                .arg(report_anchor)
                .arg("--case")
                .arg(&case)
                .arg("--case-anchor")
                .arg(&anchor)
                .output()
                .unwrap(),
        );
        assert_eq!(checked["verified"], true);
        assert_eq!(checked["case_sha256"], anchor);
    }
}
