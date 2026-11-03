#![forbid(unsafe_code)]
use anyhow::Result;
use clap::{Parser, Subcommand};
use postgres_audit_guard::{cases, detection, ecs, evidence, ingest, transfers};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};

#[derive(Parser)]
#[command(
    version,
    about = "Read-only PostgreSQL security triage with externally anchored evidence"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct CaseSource {
    #[arg(long)]
    input: PathBuf,
    #[arg(long)]
    report: PathBuf,
    /// Obtain this digest through an independently trusted channel.
    #[arg(long)]
    report_anchor: String,
}

#[derive(clap::Args)]
struct ReviewNote {
    /// Pseudonymous analyst token; not authenticated by this offline tool.
    #[arg(long)]
    actor: String,
    /// Analyst-supplied RFC3339 instant; not a trusted timestamp service.
    #[arg(long)]
    at: String,
    /// UTF-8 single-paragraph note, at most 2048 bytes (kept out of argv).
    #[arg(long)]
    reason_file: PathBuf,
    /// Repeat for each source record cited from this case's selected alert.
    #[arg(long = "evidence-ref", required = true)]
    evidence_refs: Vec<String>,
}

#[derive(Clone, clap::ValueEnum)]
enum ReviewDisposition {
    Open,
    NeedsInformation,
    ClosedExplained,
    EscalatedForReview,
}

impl From<ReviewDisposition> for cases::Disposition {
    fn from(value: ReviewDisposition) -> Self {
        match value {
            ReviewDisposition::Open => Self::Open,
            ReviewDisposition::NeedsInformation => Self::NeedsInformation,
            ReviewDisposition::ClosedExplained => Self::ClosedExplained,
            ReviewDisposition::EscalatedForReview => Self::EscalatedForReview,
        }
    }
}

#[derive(Subcommand)]
enum Command {
    /// Open an immutable human-review case tied to a verified transfer alert.
    OpenAnalystCase {
        #[command(flatten)]
        source: CaseSource,
        #[arg(long)]
        case_id: String,
        /// Zero-based index in the externally anchored canonical report.
        #[arg(long)]
        alert_index: usize,
        #[command(flatten)]
        note: ReviewNote,
        #[arg(long)]
        output: PathBuf,
    },
    /// Append a human disposition to a new snapshot, preserving the prior file.
    ReviseAnalystCase {
        #[command(flatten)]
        source: CaseSource,
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        case_anchor: String,
        #[arg(long, value_enum)]
        disposition: ReviewDisposition,
        #[command(flatten)]
        note: ReviewNote,
        #[arg(long)]
        output: PathBuf,
    },
    /// Check a case's source binding, timeline, canonical bytes and external hash.
    VerifyAnalystCase {
        #[command(flatten)]
        source: CaseSource,
        #[arg(long)]
        case: PathBuf,
        #[arg(long)]
        case_anchor: String,
    },
    /// Find explainable transfer patterns for human review; never infer a crime.
    TriageTransfers {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Verify an anchored transfer report and reproduce its analysis from source bytes.
    VerifyTransferReport {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        report: PathBuf,
        #[arg(long)]
        anchor: String,
    },
    /// Preserve exact input and detected findings in a new evidence directory.
    Scan {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        bundle: PathBuf,
    },
    /// Verify against a manifest SHA256 obtained through a separate trusted channel.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        anchor: String,
    },
    /// Export SQL-free ECS events. Derived output is not a sealed evidence bundle.
    ExportEcs {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Measure parsing and detection without writing evidence (not full-pipeline throughput).
    Bench {
        #[arg(long)]
        input: PathBuf,
    },
}

fn bounded_file(path: &Path) -> Result<Vec<u8>> {
    bounded_file_with_limit(path, transfers::MAX_INPUT_BYTES)
}

fn bounded_file_with_limit(path: &Path, limit: usize) -> Result<Vec<u8>> {
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "Input must be a regular non-symlink file"
    );
    let file = File::open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "Input must be a regular file");
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= limit, "Input exceeds resource limit");
    Ok(bytes)
}

fn revision_input(
    note: ReviewNote,
    disposition: cases::Disposition,
) -> Result<cases::RevisionInput> {
    let bytes = bounded_file_with_limit(&note.reason_file, 2048)?;
    let reason = std::str::from_utf8(&bytes)
        .map_err(|_| anyhow::anyhow!("Review note must be valid UTF-8"))?
        .trim_end_matches(['\r', '\n'])
        .to_owned();
    Ok(cases::RevisionInput {
        actor: note.actor,
        timestamp: note.at,
        disposition,
        reason,
        evidence_refs: note.evidence_refs,
    })
}

fn write_case(path: &Path, snapshot: cases::CaseSnapshot) -> Result<()> {
    let bytes = cases::canonical_bytes(&snapshot)?;
    publish_json_output(path, &bytes)?;
    println!("{}", case_summary(&snapshot, &bytes, false));
    Ok(())
}

fn case_summary(snapshot: &cases::CaseSnapshot, bytes: &[u8], verified: bool) -> serde_json::Value {
    let revision = snapshot
        .revisions
        .last()
        .expect("validated case is nonempty");
    json!({
        "schema": "analyst-case-result/v1", "case_sha256": cases::digest(bytes),
        "revision": revision.version, "disposition": revision.disposition, "verified": verified,
        "note": "Keep this digest independently. Analyst assertions are not authenticated identities, proof of crime or automatic actions."
    })
}

fn publish_json_output(path: &Path, bytes: &[u8]) -> Result<()> {
    anyhow::ensure!(!path.exists(), "Refusing to overwrite output");
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist_noclobber(path)?;
    Ok(())
}

fn main() -> Result<()> {
    match Args::parse().command {
        Command::OpenAnalystCase {
            source,
            case_id,
            alert_index,
            note,
            output,
        } => {
            let input = bounded_file(&source.input)?;
            let report = bounded_file(&source.report)?;
            let snapshot = cases::create(
                &input,
                &report,
                &source.report_anchor,
                &case_id,
                alert_index,
                revision_input(note, cases::Disposition::Open)?,
            )?;
            write_case(&output, snapshot)?;
        }
        Command::ReviseAnalystCase {
            source,
            case,
            case_anchor,
            disposition,
            note,
            output,
        } => {
            let input = bounded_file(&source.input)?;
            let report = bounded_file(&source.report)?;
            let previous = bounded_file(&case)?;
            let snapshot = cases::append(
                &input,
                &report,
                &source.report_anchor,
                &previous,
                &case_anchor,
                revision_input(note, disposition.into())?,
            )?;
            write_case(&output, snapshot)?;
        }
        Command::VerifyAnalystCase {
            source,
            case,
            case_anchor,
        } => {
            let input = bounded_file(&source.input)?;
            let report = bounded_file(&source.report)?;
            let bytes = bounded_file(&case)?;
            let snapshot =
                cases::verify(&input, &report, &source.report_anchor, &bytes, &case_anchor)?;
            println!("{}", case_summary(&snapshot, &bytes, true));
        }
        Command::TriageTransfers { input, output } => {
            let source = bounded_file(&input)?;
            let report = transfers::analyze(&source)?;
            let value = serde_json::to_value(&report)?;
            let mut bytes = serde_json::to_vec_pretty(&value)?;
            bytes.push(b'\n');
            anyhow::ensure!(
                bytes.len() <= transfers::MAX_INPUT_BYTES,
                "Report exceeds resource limit"
            );
            publish_json_output(&output, &bytes)?;
            println!(
                "{}",
                json!({"report_sha256":hex::encode(Sha256::digest(&bytes)),
                "input_records":value["input_records"],"alerts":value["alerts"].as_array().map_or(0,Vec::len),
                "note":"Keep the report digest separately. Patterns require human review; no crime is established."})
            );
        }
        Command::VerifyTransferReport {
            input,
            report,
            anchor,
        } => {
            anyhow::ensure!(
                anchor.len() == 64
                    && anchor
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "Expected anchor must be 64 lowercase hex characters"
            );
            let report_bytes = bounded_file(&report)?;
            anyhow::ensure!(
                hex::encode(Sha256::digest(&report_bytes)) == anchor,
                "Report differs from trusted external anchor"
            );
            let source = bounded_file(&input)?;
            let recomputed = serde_json::to_value(transfers::analyze(&source)?)?;
            let mut canonical = serde_json::to_vec_pretty(&recomputed)?;
            canonical.push(b'\n');
            anyhow::ensure!(
                report_bytes == canonical,
                "Report does not match canonical source analysis and current policy"
            );
            println!(
                "{}",
                json!({"verified":true,"report_sha256":anchor,"input_sha256":hex::encode(Sha256::digest(&source)),"scope":"Integrity and deterministic replay, not source authenticity or proof of crime."})
            );
        }
        Command::Scan { input, bundle } => {
            let reader = BufReader::new(File::open(input)?);
            let mut writer = evidence::BundleWriter::create(&bundle)?;
            let mut counts = BTreeMap::<String, u64>::new();
            let start = Instant::now();
            let stats = ingest::scan(reader, ingest::Limits::default(), |line, raw, event| {
                let findings = detection::analyze(&event);
                for f in &findings {
                    *counts.entry(f.rule_id.clone()).or_default() += 1;
                }
                writer.append(line, raw, &event, &findings)
            })?;
            let anchor = writer.finish()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({"schema":"postgres-audit-scan/v1",
                "records":stats.records,"bytes":stats.bytes,"findings_by_rule":counts,
                "elapsed_seconds":start.elapsed().as_secs_f64(),"anchor":anchor,
                "note":"Store the manifest hash separately. Integrity does not establish source authenticity."}))?
            );
        }
        Command::Verify { bundle, anchor } => println!(
            "{}",
            serde_json::to_string_pretty(&evidence::verify(&bundle, &anchor)?)?
        ),
        Command::ExportEcs { input, output } => {
            anyhow::ensure!(!output.exists(), "Refusing to overwrite output");
            let mut temporary = tempfile::NamedTempFile::new_in(
                output
                    .parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or(Path::new(".")),
            )?;
            let mut writer = BufWriter::new(temporary.as_file_mut());
            let mut count = 0u64;
            let stats = ingest::scan(
                BufReader::new(File::open(input)?),
                ingest::Limits::default(),
                |_, raw, event| {
                    for finding in detection::analyze(&event) {
                        serde_json::to_writer(&mut writer, &ecs::alert(&event, &finding, raw)?)?;
                        writer.write_all(b"\n")?;
                        count += 1;
                    }
                    Ok(())
                },
            )?;
            writer.flush()?;
            drop(writer);
            temporary.as_file().sync_all()?;
            temporary.persist_noclobber(output)?;
            println!(
                "{}",
                json!({"input_records":stats.records,"exported_alerts":count,"sealed":false})
            );
        }
        Command::Bench { input } => {
            let start = Instant::now();
            let mut findings = 0usize;
            let stats = ingest::scan(
                BufReader::new(File::open(input)?),
                ingest::Limits::default(),
                |_, _, event| {
                    findings += detection::analyze(&event).len();
                    Ok(())
                },
            )?;
            let seconds = start.elapsed().as_secs_f64();
            println!(
                "{}",
                json!({"schema":"postgres-audit-benchmark/v1","records":stats.records,"bytes":stats.bytes,
                "findings":findings,"wall_seconds":seconds,"records_per_second":stats.records as f64/seconds,
                "scope":"Input read, parsing and deterministic detection only; no persistence, network or SIEM."})
            );
        }
    }
    Ok(())
}
