#![forbid(unsafe_code)]
use anyhow::Result;
use clap::{Parser, Subcommand};
use postgres_audit_guard::{detection, ecs, evidence, ingest, transfers};
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
#[derive(Subcommand)]
enum Command {
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
    anyhow::ensure!(
        std::fs::symlink_metadata(path)?.file_type().is_file(),
        "Input must be a regular non-symlink file"
    );
    let file = File::open(path)?;
    anyhow::ensure!(file.metadata()?.is_file(), "Input must be a regular file");
    let mut bytes = Vec::new();
    file.take(transfers::MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= transfers::MAX_INPUT_BYTES,
        "Input exceeds resource limit"
    );
    Ok(bytes)
}

fn atomic_json_output(path: &Path, bytes: &[u8]) -> Result<()> {
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
            atomic_json_output(&output, &bytes)?;
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
