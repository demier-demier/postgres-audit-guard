#![forbid(unsafe_code)]
use anyhow::Result;
use clap::{Parser, Subcommand};
use postgres_audit_guard::{detection, ecs, evidence, ingest};
use serde_json::json;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufReader, BufWriter, Write},
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
fn main() -> Result<()> {
    match Args::parse().command {
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
