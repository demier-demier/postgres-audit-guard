//! Locally captured evidence, bound to a separately retained manifest digest.
//!
//! This is integrity checking, not a digital signature or proof that the original
//! logger was truthful/complete. Keep the anchor outside the bundle. SQL log data
//! can contain personal data or credentials: neither raw evidence nor normalized
//! findings are redacted. Use a trusted, exclusively owned local directory while
//! writing/verifying; portable std filesystem checks are not a race-proof sandbox
//! against a process that can replace files in that directory concurrently.
use crate::model::{Finding, PgLog};
use anyhow::{bail, ensure, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
};

const SCHEMA: &str = "postgres-audit-evidence/v1";
const MAX_RAW_RECORD: usize = 1024 * 1024;
const MAX_JOURNAL_RECORD: usize = 4 * 1024 * 1024;
const MAX_RAW_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RECORDS: u64 = 1_000_000;
const MAX_MANIFEST: u64 = 64 * 1024;
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const RAW_FILE: &str = "raw.bin";
const JOURNAL_FILE: &str = "records.jsonl";
const MANIFEST_FILE: &str = "manifest.json";
const INCOMPLETE_FILE: &str = ".incomplete";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Anchor {
    pub manifest_sha256: String,
    pub records: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema: String,
    records: u64,
    raw_bytes: u64,
    journal_bytes: u64,
    raw_sha256: String,
    journal_sha256: String,
    final_chain_sha256: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    index: u64,
    source_line: u64,
    raw_offset: u64,
    raw_length: u64,
    raw_sha256: String,
    previous_chain_sha256: String,
    event: PgLog,
    findings: Vec<Finding>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    payload: Payload,
    chain_sha256: String,
}

pub struct BundleWriter {
    directory: PathBuf,
    raw: BufWriter<File>,
    journal: BufWriter<File>,
    raw_hash: Sha256,
    journal_hash: Sha256,
    records: u64,
    raw_bytes: u64,
    journal_bytes: u64,
    last_source_line: u64,
    chain: String,
    poisoned: bool,
}

fn private_new_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(path)
        .context("Cannot exclusively create evidence file")
}

fn plain_file(path: &Path, limit: u64) -> Result<File> {
    let metadata = fs::symlink_metadata(path).context("Evidence file is missing")?;
    ensure!(
        metadata.file_type().is_file(),
        "Evidence must be a regular, non-symlink file"
    );
    ensure!(
        metadata.len() <= limit,
        "Evidence file exceeds resource limit"
    );
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.len() <= limit,
        "Evidence file exceeds resource limit"
    );
    Ok(file)
}

fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// serde's Display can quote malformed field names/values, which may contain
// credentials. Do not chain its source into a CLI error or monitoring output.
fn decode_json<T: DeserializeOwned>(bytes: &[u8], context: &str) -> Result<T> {
    serde_json::from_slice(bytes).map_err(|error| {
        anyhow::anyhow!(
            "{context}: {:?} at JSON line {}, column {}",
            error.classify(),
            error.line(),
            error.column()
        )
    })
}

fn valid_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn chain_digest(payload: &Payload) -> Result<String> {
    let mut hasher = Sha256::new();
    hasher.update(b"postgres-audit-evidence-record/v1\0");
    hasher.update(serde_json::to_vec(payload)?);
    Ok(hex::encode(hasher.finalize()))
}

fn validate_event(raw: &[u8], event: &PgLog, findings: &[Finding]) -> Result<()> {
    ensure!(
        !raw.is_empty() && raw.len() <= MAX_RAW_RECORD,
        "Invalid raw record length"
    );
    let event_bytes = [
        event.timestamp.as_str(),
        event.user.as_str(),
        event.dbname.as_str(),
        event.session_id.as_str(),
        event.error_severity.as_str(),
        event.state_code.as_str(),
        event.message.as_str(),
        event.statement.as_deref().unwrap_or_default(),
        event.application_name.as_str(),
    ]
    .iter()
    .try_fold(0usize, |sum, field| sum.checked_add(field.len()))
    .context("Normalized field size overflow")?;
    ensure!(
        event_bytes <= MAX_RAW_RECORD,
        "Normalized fields exceed resource limit"
    );
    // Raw data is one JSON log record, optionally followed by its original newline.
    let parsed: PgLog = decode_json(raw, "Invalid raw PostgreSQL record")?;
    ensure!(
        !parsed.timestamp.is_empty() && !parsed.message.is_empty(),
        "Raw record lacks timestamp/message"
    );
    ensure!(
        serde_json::to_vec(&parsed)? == serde_json::to_vec(event)?,
        "Normalized event differs from original raw record"
    );
    ensure!(findings.len() <= 64, "Too many findings for one record");
    for finding in findings {
        for value in [
            &finding.rule_id,
            &finding.severity,
            &finding.title,
            &finding.detail,
            &finding.outcome,
        ] {
            ensure!(
                value.len() <= 64 * 1024,
                "Finding field exceeds resource limit"
            );
        }
    }
    Ok(())
}

impl BundleWriter {
    /// Refuses an existing directory. Incomplete work remains explicitly marked.
    pub fn create(output_dir: &Path) -> Result<Self> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(output_dir)
            .context("Evidence directory must not already exist")?;
        let mut marker = private_new_file(&output_dir.join(INCOMPLETE_FILE))?;
        marker.write_all(b"Unsealed evidence. Do not treat as a verified bundle.\n")?;
        marker.sync_all()?;
        Ok(Self {
            directory: output_dir.to_owned(),
            raw: BufWriter::new(private_new_file(&output_dir.join(RAW_FILE))?),
            journal: BufWriter::new(private_new_file(&output_dir.join(JOURNAL_FILE))?),
            raw_hash: Sha256::new(),
            journal_hash: Sha256::new(),
            records: 0,
            raw_bytes: 0,
            journal_bytes: 0,
            last_source_line: 0,
            chain: GENESIS.to_owned(),
            poisoned: false,
        })
    }

    pub fn append(
        &mut self,
        source_line: u64,
        raw: &[u8],
        event: &PgLog,
        findings: &[Finding],
    ) -> Result<()> {
        ensure!(
            !self.poisoned,
            "Previous append failed; bundle cannot be completed"
        );
        let result = self.append_inner(source_line, raw, event, findings);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn append_inner(
        &mut self,
        source_line: u64,
        raw: &[u8],
        event: &PgLog,
        findings: &[Finding],
    ) -> Result<()> {
        ensure!(self.records < MAX_RECORDS, "Evidence record limit exceeded");
        ensure!(
            source_line > self.last_source_line,
            "Source line numbers must increase"
        );
        validate_event(raw, event, findings)?;
        let raw_bytes = self
            .raw_bytes
            .checked_add(raw.len() as u64)
            .context("Raw byte count overflow")?;
        ensure!(
            raw_bytes <= MAX_RAW_BYTES,
            "Raw evidence byte limit exceeded"
        );
        let payload = Payload {
            index: self.records + 1,
            source_line,
            raw_offset: self.raw_bytes,
            raw_length: raw.len() as u64,
            raw_sha256: sha256(raw),
            previous_chain_sha256: self.chain.clone(),
            event: event.clone(),
            findings: findings.to_vec(),
        };
        let chain = chain_digest(&payload)?;
        let mut bytes = serde_json::to_vec(&JournalRecord {
            payload,
            chain_sha256: chain.clone(),
        })?;
        bytes.push(b'\n');
        ensure!(
            bytes.len() <= MAX_JOURNAL_RECORD,
            "Normalized record exceeds resource limit"
        );
        let journal_bytes = self
            .journal_bytes
            .checked_add(bytes.len() as u64)
            .context("Journal byte count overflow")?;
        ensure!(
            journal_bytes <= MAX_JOURNAL_BYTES,
            "Normalized evidence byte limit exceeded"
        );
        self.raw.write_all(raw)?;
        self.journal.write_all(&bytes)?;
        self.raw_hash.update(raw);
        self.journal_hash.update(&bytes);
        self.raw_bytes = raw_bytes;
        self.journal_bytes = journal_bytes;
        self.records += 1;
        self.last_source_line = source_line;
        self.chain = chain;
        Ok(())
    }

    /// A zero-record bundle is valid and explicitly records zero captured records.
    /// File flush/sync uses the local filesystem guarantees; not a power-loss certification.
    pub fn finish(mut self) -> Result<Anchor> {
        ensure!(!self.poisoned, "Failed append prevents sealing evidence");
        self.raw.flush()?;
        self.journal.flush()?;
        self.raw.get_ref().sync_all()?;
        self.journal.get_ref().sync_all()?;
        let manifest = Manifest {
            schema: SCHEMA.to_owned(),
            records: self.records,
            raw_bytes: self.raw_bytes,
            journal_bytes: self.journal_bytes,
            raw_sha256: hex::encode(self.raw_hash.finalize()),
            journal_sha256: hex::encode(self.journal_hash.finalize()),
            final_chain_sha256: self.chain,
        };
        let mut bytes = serde_json::to_vec_pretty(&manifest)?;
        bytes.push(b'\n');
        let mut file = private_new_file(&self.directory.join(MANIFEST_FILE))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::remove_file(self.directory.join(INCOMPLETE_FILE))?;
        #[cfg(unix)]
        File::open(&self.directory)?.sync_all()?;
        Ok(Anchor {
            manifest_sha256: sha256(&bytes),
            records: self.records,
        })
    }
}

fn bounded_line<R: BufRead>(reader: &mut R, output: &mut Vec<u8>, limit: usize) -> Result<bool> {
    output.clear();
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(!output.is_empty());
        }
        let take = buffer
            .iter()
            .position(|b| *b == b'\n')
            .map_or(buffer.len(), |p| p + 1);
        ensure!(
            take <= limit.saturating_sub(output.len()),
            "Evidence journal record exceeds resource limit"
        );
        let done = buffer[take - 1] == b'\n';
        output.extend_from_slice(&buffer[..take]);
        reader.consume(take);
        if done {
            return Ok(true);
        }
    }
}

/// Verify only the three fixed evidence artifacts against a trusted external anchor.
/// Other files, such as presentation/SIEM exports, are not covered by this contract.
pub fn verify(dir: &Path, expected_manifest_sha256: &str) -> Result<Anchor> {
    ensure!(
        valid_hash(expected_manifest_sha256),
        "Expected anchor must be 64 lowercase hex characters"
    );
    ensure!(
        fs::symlink_metadata(dir)?.file_type().is_dir(),
        "Evidence directory must not be a symlink"
    );
    match fs::symlink_metadata(dir.join(INCOMPLETE_FILE)) {
        Ok(_) => bail!("Evidence bundle is incomplete"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let mut bytes = Vec::new();
    plain_file(&dir.join(MANIFEST_FILE), MAX_MANIFEST)?
        .take(MAX_MANIFEST + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_MANIFEST,
        "Manifest exceeds resource limit"
    );
    ensure!(
        sha256(&bytes) == expected_manifest_sha256,
        "Manifest does not match trusted external anchor"
    );
    let manifest: Manifest = decode_json(&bytes, "Invalid manifest")?;
    ensure!(manifest.schema == SCHEMA, "Unsupported evidence schema");
    ensure!(
        manifest.records <= MAX_RECORDS
            && manifest.raw_bytes <= MAX_RAW_BYTES
            && manifest.journal_bytes <= MAX_JOURNAL_BYTES,
        "Manifest resource limits exceeded"
    );
    ensure!(
        [
            &manifest.raw_sha256,
            &manifest.journal_sha256,
            &manifest.final_chain_sha256
        ]
        .into_iter()
        .all(|h| valid_hash(h)),
        "Invalid manifest digest"
    );
    let mut raw = BufReader::new(plain_file(&dir.join(RAW_FILE), MAX_RAW_BYTES)?);
    let mut journal = BufReader::new(plain_file(&dir.join(JOURNAL_FILE), MAX_JOURNAL_BYTES)?);
    ensure!(
        raw.get_ref().metadata()?.len() == manifest.raw_bytes,
        "Raw evidence length mismatch"
    );
    ensure!(
        journal.get_ref().metadata()?.len() == manifest.journal_bytes,
        "Journal length mismatch"
    );
    let mut raw_hash = Sha256::new();
    let mut journal_hash = Sha256::new();
    let mut chain = GENESIS.to_owned();
    let mut last_source_line = 0;
    let mut records = 0;
    let mut raw_bytes = 0;
    let mut journal_bytes = 0;
    let mut line = Vec::new();
    let mut raw_record = Vec::new();
    while bounded_line(&mut journal, &mut line, MAX_JOURNAL_RECORD)? {
        ensure!(
            records < manifest.records,
            "Additional unaccounted evidence records"
        );
        ensure!(line.last() == Some(&b'\n'), "Truncated journal record");
        journal_bytes += line.len() as u64;
        ensure!(
            journal_bytes <= manifest.journal_bytes,
            "Journal grew during verification"
        );
        journal_hash.update(&line);
        let record: JournalRecord = decode_json(&line, "Invalid evidence journal record")?;
        let p = &record.payload;
        ensure!(
            p.index == records + 1 && p.source_line > last_source_line,
            "Evidence record ordering mismatch"
        );
        ensure!(
            p.raw_offset == raw_bytes && p.raw_length > 0 && p.raw_length <= MAX_RAW_RECORD as u64,
            "Invalid raw evidence span"
        );
        ensure!(
            p.previous_chain_sha256 == chain && valid_hash(&p.raw_sha256),
            "Broken evidence chain"
        );
        ensure!(
            chain_digest(p)? == record.chain_sha256,
            "Record content/chain mismatch"
        );
        ensure!(
            p.raw_length <= manifest.raw_bytes.saturating_sub(raw_bytes),
            "Raw evidence span exceeds manifest"
        );
        raw_record.resize(p.raw_length as usize, 0);
        raw.read_exact(&mut raw_record)
            .context("Truncated raw evidence")?;
        ensure!(
            sha256(&raw_record) == p.raw_sha256,
            "Raw evidence content mismatch"
        );
        validate_event(&raw_record, &p.event, &p.findings)?;
        raw_hash.update(&raw_record);
        raw_bytes += p.raw_length;
        records += 1;
        last_source_line = p.source_line;
        chain = record.chain_sha256;
    }
    let mut extra = [0u8];
    ensure!(
        raw.read(&mut extra)? == 0,
        "Additional unaccounted raw evidence"
    );
    ensure!(
        records == manifest.records
            && raw_bytes == manifest.raw_bytes
            && journal_bytes == manifest.journal_bytes,
        "Evidence counters differ from manifest"
    );
    ensure!(
        hex::encode(raw_hash.finalize()) == manifest.raw_sha256,
        "Raw evidence digest mismatch"
    );
    ensure!(
        hex::encode(journal_hash.finalize()) == manifest.journal_sha256,
        "Journal digest mismatch"
    );
    ensure!(
        chain == manifest.final_chain_sha256,
        "Final evidence chain mismatch"
    );
    Ok(Anchor {
        manifest_sha256: expected_manifest_sha256.to_owned(),
        records,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn raw(message: &str) -> Vec<u8> {
        let mut data = serde_json::to_vec(&serde_json::json!({
            "timestamp":"2026-01-01 00:00:00.000 UTC", "message":message,
            "user":"synthetic_operator", "custom_source_field":{"preserved":true}
        }))
        .unwrap();
        data.push(b'\n');
        data
    }
    fn create_case() -> (TempDir, PathBuf, Anchor) {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("case");
        let mut writer = BundleWriter::create(&dir).unwrap();
        for (i, msg) in ["statement: SELECT 1", "statement: SELECT 2"]
            .iter()
            .enumerate()
        {
            let data = raw(msg);
            writer
                .append(
                    i as u64 + 1,
                    &data,
                    &serde_json::from_slice(&data).unwrap(),
                    &[],
                )
                .unwrap();
        }
        let anchor = writer.finish().unwrap();
        (temp, dir, anchor)
    }

    #[test]
    fn round_trip_preserves_exact_bytes_unknown_fields_and_last_line_without_newline() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("case");
        let mut writer = BundleWriter::create(&dir).unwrap();
        let one = raw("statement: SELECT 'confidential synthetic text'");
        let mut two = raw("statement: SELECT 2");
        two.pop();
        writer
            .append(1, &one, &serde_json::from_slice(&one).unwrap(), &[])
            .unwrap();
        writer
            .append(2, &two, &serde_json::from_slice(&two).unwrap(), &[])
            .unwrap();
        let anchor = writer.finish().unwrap();
        assert_eq!(verify(&dir, &anchor.manifest_sha256).unwrap(), anchor);
        assert_eq!(fs::read(dir.join(RAW_FILE)).unwrap(), [one, two].concat());
        assert!(!fs::read_to_string(dir.join(MANIFEST_FILE))
            .unwrap()
            .contains("confidential"));
        assert_eq!(anchor.records, 2);
    }

    #[test]
    fn refuses_overwrite_and_untrusted_anchor() {
        let (_temp, dir, anchor) = create_case();
        assert!(BundleWriter::create(&dir).is_err());
        assert!(verify(&dir, "").is_err());
        assert!(verify(&dir, GENESIS).is_err());
        assert!(verify(&dir, &anchor.manifest_sha256).is_ok());
    }

    #[test]
    fn malformed_fields_are_not_echoed_in_errors() {
        let sentinel = "private-secret-sentinel";
        let malformed = format!(
            "{{\"timestamp\":\"2026-01-01 UTC\",\"message\":\"test\",\"line_num\":\"{sentinel}\"}}"
        );
        let error = validate_event(malformed.as_bytes(), &PgLog::default(), &[]).unwrap_err();
        assert!(!format!("{error:#}").contains(sentinel));
        assert!(format!("{error:#}").contains("Data at JSON line"));

        let (_temp, dir, anchor) = create_case();
        let path = dir.join(JOURNAL_FILE);
        let original = fs::read_to_string(&path).unwrap();
        // Preserve the total size so verification reaches JSON decoding before
        // digest validation. A corrupt field must not leak into terminal logs.
        let changed = original.replacen(
            "\"user\":\"synthetic_operator\"",
            "\"user\":12345678901234567890",
            1,
        );
        assert_eq!(changed.len(), original.len());
        fs::write(&path, changed).unwrap();
        let error = verify(&dir, &anchor.manifest_sha256).unwrap_err();
        assert!(!format!("{error:#}").contains("12345678901234567890"));
        assert!(format!("{error:#}").contains("Invalid evidence journal record"));

        let path = dir.join(MANIFEST_FILE);
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value[sentinel] = true.into();
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(path, &bytes).unwrap();
        let error = verify(&dir, &sha256(&bytes)).unwrap_err();
        assert!(!format!("{error:#}").contains(sentinel));
        assert!(format!("{error:#}").contains("Invalid manifest"));
    }

    #[test]
    fn unfinished_and_failed_append_cannot_be_verified_or_sealed() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("case");
        let mut writer = BundleWriter::create(&dir).unwrap();
        let data = raw("original");
        let mut event: PgLog = serde_json::from_slice(&data).unwrap();
        event.message = "forged".into();
        assert!(writer.append(1, &data, &event, &[]).is_err());
        assert!(writer.finish().is_err());
        assert!(verify(&dir, GENESIS).is_err());
        assert!(dir.join(INCOMPLETE_FILE).exists());
        assert!(!dir.join(MANIFEST_FILE).exists());
    }

    #[test]
    fn altered_truncated_and_appended_raw_are_rejected() {
        for mutation in 0..3 {
            let (_temp, dir, anchor) = create_case();
            let path = dir.join(RAW_FILE);
            let mut data = fs::read(&path).unwrap();
            match mutation {
                0 => data[0] ^= 1,
                1 => {
                    data.pop();
                }
                _ => data.push(b'\n'),
            }
            fs::write(path, data).unwrap();
            assert!(verify(&dir, &anchor.manifest_sha256).is_err());
        }
    }

    #[test]
    fn reordered_records_and_modified_findings_are_rejected() {
        let (_temp, dir, anchor) = create_case();
        let path = dir.join(JOURNAL_FILE);
        let original = fs::read_to_string(&path).unwrap();
        let reversed = original
            .lines()
            .rev()
            .map(|s| format!("{s}\n"))
            .collect::<String>();
        fs::write(&path, reversed).unwrap();
        assert!(verify(&dir, &anchor.manifest_sha256).is_err());
        let mut records: Vec<serde_json::Value> = original
            .lines()
            .map(|s| serde_json::from_str(s).unwrap())
            .collect();
        records[0]["payload"]["findings"] = serde_json::json!([{"rule_id":"changed"}]);
        fs::write(
            &path,
            records.iter().map(|r| format!("{r}\n")).collect::<String>(),
        )
        .unwrap();
        assert!(verify(&dir, &anchor.manifest_sha256).is_err());
    }

    #[test]
    fn modified_manifest_cannot_reset_external_trust() {
        let (_temp, dir, anchor) = create_case();
        let path = dir.join(MANIFEST_FILE);
        let mut data: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        data["records"] = 0.into();
        fs::write(path, serde_json::to_vec(&data).unwrap()).unwrap();
        assert!(verify(&dir, &anchor.manifest_sha256).is_err());
    }

    #[test]
    fn forged_schema_paths_and_resource_counts_reject_even_with_new_anchor() {
        for mutation in 0..3 {
            let (_temp, dir, _anchor) = create_case();
            let path = dir.join(MANIFEST_FILE);
            let mut data: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            match mutation {
                0 => data["schema"] = "other".into(),
                1 => data["raw_path"] = "../../private".into(),
                _ => data["records"] = (MAX_RECORDS + 1).into(),
            }
            let bytes = serde_json::to_vec(&data).unwrap();
            fs::write(path, &bytes).unwrap();
            assert!(verify(&dir, &sha256(&bytes)).is_err());
        }
    }

    #[test]
    fn zero_records_is_explicit_and_verifiable() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("empty");
        let anchor = BundleWriter::create(&dir).unwrap().finish().unwrap();
        assert_eq!(anchor.records, 0);
        assert_eq!(verify(&dir, &anchor.manifest_sha256).unwrap(), anchor);
    }

    #[test]
    fn bounded_reader_stops_before_collecting_oversized_line() {
        let input = vec![b'x'; 8192];
        let mut reader = BufReader::with_capacity(16, input.as_slice());
        let mut output = Vec::new();
        assert!(bounded_line(&mut reader, &mut output, 64).is_err());
        assert!(output.len() <= 64);
    }

    #[test]
    fn oversized_record_and_invalid_source_order_poison_the_bundle() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("oversized");
        let mut writer = BundleWriter::create(&dir).unwrap();
        let data = raw("original");
        let event = serde_json::from_slice(&data).unwrap();
        assert!(writer
            .append(1, &vec![0; MAX_RAW_RECORD + 1], &event, &[])
            .is_err());
        assert!(writer.finish().is_err());

        let dir = temp.path().join("order");
        let mut writer = BundleWriter::create(&dir).unwrap();
        writer.append(1, &data, &event, &[]).unwrap();
        assert!(writer.append(1, &data, &event, &[]).is_err());
        assert!(writer.finish().is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_permissions_and_symlink_files_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let (temp, dir, anchor) = create_case();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.join(RAW_FILE))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let copied = temp.path().join("copied");
        fs::rename(dir.join(RAW_FILE), &copied).unwrap();
        symlink(&copied, dir.join(RAW_FILE)).unwrap();
        assert!(verify(&dir, &anchor.manifest_sha256).is_err());
        let link = temp.path().join("case-link");
        symlink(&dir, &link).unwrap();
        assert!(verify(&link, &anchor.manifest_sha256).is_err());
    }
}
