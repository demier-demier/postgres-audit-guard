//! Evidence-bound, immutable analyst case snapshots.
//!
//! Hashes detect changes only relative to independently retained anchors. Actor
//! labels and event times are operator assertions, not authenticated identities
//! or trusted timestamps. New snapshots can branch: this offline format has no
//! global latest-head service, access control, lock or compare-and-swap ledger.
use crate::transfers;
use anyhow::{anyhow, ensure, Result};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const MAX_CASE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_REVISIONS: usize = 128;
pub const MAX_REASON_BYTES: usize = 2048;
pub const MAX_REFS_PER_REVISION: usize = 1024;
const SCHEMA: &str = "transfer-case/v1";

/// An explicit human workflow label, never an automatic account action or a
/// finding of criminal activity. A closed explanation can be reopened.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Disposition {
    Open,
    NeedsInformation,
    ClosedExplained,
    EscalatedForReview,
}

#[derive(Debug, Clone)]
pub struct RevisionInput {
    pub actor: String,
    pub timestamp: String,
    pub disposition: Disposition,
    pub reason: String,
    pub evidence_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Revision {
    pub version: usize,
    pub previous_event_sha256: Option<String>,
    pub previous_snapshot_sha256: Option<String>,
    pub actor: String,
    pub timestamp: String,
    pub disposition: Disposition,
    pub reason: String,
    pub evidence_refs: Vec<String>,
    pub event_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CaseSnapshot {
    pub schema: String,
    pub case_id: String,
    pub input_sha256: String,
    pub report_sha256: String,
    pub alert_index: usize,
    pub alert_sha256: String,
    pub revisions: Vec<Revision>,
}

pub fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn valid_anchor(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn anchored(bytes: &[u8], anchor: &str, max: usize) -> Result<()> {
    ensure!(
        valid_anchor(anchor),
        "Expected anchor must be 64 lowercase hex characters"
    );
    ensure!(
        bytes.len() <= max,
        "Anchored document exceeds resource limit"
    );
    ensure!(
        digest(bytes) == anchor,
        "Document differs from trusted external anchor"
    );
    Ok(())
}

/// The same Value-based pretty JSON + LF representation used by the transfer
/// CLI. This function encodes a snapshot; verification is a separate operation.
pub fn canonical_bytes(snapshot: &CaseSnapshot) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(&serde_json::to_value(snapshot)?)?;
    bytes.push(b'\n');
    ensure!(
        bytes.len() <= MAX_CASE_BYTES,
        "Case snapshot exceeds resource limit"
    );
    Ok(bytes)
}

fn verified_report(input: &[u8], report: &[u8], anchor: &str) -> Result<transfers::Report> {
    anchored(report, anchor, transfers::MAX_REPORT_BYTES)?;
    let analyzed = transfers::analyze(input)?;
    let mut canonical = serde_json::to_vec_pretty(&serde_json::to_value(&analyzed)?)?;
    canonical.push(b'\n');
    ensure!(
        report == canonical,
        "Report does not match canonical source analysis and current policy"
    );
    Ok(analyzed)
}

fn alert_digest(alert: &transfers::Alert) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&serde_json::to_value(alert)?)?))
}

fn binding_digest(snapshot: &CaseSnapshot) -> Result<String> {
    Ok(digest(&serde_json::to_vec(&json!({
        "schema":"transfer-case-binding/v1",
        "case_schema":snapshot.schema,
        "case_id":snapshot.case_id,
        "input_sha256":snapshot.input_sha256,
        "report_sha256":snapshot.report_sha256,
        "alert_index":snapshot.alert_index,
        "alert_sha256":snapshot.alert_sha256,
    }))?))
}

fn event_digest(binding: &str, revision: &Revision) -> Result<String> {
    let mut material = serde_json::to_value(revision)?;
    let map = material
        .as_object_mut()
        .expect("Revision serializes as an object");
    map.remove("event_sha256");
    map.insert("schema".into(), "transfer-case-event/v1".into());
    map.insert("binding_sha256".into(), binding.into());
    Ok(digest(&serde_json::to_vec(&material)?))
}

fn parse_timestamp(value: &str) -> Result<DateTime<Utc>> {
    ensure!(value.len() <= 64, "Invalid case timestamp");
    DateTime::parse_from_rfc3339(value)
        .map(|t| t.with_timezone(&Utc))
        .map_err(|_| anyhow!("Invalid case RFC3339 timestamp"))
}

fn stamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn validate_revision_content(
    revision: &Revision,
    allowed: &BTreeSet<&str>,
) -> Result<DateTime<Utc>> {
    ensure!(
        valid_identifier(&revision.actor),
        "Invalid case actor identifier"
    );
    ensure!(
        !revision.reason.trim().is_empty()
            && revision.reason.len() <= MAX_REASON_BYTES
            && !revision.reason.chars().any(char::is_control),
        "Case reason must be nonempty, bounded and contain no control characters"
    );
    ensure!(
        !revision.evidence_refs.is_empty() && revision.evidence_refs.len() <= MAX_REFS_PER_REVISION,
        "Case evidence reference count is outside the permitted range"
    );
    let mut seen = BTreeSet::new();
    for id in &revision.evidence_refs {
        ensure!(valid_identifier(id), "Invalid case evidence reference");
        ensure!(
            allowed.contains(id.as_str()),
            "Case reference is not part of the selected alert"
        );
        ensure!(
            seen.insert(id.as_str()),
            "Duplicate case evidence reference"
        );
    }
    ensure!(
        revision
            .evidence_refs
            .windows(2)
            .all(|pair| pair[0] < pair[1]),
        "Case evidence references are not in canonical order"
    );
    let timestamp = parse_timestamp(&revision.timestamp)?;
    ensure!(
        revision.timestamp == stamp(timestamp),
        "Case timestamp is not canonical UTC"
    );
    Ok(timestamp)
}

/// Create the first (Open) snapshot for one alert from a verified report.
/// The caller must persist canonical bytes without overwriting existing files,
/// and retain the returned snapshot digest in a separate trusted record.
pub fn create(
    input: &[u8],
    report: &[u8],
    report_anchor: &str,
    case_id: &str,
    alert_index: usize,
    revision: RevisionInput,
) -> Result<CaseSnapshot> {
    ensure!(valid_identifier(case_id), "Invalid case identifier");
    let analyzed = verified_report(input, report, report_anchor)?;
    let alert = analyzed
        .alerts
        .get(alert_index)
        .ok_or_else(|| anyhow!("Selected alert does not exist"))?;
    let mut snapshot = CaseSnapshot {
        schema: SCHEMA.into(),
        case_id: case_id.into(),
        input_sha256: analyzed.input_sha256.clone(),
        report_sha256: report_anchor.into(),
        alert_index,
        alert_sha256: alert_digest(alert)?,
        revisions: Vec::new(),
    };
    push_revision(&mut snapshot, alert, revision)?;
    canonical_bytes(&snapshot)?;
    Ok(snapshot)
}

/// Verify exact canonical case bytes, the full revision chain, and replay of the
/// independently anchored report. An older authentic snapshot can still verify;
/// latest-head and branch detection require a separate trusted registry.
pub fn verify(
    input: &[u8],
    report: &[u8],
    report_anchor: &str,
    snapshot: &[u8],
    snapshot_anchor: &str,
) -> Result<CaseSnapshot> {
    let (case, _) = verify_inner(input, report, report_anchor, snapshot, snapshot_anchor)?;
    Ok(case)
}

fn verify_inner(
    input: &[u8],
    report: &[u8],
    report_anchor: &str,
    snapshot: &[u8],
    snapshot_anchor: &str,
) -> Result<(CaseSnapshot, transfers::Report)> {
    anchored(snapshot, snapshot_anchor, MAX_CASE_BYTES)?;
    // Suppress serde diagnostics: malformed private fields can appear in them.
    let case: CaseSnapshot =
        serde_json::from_slice(snapshot).map_err(|_| anyhow!("Invalid case snapshot schema"))?;
    ensure!(case.schema == SCHEMA, "Unsupported case snapshot schema");
    ensure!(valid_identifier(&case.case_id), "Invalid case identifier");
    ensure!(
        !case.revisions.is_empty() && case.revisions.len() <= MAX_REVISIONS,
        "Case revision count is outside the permitted range"
    );
    ensure!(
        valid_anchor(&case.input_sha256)
            && valid_anchor(&case.report_sha256)
            && valid_anchor(&case.alert_sha256),
        "Invalid case binding digest"
    );
    for revision in &case.revisions {
        ensure!(
            valid_identifier(&revision.actor)
                && revision.timestamp.len() <= 64
                && revision.reason.len() <= MAX_REASON_BYTES,
            "Case revision field exceeds its bounds"
        );
        ensure!(
            !revision.evidence_refs.is_empty()
                && revision.evidence_refs.len() <= MAX_REFS_PER_REVISION
                && revision.evidence_refs.iter().all(|id| valid_identifier(id)),
            "Case evidence references exceed their bounds"
        );
        ensure!(
            valid_anchor(&revision.event_sha256)
                && revision
                    .previous_event_sha256
                    .as_deref()
                    .is_none_or(valid_anchor)
                && revision
                    .previous_snapshot_sha256
                    .as_deref()
                    .is_none_or(valid_anchor),
            "Invalid case revision digest"
        );
    }
    ensure!(
        snapshot == canonical_bytes(&case)?,
        "Case snapshot is not canonical JSON"
    );
    let analyzed = verified_report(input, report, report_anchor)?;
    ensure!(
        case.input_sha256 == analyzed.input_sha256,
        "Case source binding differs"
    );
    ensure!(
        case.report_sha256 == report_anchor,
        "Case report binding differs"
    );
    let alert = analyzed
        .alerts
        .get(case.alert_index)
        .ok_or_else(|| anyhow!("Selected alert does not exist"))?;
    ensure!(
        case.alert_sha256 == alert_digest(alert)?,
        "Case selected-alert binding differs"
    );
    let allowed = alert.source_record_ids.iter().map(String::as_str).collect();
    let binding = binding_digest(&case)?;
    let mut previous_time = None;
    let mut prefix = case.clone();
    prefix.revisions.clear();
    for (index, revision) in case.revisions.iter().enumerate() {
        ensure!(
            revision.version == index + 1,
            "Case revision sequence differs"
        );
        if index == 0 {
            ensure!(
                revision.disposition == Disposition::Open,
                "First case revision must be open"
            );
            ensure!(
                revision.previous_event_sha256.is_none()
                    && revision.previous_snapshot_sha256.is_none(),
                "First case revision must not have a predecessor"
            );
        } else {
            ensure!(
                revision.previous_event_sha256.as_deref()
                    == Some(case.revisions[index - 1].event_sha256.as_str()),
                "Case event predecessor differs"
            );
            ensure!(
                revision.previous_snapshot_sha256.as_deref()
                    == Some(digest(&canonical_bytes(&prefix)?).as_str()),
                "Case snapshot predecessor differs"
            );
        }
        let timestamp = validate_revision_content(revision, &allowed)?;
        ensure!(
            timestamp >= parse_timestamp(&alert.window_end)?,
            "Case timestamp precedes selected alert evidence"
        );
        if let Some(previous) = previous_time {
            ensure!(
                timestamp > previous,
                "Case timestamps must strictly increase"
            );
        }
        previous_time = Some(timestamp);
        ensure!(
            revision.event_sha256 == event_digest(&binding, revision)?,
            "Case event digest differs"
        );
        prefix.revisions.push(revision.clone());
    }
    Ok((case, analyzed))
}

/// Append one explicit human disposition to a verified snapshot. The original
/// bytes remain untouched. Persist the result to a new file with no-clobber I/O.
pub fn append(
    input: &[u8],
    report: &[u8],
    report_anchor: &str,
    snapshot: &[u8],
    snapshot_anchor: &str,
    revision: RevisionInput,
) -> Result<CaseSnapshot> {
    let (mut case, analyzed) =
        verify_inner(input, report, report_anchor, snapshot, snapshot_anchor)?;
    let selected = case.alert_index;
    push_revision(&mut case, &analyzed.alerts[selected], revision)?;
    canonical_bytes(&case)?;
    Ok(case)
}

fn push_revision(
    case: &mut CaseSnapshot,
    alert: &transfers::Alert,
    input: RevisionInput,
) -> Result<()> {
    ensure!(
        case.revisions.len() < MAX_REVISIONS,
        "Case revision limit reached"
    );
    let previous = case.revisions.last();
    if previous.is_none() {
        ensure!(
            input.disposition == Disposition::Open,
            "First case revision must be open"
        );
    }
    let previous_snapshot_sha256 = if previous.is_some() {
        Some(digest(&canonical_bytes(case)?))
    } else {
        None
    };
    ensure!(
        !input.evidence_refs.is_empty() && input.evidence_refs.len() <= MAX_REFS_PER_REVISION,
        "Case evidence reference count is outside the permitted range"
    );
    let mut refs = input.evidence_refs;
    refs.sort();
    let mut revision = Revision {
        version: case.revisions.len() + 1,
        previous_event_sha256: previous.map(|event| event.event_sha256.clone()),
        previous_snapshot_sha256,
        actor: input.actor,
        timestamp: stamp(parse_timestamp(&input.timestamp)?),
        disposition: input.disposition,
        reason: input.reason,
        evidence_refs: refs,
        event_sha256: String::new(),
    };
    let allowed = alert.source_record_ids.iter().map(String::as_str).collect();
    let timestamp = validate_revision_content(&revision, &allowed)?;
    ensure!(
        timestamp >= parse_timestamp(&alert.window_end)?,
        "Case timestamp precedes selected alert evidence"
    );
    if let Some(last) = previous {
        ensure!(
            timestamp > parse_timestamp(&last.timestamp)?,
            "Case timestamps must strictly increase"
        );
    }
    revision.event_sha256 = event_digest(&binding_digest(case)?, &revision)?;
    case.revisions.push(revision);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> (Vec<u8>, Vec<u8>, String) {
        let input = include_bytes!("../examples/financial-crime/transfers.jsonl").to_vec();
        let report = transfers::analyze(&input).unwrap();
        let mut bytes = serde_json::to_vec_pretty(&serde_json::to_value(report).unwrap()).unwrap();
        bytes.push(b'\n');
        let anchor = digest(&bytes);
        (input, bytes, anchor)
    }

    fn revision(disposition: Disposition, minute: u8, refs: Vec<String>) -> RevisionInput {
        RevisionInput {
            actor: "analyst-synthetic-01".into(),
            timestamp: format!("2026-11-03T12:{minute:02}:00Z"),
            disposition,
            reason: "Synthetic review context retained for a human decision.".into(),
            evidence_refs: refs,
        }
    }

    fn refs(input: &[u8], index: usize) -> Vec<String> {
        let report = transfers::analyze(input).unwrap();
        report.alerts[index]
            .source_record_ids
            .iter()
            .take(2)
            .cloned()
            .collect()
    }

    fn create_case() -> (Vec<u8>, Vec<u8>, String, CaseSnapshot) {
        let (input, report, anchor) = fixture();
        let case = create(
            &input,
            &report,
            &anchor,
            "case-synthetic-01",
            0,
            revision(Disposition::Open, 0, refs(&input, 0)),
        )
        .unwrap();
        (input, report, anchor, case)
    }

    #[test]
    fn lifecycle_is_replayable_and_keeps_prior_snapshots_unchanged() {
        let (input, report, report_anchor, first) = create_case();
        let before = canonical_bytes(&first).unwrap();
        let mut prior = first;
        for (i, state) in [
            Disposition::NeedsInformation,
            Disposition::ClosedExplained,
            Disposition::Open,
            Disposition::EscalatedForReview,
        ]
        .iter()
        .enumerate()
        {
            let raw = canonical_bytes(&prior).unwrap();
            let next = append(
                &input,
                &report,
                &report_anchor,
                &raw,
                &digest(&raw),
                revision(*state, (i + 1) as u8, refs(&input, 0)),
            )
            .unwrap();
            assert_eq!(
                &next.revisions[..prior.revisions.len()],
                prior.revisions.as_slice()
            );
            assert_eq!(
                next.revisions.last().unwrap().previous_snapshot_sha256,
                Some(digest(&raw))
            );
            let bytes = canonical_bytes(&next).unwrap();
            assert_eq!(
                verify(&input, &report, &report_anchor, &bytes, &digest(&bytes)).unwrap(),
                next
            );
            prior = next;
        }
        assert!(verify(&input, &report, &report_anchor, &before, &digest(&before)).is_ok());
        assert_eq!(prior.revisions.len(), 5);
    }

    #[test]
    fn source_report_and_case_anchors_are_independently_required() {
        let (input, report, report_anchor, case) = create_case();
        let bytes = canonical_bytes(&case).unwrap();
        assert!(verify(&input, &report, &report_anchor, &bytes, &"0".repeat(64)).is_err());
        assert!(verify(&input, &report, &"0".repeat(64), &bytes, &digest(&bytes)).is_err());
        let mut changed_source = input.clone();
        changed_source.push(b'\n');
        assert!(verify(
            &changed_source,
            &report,
            &report_anchor,
            &bytes,
            &digest(&bytes)
        )
        .is_err());
        let mut changed_report = report.clone();
        changed_report.push(b' ');
        assert!(verify(
            &input,
            &changed_report,
            &digest(&changed_report),
            &bytes,
            &digest(&bytes)
        )
        .is_err());
        assert!(verify(
            &input,
            &report,
            &report_anchor,
            &bytes,
            &report_anchor.to_uppercase()
        )
        .is_err());
    }

    #[test]
    fn reanchoring_modified_history_does_not_bypass_event_checks() {
        let (input, report, report_anchor, case) = create_case();
        for mutate in [0, 1, 2, 3, 4] {
            let mut modified = case.clone();
            match mutate {
                0 => modified.case_id = "transplanted".into(),
                1 => modified.alert_index = 1,
                2 => modified.revisions[0].reason = "Replacement reason".into(),
                3 => modified.revisions[0].version = 2,
                _ => modified.revisions[0].previous_event_sha256 = Some("0".repeat(64)),
            }
            let bytes = canonical_bytes(&modified).unwrap();
            assert!(verify(&input, &report, &report_anchor, &bytes, &digest(&bytes)).is_err());
        }
    }

    #[test]
    fn ambiguous_unknown_and_noncanonical_json_are_rejected_without_content_leaks() {
        let (input, report, report_anchor, case) = create_case();
        let bytes = canonical_bytes(&case).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        let bad = [
            text.replacen('{', "{\"private-canary\":true,", 1),
            text.replacen('{', "{\"case_id\":\"private-canary\",", 1),
            text.replacen("\"version\": 1", "\"version\": \"private-canary\"", 1),
            serde_json::to_string(&case).unwrap(),
            format!("{text} "),
        ];
        for value in bad {
            let result = verify(
                &input,
                &report,
                &report_anchor,
                value.as_bytes(),
                &digest(value.as_bytes()),
            );
            assert!(result.is_err());
            assert!(!format!("{:#}", result.unwrap_err()).contains("private-canary"));
        }
    }

    #[test]
    fn reference_membership_duplicates_and_bounds_are_checked() {
        let (input, report, anchor) = fixture();
        let good = refs(&input, 0);
        for list in [
            vec![],
            vec!["not-in-alert".into()],
            vec![good[0].clone(), good[0].clone()],
            vec![good[0].clone(); MAX_REFS_PER_REVISION + 1],
        ] {
            assert!(create(
                &input,
                &report,
                &anchor,
                "case-1",
                0,
                revision(Disposition::Open, 0, list)
            )
            .is_err());
        }
        let mut reversed = good.clone();
        reversed.reverse();
        let case = create(
            &input,
            &report,
            &anchor,
            "case-1",
            0,
            revision(Disposition::Open, 0, reversed),
        )
        .unwrap();
        assert!(case.revisions[0]
            .evidence_refs
            .windows(2)
            .all(|p| p[0] < p[1]));
    }

    #[test]
    fn reason_and_actor_validation_never_echoes_private_values() {
        let (input, report, anchor) = fixture();
        for (actor, reason) in [
            ("private-canary\n", "Context".into()),
            ("analyst", "private-canary\n".into()),
            ("analyst", " ".into()),
            ("analyst", "x".repeat(MAX_REASON_BYTES + 1)),
        ] {
            let mut r = revision(Disposition::Open, 0, refs(&input, 0));
            r.actor = actor.into();
            r.reason = reason;
            let error = create(&input, &report, &anchor, "case-1", 0, r).unwrap_err();
            assert!(!format!("{error:#}").contains("private-canary"));
        }
    }

    #[test]
    fn typed_time_order_and_utc_normalization_are_enforced() {
        let (input, report, report_anchor, case) = create_case();
        let raw = canonical_bytes(&case).unwrap();
        for invalid in [
            "2026-11-03T11:59:59.999Z",
            "2026-11-03T09:00:00-03:00",
            "private-canary",
        ] {
            let mut r = revision(Disposition::NeedsInformation, 1, refs(&input, 0));
            r.timestamp = invalid.into();
            let err = append(&input, &report, &report_anchor, &raw, &digest(&raw), r).unwrap_err();
            assert!(!format!("{err:#}").contains("private-canary"));
        }
        let mut r = revision(Disposition::NeedsInformation, 1, refs(&input, 0));
        r.timestamp = "2026-11-03T09:00:00.100-03:00".into();
        let next = append(&input, &report, &report_anchor, &raw, &digest(&raw), r).unwrap();
        assert_eq!(next.revisions[1].timestamp, "2026-11-03T12:00:00.100Z");
    }

    #[test]
    fn canonical_predecessor_binds_every_saved_prefix() {
        let (input, report, report_anchor, case) = create_case();
        let raw = canonical_bytes(&case).unwrap();
        let mut next = append(
            &input,
            &report,
            &report_anchor,
            &raw,
            &digest(&raw),
            revision(Disposition::ClosedExplained, 1, refs(&input, 0)),
        )
        .unwrap();
        next.revisions[1].previous_snapshot_sha256 = Some("0".repeat(64));
        // Even recomputing this event digest cannot repair a wrong prefix anchor.
        next.revisions[1].event_sha256 =
            event_digest(&binding_digest(&next).unwrap(), &next.revisions[1]).unwrap();
        let bytes = canonical_bytes(&next).unwrap();
        assert!(verify(&input, &report, &report_anchor, &bytes, &digest(&bytes)).is_err());
    }

    #[test]
    fn revision_count_and_document_size_are_bounded() {
        let (input, report, anchor, mut case) = create_case();
        let alert = &transfers::analyze(&input).unwrap().alerts[0];
        for i in 1..MAX_REVISIONS {
            let mut r = revision(Disposition::NeedsInformation, 1, refs(&input, 0));
            r.timestamp = format!("2026-11-03T12:{:02}:{:02}Z", i / 60, i % 60);
            push_revision(&mut case, alert, r).unwrap();
        }
        let raw = canonical_bytes(&case).unwrap();
        assert!(verify(&input, &report, &anchor, &raw, &digest(&raw)).is_ok());
        assert!(append(
            &input,
            &report,
            &anchor,
            &raw,
            &digest(&raw),
            revision(Disposition::Open, 3, refs(&input, 0))
        )
        .is_err());
        let oversized = vec![b' '; MAX_CASE_BYTES + 1];
        assert!(verify(&input, &report, &anchor, &oversized, &digest(&oversized)).is_err());
    }

    #[test]
    fn empty_history_and_non_open_initial_state_are_rejected() {
        let (input, report, anchor, mut case) = create_case();
        assert!(create(
            &input,
            &report,
            &anchor,
            "case-1",
            0,
            revision(Disposition::ClosedExplained, 0, refs(&input, 0))
        )
        .is_err());
        case.revisions.clear();
        let bytes = canonical_bytes(&case).unwrap();
        assert!(verify(&input, &report, &anchor, &bytes, &digest(&bytes)).is_err());
    }
    #[test]
    fn first_case_time_must_not_precede_alert_evidence() {
        let (input, report, anchor) = fixture();
        let selected = &transfers::analyze(&input).unwrap().alerts[0];
        let mut r = revision(Disposition::Open, 0, refs(&input, 0));
        r.timestamp = "2026-01-01T00:00:00Z".into();
        assert!(create(&input, &report, &anchor, "case-1", 0, r.clone()).is_err());
        r.timestamp = selected.window_end.clone();
        let case = create(&input, &report, &anchor, "case-1", 0, r).unwrap();
        let bytes = canonical_bytes(&case).unwrap();
        assert!(verify(&input, &report, &anchor, &bytes, &digest(&bytes)).is_ok());
    }
}
