//! Bounded, deterministic screening of synthetic transfer records.
//!
//! These rules match temporal/amount patterns for human investigation. They do
//! not identify criminal intent, establish beneficial ownership, trace fungible
//! funds, or implement a jurisdiction's legal reporting thresholds.
use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RECORDS: usize = 20_000;
pub const MAX_WORK_UNITS: u64 = 5_000_000;
pub const MAX_ALERTS: usize = 1_000;
pub const MAX_EVIDENCE_REFERENCES: usize = 50_000;
pub const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;
const WINDOW_SECONDS: i64 = 3_600;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InputTransfer {
    id: String,
    timestamp: String,
    from_account: String,
    to_account: String,
    amount_minor: u64,
    currency: String,
}

#[derive(Debug)]
struct Transfer {
    id: String,
    timestamp: DateTime<Utc>,
    from_account: String,
    to_account: String,
    amount_minor: u64,
    currency: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Report {
    pub schema: String,
    pub input_sha256: String,
    pub input_records: usize,
    pub policy: Policy,
    pub alerts: Vec<Alert>,
    pub work_units: u64,
    pub limitations: Vec<String>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Policy {
    pub window_seconds: i64,
    pub fan_in_min_senders: usize,
    pub flow_ratio_min_percent: u32,
    pub circular_ratio_max_percent: u32,
    pub strictly_ordered_phases: bool,
    pub max_input_bytes: usize,
    pub max_records: usize,
    pub max_work_units: u64,
    pub max_alerts: usize,
    pub max_evidence_references: usize,
    pub max_report_bytes: usize,
    pub threshold_basis: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct Alert {
    pub rule_id: String,
    pub title: String,
    pub currency: String,
    pub accounts: Vec<String>,
    pub source_record_ids: Vec<String>,
    pub window_start: String,
    pub window_end: String,
    pub evidence: Evidence,
    pub interpretation: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Evidence {
    FanIn {
        distinct_senders: usize,
        incoming_records: usize,
        outgoing_records: usize,
        incoming_total_minor: String,
        outgoing_total_minor: String,
        outgoing_times_100: String,
        incoming_times_80: String,
        collection_ends_at: String,
    },
    Circular {
        amounts_minor: [String; 3],
        comparisons: [RatioComparison; 2],
    },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct RatioComparison {
    pub previous_times_80: String,
    pub next_times_100: String,
    pub previous_times_100: String,
}

#[derive(Clone, Copy)]
struct Limits {
    work: u64,
    alerts: usize,
    references: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            work: MAX_WORK_UNITS,
            alerts: MAX_ALERTS,
            references: MAX_EVIDENCE_REFERENCES,
        }
    }
}
struct Budget {
    limits: Limits,
    work: u64,
    references: usize,
    alerts: usize,
}
impl Budget {
    fn new(limits: Limits) -> Self {
        Self {
            limits,
            work: 0,
            references: 0,
            alerts: 0,
        }
    }
    fn inspect(&mut self) -> Result<()> {
        self.work += 1;
        if self.work > self.limits.work {
            bail!("transfer analysis work limit exceeded; no complete report produced");
        }
        Ok(())
    }
    fn reserve_alert(&mut self, references: usize) -> Result<()> {
        let total = self
            .references
            .checked_add(references)
            .ok_or_else(|| anyhow!("evidence reference count overflow"))?;
        if self.alerts >= self.limits.alerts {
            bail!("transfer alert limit exceeded; no complete report produced");
        }
        if total > self.limits.references {
            bail!("transfer evidence reference limit exceeded; no complete report produced");
        }
        self.alerts += 1;
        self.references = total;
        Ok(())
    }
}

#[derive(Default)]
struct AccountIndex {
    incoming: Vec<usize>,
    outgoing: Vec<usize>,
}
type Index<'a> = BTreeMap<(&'a str, &'a str), AccountIndex>;

/// Analyze a complete bounded NDJSON extract. A rejected input or exceeded
/// analysis/output budget returns an error, never a partial or clean report.
pub fn analyze(raw: &[u8]) -> Result<Report> {
    analyze_with_limits(raw, Limits::default())
}

fn analyze_with_limits(raw: &[u8], limits: Limits) -> Result<Report> {
    let records = parse(raw)?;
    let mut index = Index::new();
    for (i, transfer) in records.iter().enumerate() {
        index
            .entry((&transfer.currency, &transfer.from_account))
            .or_default()
            .outgoing
            .push(i);
        index
            .entry((&transfer.currency, &transfer.to_account))
            .or_default()
            .incoming
            .push(i);
    }
    let mut budget = Budget::new(limits);
    let mut alerts = Vec::new();
    fan_in(&records, &index, &mut budget, &mut alerts)?;
    circular(&records, &index, &mut budget, &mut alerts)?;
    // Source IDs are validated unique, and both rules place their earliest
    // source first. Compare typed instants: formatted RFC3339 strings with
    // optional fractions (or an offset crossing the year boundary) do not
    // necessarily sort chronologically.
    let instants: BTreeMap<_, _> = records
        .iter()
        .map(|record| (record.id.as_str(), record.timestamp))
        .collect();
    alerts.sort_by(|a, b| {
        (
            instants[a.source_record_ids[0].as_str()],
            &a.rule_id,
            &a.currency,
            &a.source_record_ids,
        )
            .cmp(&(
                instants[b.source_record_ids[0].as_str()],
                &b.rule_id,
                &b.currency,
                &b.source_record_ids,
            ))
    });
    let report = Report {
        schema: "transfer-triage/v1".into(),
        input_sha256: hex::encode(Sha256::digest(raw)),
        input_records: records.len(),
        policy: Policy {
            window_seconds: WINDOW_SECONDS,
            fan_in_min_senders: 3,
            flow_ratio_min_percent: 80,
            circular_ratio_max_percent: 100,
            strictly_ordered_phases: true,
            max_input_bytes: MAX_INPUT_BYTES,
            max_records: MAX_RECORDS,
            max_work_units: limits.work,
            max_alerts: limits.alerts,
            max_evidence_references: limits.references,
            max_report_bytes: MAX_REPORT_BYTES,
            threshold_basis: "Arbitrary synthetic-lab policy, not a legal or regulatory threshold.".into(),
        },
        alerts,
        work_units: budget.work,
        limitations: vec![
            "Scenario screening only: no inference of fraud, money laundering, criminal intent, ownership, sanctions status or legal breach.".into(),
            "TF001 uses the maximal retrospective 60-minute inflow window at each distinct incoming instant, followed by the earliest qualifying outgoing prefix ending within 60 minutes of its oldest included inflow; it does not search every possible subset.".into(),
            "Windows can overlap and reuse records. Amount relationships do not trace fungible funds or establish that the same money returned.".into(),
            "Legitimate merchant settlements, treasury operations and other ordinary activity can match. A no-alert report does not establish that activity is safe.".into(),
            "Input order is normalized by timestamp instant then ID. Equal timestamps cannot establish a subsequent phase or leg. Currency codes are syntax-checked only; no exchange conversion or registry lookup is performed.".into(),
            "Only the supplied extract is evaluated. Missing, delayed, reversed or unrecorded transfers, account ownership and external context are not inferred. Monetary evidence is exact decimal strings in integer minor units.".into(),
        ],
    };
    // The reference cap bounds allocations before serialization. This independent
    // final cap also protects against future expansion of the report schema.
    if serde_json::to_vec(&report)?.len() > MAX_REPORT_BYTES {
        bail!("transfer report size limit exceeded; no complete report produced");
    }
    Ok(report)
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

fn parse(raw: &[u8]) -> Result<Vec<Transfer>> {
    if raw.len() > MAX_INPUT_BYTES {
        bail!("transfer input exceeds 16 MiB limit");
    }
    let input = std::str::from_utf8(raw).map_err(|_| anyhow!("transfer input must be UTF-8"))?;
    let mut records = Vec::new();
    let mut ids = BTreeSet::new();
    for (line_index, line) in input.lines().enumerate() {
        let line_number = line_index + 1;
        if line_number > MAX_RECORDS {
            bail!("transfer input exceeds 20000 record limit");
        }
        if line.trim().is_empty() {
            bail!("blank transfer record at line {line_number}");
        }
        // Do not echo source rows or serde errors, which may contain account data.
        let value: InputTransfer = serde_json::from_str(line)
            .map_err(|_| anyhow!("invalid transfer schema at line {line_number}"))?;
        if !valid_identifier(&value.id)
            || !valid_identifier(&value.from_account)
            || !valid_identifier(&value.to_account)
        {
            bail!("invalid transfer identifier at line {line_number}; expected 1..64 ASCII letters, digits, underscore, dash, dot or colon");
        }
        if !ids.insert(value.id.clone()) {
            bail!("duplicate transfer ID at line {line_number}");
        }
        if value.from_account == value.to_account {
            bail!("self-transfer is unsupported at line {line_number}");
        }
        if value.amount_minor == 0 {
            bail!("amount_minor must be positive at line {line_number}");
        }
        if value.currency.len() != 3 || !value.currency.bytes().all(|b| b.is_ascii_uppercase()) {
            bail!("currency must have three uppercase ASCII letters at line {line_number}");
        }
        let timestamp = DateTime::parse_from_rfc3339(&value.timestamp)
            .map_err(|_| anyhow!("invalid RFC3339 timestamp at line {line_number}"))?
            .with_timezone(&Utc);
        records.push(Transfer {
            id: value.id,
            timestamp,
            from_account: value.from_account,
            to_account: value.to_account,
            amount_minor: value.amount_minor,
            currency: value.currency,
        });
    }
    if records.is_empty() {
        bail!("transfer input must contain at least one record");
    }
    records.sort_by(|a, b| (&a.timestamp, &a.id).cmp(&(&b.timestamp, &b.id)));
    Ok(records)
}

fn stamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}
fn sum_add(total: u128, amount: u64) -> Result<u128> {
    total
        .checked_add(u128::from(amount))
        .context("transfer amount sum overflow")
}
fn product(value: u128, multiplier: u128) -> Result<u128> {
    value
        .checked_mul(multiplier)
        .context("transfer ratio product overflow")
}
fn window_end(start: DateTime<Utc>) -> Result<DateTime<Utc>> {
    start
        .checked_add_signed(Duration::seconds(WINDOW_SECONDS))
        .context("timestamp window overflow")
}

fn fan_in(
    records: &[Transfer],
    index: &Index<'_>,
    budget: &mut Budget,
    alerts: &mut Vec<Alert>,
) -> Result<()> {
    for ((currency, _account), group) in index {
        if group.incoming.len() < 3 || group.outgoing.is_empty() {
            continue;
        }
        for (position, &pivot_index) in group.incoming.iter().enumerate() {
            budget.inspect()?;
            let pivot = records[pivot_index].timestamp;
            // All receipts sharing the collection-ending instant belong to one phase.
            if position + 1 < group.incoming.len()
                && records[group.incoming[position + 1]].timestamp == pivot
            {
                continue;
            }
            let lower = pivot
                .checked_sub_signed(Duration::seconds(WINDOW_SECONDS))
                .context("timestamp window overflow")?;
            let start =
                group.incoming[..=position].partition_point(|&i| records[i].timestamp < lower);
            let incoming = &group.incoming[start..=position];
            let mut senders = BTreeSet::new();
            let mut incoming_total = 0_u128;
            for &i in incoming {
                budget.inspect()?;
                senders.insert(records[i].from_account.as_str());
                incoming_total = sum_add(incoming_total, records[i].amount_minor)?;
            }
            if senders.len() < 3 {
                continue;
            }
            let oldest = records[incoming[0]].timestamp;
            let deadline = window_end(oldest)?;
            let first = group
                .outgoing
                .partition_point(|&i| records[i].timestamp <= pivot);
            let last = group
                .outgoing
                .partition_point(|&i| records[i].timestamp <= deadline);
            if first >= last {
                continue;
            }
            let mut outgoing_total = 0_u128;
            for (offset, &out_index) in group.outgoing[first..last].iter().enumerate() {
                budget.inspect()?;
                outgoing_total = sum_add(outgoing_total, records[out_index].amount_minor)?;
                if product(outgoing_total, 100)? < product(incoming_total, 80)? {
                    continue;
                }
                let outgoing = &group.outgoing[first..=first + offset];
                let sources: Vec<_> = incoming.iter().chain(outgoing).copied().collect();
                let accounts = account_names(records, &sources);
                budget.reserve_alert(sources.len() + accounts.len())?;
                alerts.push(Alert {
                    rule_id: "TF001".into(), title: "Multiple senders followed by rapid aggregate outflow".into(),
                    currency: (*currency).into(), accounts,
                    source_record_ids: sources.iter().map(|&i| records[i].id.clone()).collect(),
                    window_start: stamp(oldest), window_end: stamp(records[out_index].timestamp),
                    evidence: Evidence::FanIn {
                        distinct_senders: senders.len(), incoming_records: incoming.len(), outgoing_records: outgoing.len(),
                        incoming_total_minor: incoming_total.to_string(), outgoing_total_minor: outgoing_total.to_string(),
                        outgoing_times_100: product(outgoing_total, 100)?.to_string(), incoming_times_80: product(incoming_total, 80)?.to_string(),
                        collection_ends_at: stamp(pivot),
                    },
                    interpretation: "Review this temporal concentration and redistribution pattern. Legitimate settlement can produce it; these records do not establish intent or trace specific funds.".into(),
                });
                break;
            }
        }
    }
    Ok(())
}

fn account_names(records: &[Transfer], sources: &[usize]) -> Vec<String> {
    let mut accounts = BTreeSet::new();
    for &i in sources {
        accounts.insert(records[i].from_account.as_str());
        accounts.insert(records[i].to_account.as_str());
    }
    accounts.into_iter().map(str::to_owned).collect()
}
fn qualifying_ratio(previous: u64, next: u64) -> bool {
    // u64*100 is always representable in u128.
    let scaled = u128::from(next) * 100;
    scaled >= u128::from(previous) * 80 && scaled <= u128::from(previous) * 100
}
fn ratio_evidence(previous: u64, next: u64) -> RatioComparison {
    RatioComparison {
        previous_times_80: (u128::from(previous) * 80).to_string(),
        next_times_100: (u128::from(next) * 100).to_string(),
        previous_times_100: (u128::from(previous) * 100).to_string(),
    }
}
fn subsequent<'a>(
    records: &[Transfer],
    outgoing: &'a [usize],
    after: DateTime<Utc>,
    deadline: DateTime<Utc>,
) -> &'a [usize] {
    let start = outgoing.partition_point(|&i| records[i].timestamp <= after);
    let end = outgoing.partition_point(|&i| records[i].timestamp <= deadline);
    if start >= end {
        &[]
    } else {
        &outgoing[start..end]
    }
}
fn circular(
    records: &[Transfer],
    index: &Index<'_>,
    budget: &mut Budget,
    alerts: &mut Vec<Alert>,
) -> Result<()> {
    for (first_index, first) in records.iter().enumerate() {
        budget.inspect()?;
        let deadline = window_end(first.timestamp)?;
        let second_group = &index[&(first.currency.as_str(), first.to_account.as_str())];
        for &second_index in subsequent(records, &second_group.outgoing, first.timestamp, deadline)
        {
            budget.inspect()?;
            let second = &records[second_index];
            if second.to_account == first.from_account
                || !qualifying_ratio(first.amount_minor, second.amount_minor)
            {
                continue;
            }
            let third_group = &index[&(first.currency.as_str(), second.to_account.as_str())];
            for &third_index in
                subsequent(records, &third_group.outgoing, second.timestamp, deadline)
            {
                budget.inspect()?;
                let third = &records[third_index];
                if third.to_account != first.from_account
                    || !qualifying_ratio(second.amount_minor, third.amount_minor)
                {
                    continue;
                }
                budget.reserve_alert(6)?;
                alerts.push(Alert {
                    rule_id: "TF002".into(), title: "Three-account ordered circular transfer pattern".into(),
                    currency: first.currency.clone(),
                    accounts: vec![first.from_account.clone(), first.to_account.clone(), second.to_account.clone()],
                    source_record_ids: [first_index, second_index, third_index].iter().map(|&i| records[i].id.clone()).collect(),
                    window_start: stamp(first.timestamp), window_end: stamp(third.timestamp),
                    evidence: Evidence::Circular {
                        amounts_minor: [first.amount_minor.to_string(), second.amount_minor.to_string(), third.amount_minor.to_string()],
                        comparisons: [ratio_evidence(first.amount_minor, second.amount_minor), ratio_evidence(second.amount_minor, third.amount_minor)],
                    },
                    interpretation: "Review the ordered three-account amount pattern. A matching cycle does not establish that the same funds returned, common ownership or criminal intent.".into(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn row(id: &str, minute: u32, from: &str, to: &str, amount: u64, currency: &str) -> Value {
        let timestamp = format!("2026-01-01T{:02}:{:02}:00Z", minute / 60, minute % 60);
        json!({"id":id,"timestamp":timestamp,"from_account":from,"to_account":to,"amount_minor":amount,"currency":currency})
    }
    fn encode(rows: &[Value]) -> Vec<u8> {
        rows.iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n")
            .into_bytes()
    }
    fn cycle() -> Vec<Value> {
        vec![
            row("c1", 0, "A", "B", 100_000, "USD"),
            row("c2", 30, "B", "C", 80_000, "USD"),
            row("c3", 60, "C", "A", 64_000, "USD"),
        ]
    }
    fn fan() -> Vec<Value> {
        vec![
            row("f1", 0, "A", "M", 30_000, "EUR"),
            row("f2", 5, "B", "M", 30_000, "EUR"),
            row("f3", 10, "C", "M", 40_000, "EUR"),
            row("f4", 20, "M", "D", 50_000, "EUR"),
            row("f5", 30, "M", "E", 30_000, "EUR"),
        ]
    }
    #[test]
    fn fan_in_uses_aggregate_outflow_and_exact_evidence() {
        let report = analyze(&encode(&fan())).unwrap();
        assert_eq!(report.alerts.len(), 1);
        let a = &report.alerts[0];
        assert_eq!(a.rule_id, "TF001");
        assert_eq!(a.source_record_ids, ["f1", "f2", "f3", "f4", "f5"]);
        match &a.evidence {
            Evidence::FanIn {
                incoming_total_minor,
                outgoing_total_minor,
                incoming_times_80,
                outgoing_times_100,
                ..
            } => {
                assert_eq!(incoming_total_minor, "100000");
                assert_eq!(outgoing_total_minor, "80000");
                assert_eq!(incoming_times_80, outgoing_times_100);
            }
            _ => panic!("wrong evidence"),
        }
    }
    #[test]
    fn legitimate_merchant_pattern_also_alerts_without_intent_claim() {
        let mut rows = fan();
        rows[3]["to_account"] = json!("merchant_settlement");
        let report = analyze(&encode(&rows)).unwrap();
        assert_eq!(report.alerts.len(), 1);
        assert!(report.alerts[0]
            .interpretation
            .contains("Legitimate settlement"));
    }
    #[test]
    fn circular_boundaries_are_inclusive_and_integer_exact() {
        let report = analyze(&encode(&cycle())).unwrap();
        assert_eq!(report.alerts.len(), 1);
        assert_eq!(report.alerts[0].rule_id, "TF002");
        assert_eq!(report.alerts[0].source_record_ids, ["c1", "c2", "c3"]);
        match &report.alerts[0].evidence {
            Evidence::Circular { comparisons, .. } => assert_eq!(
                comparisons[0].previous_times_80,
                comparisons[0].next_times_100
            ),
            _ => panic!("wrong evidence"),
        }
    }
    #[test]
    fn benign_timing_currency_and_amount_controls_do_not_alert() {
        let benign = vec![
            row("salary", 0, "employer", "person", 500_000, "USD"),
            row("rent", 10, "person", "landlord", 200_000, "USD"),
            row("shopping", 20, "person", "shop", 10_000, "USD"),
        ];
        assert!(analyze(&encode(&benign)).unwrap().alerts.is_empty());
        for (field, value) in [
            ("currency", json!("EUR")),
            ("timestamp", json!("2026-01-01T01:00:01Z")),
            ("amount_minor", json!(63_999)),
        ] {
            let mut rows = cycle();
            rows[2][field] = value;
            assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        }
        let mut rows = cycle();
        rows[1]["amount_minor"] = json!(100_001);
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = fan();
        rows[4]["amount_minor"] = json!(29_999);
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = fan();
        rows[4]["currency"] = json!("USD");
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = fan();
        rows[4]["timestamp"] = json!("2026-01-01T01:00:01Z");
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
    }
    #[test]
    fn distinct_senders_and_strict_phases_are_required() {
        let mut rows = fan();
        rows[2]["from_account"] = json!("B");
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = cycle();
        rows[1]["timestamp"] = rows[0]["timestamp"].clone();
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = fan();
        rows[3]["timestamp"] = rows[2]["timestamp"].clone();
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = cycle();
        rows[1]["to_account"] = json!("A");
        rows[2]["from_account"] = json!("A");
        rows[2]["to_account"] = json!("B");
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
    }
    #[test]
    fn sorting_and_offsets_preserve_semantics_and_reproducibility() {
        let first = analyze(&encode(&cycle())).unwrap();
        let mut rows = cycle();
        rows[1]["timestamp"] = json!("2025-12-31T21:30:00-03:00");
        rows.reverse();
        let raw = encode(&rows);
        let reversed = analyze(&raw).unwrap();
        assert_eq!(first.alerts, reversed.alerts);
        assert_eq!(first.work_units, reversed.work_units);
        assert_ne!(first.input_sha256, reversed.input_sha256);
        assert_eq!(
            serde_json::to_vec(&reversed).unwrap(),
            serde_json::to_vec(&analyze(&raw).unwrap()).unwrap()
        );
    }
    #[test]
    fn amounts_above_u64_aggregate_without_wraparound() {
        let mut rows = fan();
        for r in &mut rows[..3] {
            r["amount_minor"] = json!(u64::MAX);
        }
        rows[3]["amount_minor"] = json!(u64::MAX);
        rows[4]["amount_minor"] = json!(u64::MAX);
        rows.push(row("f6", 40, "M", "F", u64::MAX, "EUR"));
        let report = analyze(&encode(&rows)).unwrap();
        match &report.alerts[0].evidence {
            Evidence::FanIn {
                incoming_total_minor,
                outgoing_total_minor,
                ..
            } => {
                let expected = (u128::from(u64::MAX) * 3).to_string();
                assert_eq!(incoming_total_minor, &expected);
                assert_eq!(outgoing_total_minor, &expected);
            }
            _ => panic!("wrong evidence"),
        }
        assert!(qualifying_ratio(u64::MAX, u64::MAX));
        assert!(sum_add(u128::MAX, 1).is_err());
        assert!(product(u128::MAX, 100).is_err());
    }
    #[test]
    fn strict_schema_validation_rejects_invalid_inputs_without_echoing_data() {
        let valid = cycle()[0].clone();
        for (field, value) in [
            ("unknown", json!("private_secret")),
            ("amount_minor", json!(0)),
            ("amount_minor", json!(1.5)),
            ("amount_minor", json!(-1)),
            ("currency", json!("usd")),
            ("id", json!("private secret")),
            ("from_account", json!("é")),
            ("id", json!("x".repeat(65))),
            ("timestamp", json!("private_secret")),
            ("to_account", json!("A")),
        ] {
            let mut row = valid.clone();
            row[field] = value;
            let error = analyze(&encode(&[row])).unwrap_err().to_string();
            assert!(!error.contains("private_secret"));
        }
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove("currency");
        assert!(analyze(&encode(&[missing])).is_err());
        assert!(analyze(&[0xff]).is_err());
        assert!(analyze(b"").is_err());
        assert!(analyze(b"\n").is_err());
        let mut raw = encode(&[valid]);
        raw.extend_from_slice(b"\n\n");
        assert!(analyze(&raw).is_err());
        assert!(analyze(b"{\"id\":\"a\",\"id\":\"b\"}").is_err());
        assert!(analyze(b"{\"id\":\"x\",\"timestamp\":\"2026-01-01T00:00:00Z\",\"from_account\":\"A\",\"to_account\":\"B\",\"amount_minor\":18446744073709551616,\"currency\":\"USD\"}").is_err());
    }
    #[test]
    fn duplicate_ids_and_hard_input_caps_are_rejected() {
        let one = cycle()[0].clone();
        assert!(analyze(&encode(&[one.clone(), one]))
            .unwrap_err()
            .to_string()
            .contains("duplicate"));
        assert!(analyze(&vec![b' '; MAX_INPUT_BYTES + 1])
            .unwrap_err()
            .to_string()
            .contains("16 MiB"));
        let rows: Vec<_> = (0..=MAX_RECORDS)
            .map(|n| row(&format!("r{n}"), 0, "A", "B", 1, "USD"))
            .collect();
        assert!(analyze(&encode(&rows))
            .unwrap_err()
            .to_string()
            .contains("20000"));
    }
    #[test]
    fn resource_caps_return_errors_not_truncated_reports() {
        let raw = encode(&cycle());
        for limits in [
            Limits {
                work: 1,
                ..Limits::default()
            },
            Limits {
                alerts: 0,
                ..Limits::default()
            },
            Limits {
                references: 5,
                ..Limits::default()
            },
        ] {
            assert!(analyze_with_limits(&raw, limits)
                .unwrap_err()
                .to_string()
                .contains("limit exceeded"));
        }
        let accepted = analyze_with_limits(
            &raw,
            Limits {
                references: 6,
                alerts: 1,
                ..Limits::default()
            },
        )
        .unwrap();
        assert_eq!(accepted.alerts.len(), 1);
    }
    #[test]
    fn collection_window_begins_at_actual_oldest_receipt() {
        let mut rows = fan();
        rows[0]["timestamp"] = json!("2025-12-31T23:00:00Z");
        assert!(analyze(&encode(&rows)).unwrap().alerts.is_empty());
        let mut rows = fan();
        rows[4]["timestamp"] = json!("2026-01-01T01:00:00Z");
        assert_eq!(analyze(&encode(&rows)).unwrap().alerts.len(), 1);
    }
    #[test]
    fn equal_time_receipts_form_one_collection_phase() {
        let mut rows = fan();
        for row in &mut rows[..3] {
            row["timestamp"] = json!("2026-01-01T00:00:00Z");
        }
        let report = analyze(&encode(&rows)).unwrap();
        assert_eq!(report.alerts.len(), 1);
        assert_eq!(report.alerts[0].source_record_ids.len(), 5);
    }
    #[test]
    fn alert_order_uses_instants_including_fractional_seconds() {
        let mut rows = cycle();
        let mut later = cycle();
        for record in &mut later {
            record["id"] = json!(format!("later_{}", record["id"].as_str().unwrap()));
            record["from_account"] = json!(format!(
                "later_{}",
                record["from_account"].as_str().unwrap()
            ));
            record["to_account"] =
                json!(format!("later_{}", record["to_account"].as_str().unwrap()));
        }
        later[0]["timestamp"] = json!("2026-01-01T00:00:00.100Z");
        rows.extend(later);
        let report = analyze(&encode(&rows)).unwrap();
        assert_eq!(report.alerts.len(), 2);
        assert_eq!(report.alerts[0].source_record_ids[0], "c1");
        assert_eq!(report.alerts[1].source_record_ids[0], "later_c1");
    }
    #[test]
    fn actual_default_work_cap_rejects_dense_windows() {
        let mut rows: Vec<_> = (0..3_200)
            .map(|n| {
                let mut record = row(&format!("dense{n}"), 0, "A", "M", 1, "USD");
                record["timestamp"] = json!(format!(
                    "2026-01-01T00:00:{:02}.{:03}Z",
                    n / 1_000,
                    n % 1_000
                ));
                record
            })
            .collect();
        rows.push(row("out", 1, "M", "B", 5_000, "USD"));
        assert!(analyze(&encode(&rows))
            .unwrap_err()
            .to_string()
            .contains("work limit"));
    }
    #[test]
    fn actual_default_alert_and_reference_caps_are_enforced() {
        let mut rows = Vec::new();
        for n in 0..=MAX_ALERTS {
            for mut record in cycle() {
                for field in ["id", "from_account", "to_account"] {
                    record[field] = json!(format!("{n}_{}", record[field].as_str().unwrap()));
                }
                rows.push(record);
            }
        }
        assert!(analyze(&encode(&rows))
            .unwrap_err()
            .to_string()
            .contains("alert limit"));
        let mut rows: Vec<_> = (0..500)
            .map(|n| {
                let mut record = row(&format!("in{n}"), 0, &format!("sender{n}"), "M", 1, "USD");
                record["timestamp"] = json!(format!("2026-01-01T00:00:00.{n:03}Z"));
                record
            })
            .collect();
        rows.push(row("out", 1, "M", "B", 500, "USD"));
        assert!(analyze(&encode(&rows))
            .unwrap_err()
            .to_string()
            .contains("reference limit"));
    }
}
