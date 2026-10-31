//! Minimal ECS-compatible export. Raw SQL, literals and identity fields are excluded.
use crate::model::{Finding, PgLog};
use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, Utc};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub fn timestamp(value: &str) -> Result<String> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Ok(parsed.to_rfc3339());
    }
    for format in [
        "%Y-%m-%d %H:%M:%S%.f%#z",
        "%Y-%m-%d %H:%M:%S%.f %#z",
        "%Y-%m-%d %H:%M:%S%.f %z",
    ] {
        if let Ok(parsed) = DateTime::parse_from_str(value, format) {
            return Ok(parsed.to_rfc3339());
        }
    }
    if let Some(naive) = value.strip_suffix(" UTC") {
        return Ok(
            NaiveDateTime::parse_from_str(naive, "%Y-%m-%d %H:%M:%S%.f")?
                .and_local_timezone(Utc)
                .single()
                .context("Invalid UTC timestamp")?
                .to_rfc3339(),
        );
    }
    anyhow::bail!("Unsupported timestamp timezone: configure PostgreSQL log_timezone=UTC")
}

pub fn alert(event: &PgLog, finding: &Finding, raw: &[u8]) -> Result<Value> {
    let hash = hex::encode(Sha256::digest(raw));
    let id = hex::encode(Sha256::digest(format!("{hash}:{}", finding.rule_id)));
    Ok(json!({
        "@timestamp": timestamp(&event.timestamp)?,
        "ecs":{"version":"8.17.0"},
        "event":{"kind":"alert","category":["database"],"type":["info"],
            "outcome": if finding.outcome == "failure_observed" { "failure" } else { "unknown" },
            "module":"postgres_audit_guard","dataset":"postgres_audit_guard.postgresql",
            "id":id,"hash":hash,"action":finding.rule_id},
        "rule":{"id":finding.rule_id,"name":finding.title,"version":"0.1.0","license":"MIT"},
        "postgres_audit_guard":{"schema":"ecs-export/v1","severity":finding.severity,
            "sqlstate":event.state_code,"raw_sql_included":false,
            "scope":"rule signal; no confirmed compromise or transaction-success inference"}
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn timestamp_requires_known_offset_and_preserves_instant() {
        assert_eq!(
            timestamp("2026-10-31 12:03:04.123 UTC").unwrap(),
            "2026-10-31T12:03:04.123+00:00"
        );
        assert!(timestamp("2026-10-31 12:03:04 CST").is_err());
        assert_eq!(
            timestamp("2026-10-31 18:22:47.966 -03").unwrap(),
            "2026-10-31T18:22:47.966-03:00"
        );
    }
    #[test]
    fn exports_no_raw_literals_or_identity_and_never_assumes_success() {
        let e = PgLog {
            timestamp: "2026-10-31T12:00:00Z".into(),
            user: "private-person".into(),
            message: "COPY password_secret TO STDOUT".into(),
            ..Default::default()
        };
        let f = Finding {
            rule_id: "DB004".into(),
            severity: "high".into(),
            title: "Export observed".into(),
            detail: "private SQL excluded".into(),
            outcome: "unknown".into(),
        };
        let out = alert(&e, &f, e.message.as_bytes()).unwrap();
        let text = out.to_string();
        assert!(!text.contains("password_secret") && !text.contains("private-person"));
        assert_eq!(out["event"]["outcome"], "unknown");
        assert_eq!(out, alert(&e, &f, e.message.as_bytes()).unwrap());
    }
}
