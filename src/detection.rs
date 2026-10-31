//! Bounded lexical/structural triage of PostgreSQL log statements.
//!
//! This is deliberately not a SQL authorization engine or full semantic analyzer.
//! String literals and comments never become commands. Object matching uses a
//! documented basename policy, not catalog resolution (CTE aliases may match).
//! Ordinary log_statement records precede execution. Duration records also do not
//! establish transaction commit or authorized intent; a finding never proves success.
use crate::model::{Finding, PgLog};
use sqlparser::{
    dialect::PostgreSqlDialect,
    tokenizer::{Token, Tokenizer},
};
use std::collections::BTreeMap;

pub const MAX_SQL_BYTES: usize = 65_536;
pub const MAX_TOKENS: usize = 8_192;
const MAX_DEPTH: usize = 32;

/// Basenames in this original banking lab. Deployments must review this policy.
pub const SENSITIVE_TABLES: &[&str] = &[
    "accounts",
    "bank_accounts",
    "payments",
    "transactions",
    "customers",
    "beneficiaries",
    "cards",
];
const PRIVILEGED_ROLES: &[&str] = &[
    "pg_read_all_data",
    "pg_write_all_data",
    "pg_read_server_files",
    "pg_write_server_files",
    "pg_execute_server_program",
    "pg_signal_backend",
    "pg_checkpoint",
];

fn kw(t: Option<&Token>, value: &str) -> bool {
    matches!(t, Some(Token::Word(w)) if w.quote_style.is_none() && w.value.eq_ignore_ascii_case(value))
}

fn ident(t: &Token) -> Option<String> {
    match t {
        Token::Word(w) => Some(if w.quote_style.is_some() {
            w.value.clone()
        } else {
            w.value.to_ascii_lowercase()
        }),
        _ => None,
    }
}

/// Read a possibly schema-qualified identifier, retaining its last component.
fn object_name(tokens: &[Token], start: usize) -> Option<String> {
    let mut name = ident(tokens.get(start)?)?;
    let mut i = start + 1;
    while matches!(tokens.get(i), Some(Token::Period)) {
        name = ident(tokens.get(i + 1)?)?;
        i += 2;
    }
    Some(name)
}

fn sensitive(name: Option<String>) -> bool {
    name.is_some_and(|v| SENSITIVE_TABLES.contains(&v.as_str()))
}

fn scalar(t: Option<&Token>) -> Option<String> {
    match t? {
        Token::SingleQuotedString(v) | Token::EscapedStringLiteral(v) => {
            Some(v.to_ascii_lowercase())
        }
        Token::Number(v, _) => Some(v.clone()),
        t => ident(t),
    }
}

fn outcome(event: &PgLog) -> String {
    if matches!(event.error_severity.as_str(), "ERROR" | "FATAL" | "PANIC") {
        "failure_observed".into()
    } else {
        "unknown".into()
    }
}

fn add(
    out: &mut BTreeMap<&'static str, Finding>,
    event: &PgLog,
    id: &'static str,
    severity: &str,
    title: &str,
    detail: &str,
) {
    out.entry(id).or_insert_with(|| Finding {
        rule_id: id.into(),
        severity: severity.into(),
        title: title.into(),
        detail: detail.into(),
        outcome: outcome(event),
    });
}

fn coverage(out: &mut BTreeMap<&'static str, Finding>, event: &PgLog, detail: &str) {
    add(
        out,
        event,
        "DB900",
        "warning",
        "SQL analysis coverage limitation",
        detail,
    );
}

fn statement_text(event: &PgLog) -> Option<&str> {
    if let Some(sql) = event.statement.as_deref().filter(|s| !s.trim().is_empty()) {
        return Some(sql);
    }
    let mut message = event.message.as_str();
    if let Some(rest) = message.strip_prefix("duration: ") {
        let (duration, tail) = rest.split_once(" ms  ")?;
        // Accept only the native decimal millisecond prefix, never search for
        // a statement substring inside arbitrary server/application messages.
        if duration.len() > 32
            || !duration.bytes().all(|b| b.is_ascii_digit() || b == b'.')
            || !duration.parse::<f64>().ok().is_some_and(f64::is_finite)
        {
            return None;
        }
        message = tail;
    }
    if let Some(sql) = message.strip_prefix("statement: ") {
        return Some(sql);
    }
    // PostgreSQL extended-query execution logging. Ambiguous exotic prepared
    // statement names remain a coverage limitation, not a complete protocol parser.
    message
        .strip_prefix("execute ")
        .and_then(|s| s.split_once(": ").map(|(_, sql)| sql))
}

/// Recognize relation positions at each SELECT's own parenthesis depth. This
/// avoids confusing SUBSTRING/EXTRACT/TRIM's expression FROM with a table FROM.
/// It remains a lexical policy: aliases, CTE resolution and custom grammar are
/// not resolved against PostgreSQL's catalog.
fn sensitive_query_relation(tokens: &[Token]) -> bool {
    // 0: no SELECT, 1: SELECT list, 2: FROM/JOIN list, 3: later clauses.
    let mut phases = vec![0u8];
    for (i, token) in tokens.iter().enumerate() {
        match token {
            Token::LParen => {
                phases.push(0);
                continue;
            }
            Token::RParen => {
                phases.pop();
                continue;
            }
            _ => {}
        }
        let Some(phase) = phases.last_mut() else {
            return false;
        };
        if kw(Some(token), "SELECT") {
            *phase = 1;
            continue;
        }
        if [
            "WHERE",
            "GROUP",
            "HAVING",
            "WINDOW",
            "ORDER",
            "LIMIT",
            "OFFSET",
            "FOR",
            "UNION",
            "INTERSECT",
            "EXCEPT",
        ]
        .iter()
        .any(|w| kw(Some(token), w))
        {
            *phase = 3;
            continue;
        }
        let from = *phase == 1
            && kw(Some(token), "FROM")
            && !kw(i.checked_sub(1).and_then(|p| tokens.get(p)), "DISTINCT");
        let join_or_comma =
            *phase == 2 && (kw(Some(token), "JOIN") || matches!(token, Token::Comma));
        if from {
            *phase = 2;
        }
        if (from || join_or_comma) && sensitive(object_name(tokens, i + 1)) {
            return true;
        }
    }
    false
}

fn logging_disabled(tokens: &[Token]) -> bool {
    for (i, t) in tokens.iter().enumerate() {
        if !kw(Some(t), "SET") {
            continue;
        }
        let mut key = i + 1;
        if kw(tokens.get(key), "LOCAL") || kw(tokens.get(key), "SESSION") {
            key += 1;
        }
        let Some(mut name) = tokens.get(key).and_then(ident) else {
            continue;
        };
        let mut separator = key + 1;
        if matches!(tokens.get(separator), Some(Token::Period)) {
            let Some(part) = tokens.get(separator + 1).and_then(ident) else {
                continue;
            };
            name.push('.');
            name.push_str(&part);
            separator += 2;
        }
        if !matches!(tokens.get(separator), Some(Token::Eq)) && !kw(tokens.get(separator), "TO") {
            continue;
        }
        let value_index = separator + 1;
        let mut value = scalar(tokens.get(value_index));
        if matches!(tokens.get(value_index), Some(Token::Minus)) {
            value = scalar(tokens.get(value_index + 1)).map(|v| format!("-{v}"));
        }
        if disabled_value(&name, value.as_deref()) {
            return true;
        }
    }
    // Explicit literal set_config calls; computed arguments are not evaluated.
    tokens.windows(6).any(|w| {
        ident(&w[0]).as_deref() == Some("set_config")
            && matches!(w[1], Token::LParen)
            && matches!(w[3], Token::Comma)
            && disabled_value(
                scalar(Some(&w[2])).as_deref().unwrap_or(""),
                scalar(Some(&w[4])).as_deref(),
            )
    })
}

fn disabled_value(name: &str, value: Option<&str>) -> bool {
    match name {
        "log_statement" | "pgaudit.log" => value == Some("none"),
        "log_connections" | "log_disconnections" => matches!(value, Some("off" | "false" | "0")),
        "log_min_duration_statement" => value == Some("-1"),
        _ => false,
    }
}

fn analyze_tokens(tokens: &[Token], event: &PgLog, out: &mut BTreeMap<&'static str, Finding>) {
    if tokens.is_empty() {
        return;
    }
    let role_ddl = (kw(tokens.first(), "ALTER") || kw(tokens.first(), "CREATE"))
        && (kw(tokens.get(1), "ROLE") || kw(tokens.get(1), "USER"))
        && !tokens
            .iter()
            .skip(3)
            .any(|t| kw(Some(t), "SET") || kw(Some(t), "RESET") || kw(Some(t), "RENAME"));
    if role_ddl
        && tokens.iter().skip(3).any(|t| {
            ["SUPERUSER", "CREATEROLE", "BYPASSRLS", "REPLICATION"]
                .iter()
                .any(|option| kw(Some(t), option))
        })
    {
        add(out, event, "DB001", "high", "Privileged role option observed",
            "A CREATE/ALTER ROLE or USER statement requests a privileged option. Statement logs do not prove the role changed.");
    }
    if kw(tokens.first(), "GRANT") {
        let to = tokens
            .iter()
            .position(|t| kw(Some(t), "TO"))
            .unwrap_or(tokens.len());
        let on = tokens[..to].iter().position(|t| kw(Some(t), "ON"));
        let privileged_membership = on.is_none()
            && tokens[1..to]
                .iter()
                .filter_map(ident)
                .any(|v| PRIVILEGED_ROLES.contains(&v.as_str()));
        let admin_option = tokens
            .windows(3)
            .any(|w| kw(w.first(), "WITH") && kw(w.get(1), "ADMIN") && kw(w.get(2), "OPTION"));
        let sensitive_object = on.is_some_and(|i| {
            let start = if kw(tokens.get(i + 1), "TABLE") {
                i + 2
            } else {
                i + 1
            };
            sensitive(object_name(tokens, start))
                || tokens[start..to].iter().enumerate().any(|(offset, t)| {
                    matches!(t, Token::Comma) && sensitive(object_name(tokens, start + offset + 1))
                })
        });
        if privileged_membership || admin_option || sensitive_object {
            add(out, event, "DB002", "high", "Sensitive privilege grant observed",
                "A GRANT references a privileged built-in role, ADMIN OPTION, or a configured sensitive table basename. Catalog resolution and approval context require review.");
        }
    }
    if kw(tokens.first(), "COPY") {
        let mut depth = 0usize;
        let mut to = None;
        for (i, t) in tokens.iter().enumerate() {
            match t {
                Token::LParen => depth += 1,
                Token::RParen => depth = depth.saturating_sub(1),
                _ => {}
            }
            if depth == 0 && kw(Some(t), "TO") {
                to = Some(i);
                break;
            }
        }
        if let Some(to) = to {
            if kw(tokens.get(to + 1), "PROGRAM") {
                add(out, event, "DB003", "high", "Server-program export observed",
                    "COPY TO PROGRAM requests server-side process execution. Review authorization and the associated error records; no command is executed by this tool.");
            }
            let direct = sensitive(object_name(tokens, 1));
            let query_reference = sensitive_query_relation(&tokens[..to]);
            if direct || query_reference {
                add(out, event, "DB004", "high", "Sensitive data export observed",
                    "COPY TO references a configured sensitive table basename, directly or in a query. This is an export attempt signal, not proof of exfiltration, returned rows or unauthorized intent.");
            }
        }
    }
    let set_form =
        kw(tokens.first(), "SET") || kw(tokens.first(), "ALTER") || kw(tokens.first(), "SELECT");
    if set_form && logging_disabled(tokens) {
        add(out, event, "DB005", "high", "Logging reduction setting observed",
            "A known logging setting is assigned a reduced/off value. The statement may have failed; raw logs and effective server configuration must be reviewed.");
    }
    if ["DO", "CALL", "EXECUTE", "PREPARE"]
        .iter()
        .any(|v| kw(tokens.first(), v))
        || (kw(tokens.first(), "CREATE")
            && tokens
                .iter()
                .take(5)
                .any(|t| kw(Some(t), "FUNCTION") || kw(Some(t), "PROCEDURE")))
    {
        coverage(out, event, "Procedural, prepared or dynamic SQL bodies are not expanded or executed. Review separately; absence of other findings is not a clean security verdict.");
    }
}

/// Analyze a single log event without network access, database writes or SQL execution.
/// Findings are deduplicated by rule within the event and ordered by stable rule ID.
pub fn analyze(event: &PgLog) -> Vec<Finding> {
    let mut out = BTreeMap::new();
    if event.state_code == "42501" || event.state_code == "28P01" || event.state_code == "28000" {
        add(&mut out, event, "DB006", "medium", "Permission or authentication failure observed",
            "PostgreSQL emitted a permission/authentication SQLSTATE. A single failure does not establish an attack or brute-force campaign.");
    }
    let Some(sql) = statement_text(event) else {
        return out.into_values().collect();
    };
    if sql.len() > MAX_SQL_BYTES {
        coverage(
            &mut out,
            event,
            "SQL exceeds the 64 KiB analysis budget and was not tokenized.",
        );
        return out.into_values().collect();
    }
    let Ok(mut tokens) = Tokenizer::new(&PostgreSqlDialect {}, sql).tokenize() else {
        coverage(
            &mut out,
            event,
            "SQL could not be tokenized; this event requires manual review.",
        );
        return out.into_values().collect();
    };
    tokens.retain(|t| !matches!(t, Token::Whitespace(_) | Token::EOF));
    if tokens.len() > MAX_TOKENS {
        coverage(
            &mut out,
            event,
            "SQL exceeds the 8192-token analysis budget and was not classified.",
        );
        return out.into_values().collect();
    }
    let mut depth = 0usize;
    for t in &tokens {
        match t {
            Token::LParen => depth += 1,
            Token::RParen if depth > 0 => depth -= 1,
            Token::RParen => {
                depth = MAX_DEPTH + 1;
                break;
            }
            _ => {}
        }
        if depth > MAX_DEPTH {
            break;
        }
    }
    if depth != 0 {
        coverage(
            &mut out,
            event,
            "Unbalanced or excessively nested SQL was not classified.",
        );
        return out.into_values().collect();
    }
    for statement in tokens.split(|t| matches!(t, Token::SemiColon)) {
        analyze_tokens(statement, event, &mut out);
    }
    out.into_values().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    fn event(sql: &str) -> PgLog {
        PgLog {
            message: format!("statement: {sql}"),
            error_severity: "LOG".into(),
            ..Default::default()
        }
    }
    fn ids(sql: &str) -> Vec<String> {
        analyze(&event(sql))
            .into_iter()
            .map(|f| f.rule_id)
            .collect()
    }
    #[test]
    fn detects_real_lab_statements_as_unknown_outcome() {
        for (sql, expected) in [
            ("ALTER ROLE lab_reader SUPERUSER", "DB001"),
            ("COPY public.bank_accounts TO STDOUT WITH CSV", "DB004"),
            ("SET log_statement='none'", "DB005"),
        ] {
            let f = analyze(&event(sql));
            assert_eq!(f.len(), 1);
            assert_eq!(f[0].rule_id, expected);
            assert_eq!(f[0].outcome, "unknown");
        }
    }
    #[test]
    fn literals_comments_and_identifiers_are_not_commands_or_options() {
        for sql in [
            "SELECT 1",
            "SELECT 'ALTER ROLE lab_reader SUPERUSER'",
            "SELECT $$COPY bank_accounts TO PROGRAM 'anything'$$",
            "/* ALTER ROLE r SUPERUSER */ SELECT 1 -- GRANT pg_read_all_data TO r",
            "CREATE ROLE \"SUPERUSER\" NOSUPERUSER",
            "SET log_statement='all'",
            "COPY bank_accounts FROM STDIN",
            "SELECT set_config('application_name','none',false)",
            "ALTER ROLE analyst SET application_name=SUPERUSER",
            "ALTER ROLE analyst RENAME TO SUPERUSER",
        ] {
            assert!(ids(sql).is_empty(), "{sql}");
        }
    }
    #[test]
    fn quoted_schema_names_and_multi_statement_events() {
        assert_eq!(
            ids("COPY \"public\".\"bank_accounts\" TO STDOUT"),
            ["DB004"]
        );
        assert_eq!(
            ids("COPY \"BANK_ACCOUNTS\" TO STDOUT"),
            Vec::<String>::new()
        );
        assert_eq!(ids("SELECT 1; ALTER USER r WITH BYPASSRLS; SET log_connections TO off; ALTER ROLE r CREATEROLE"),["DB001","DB005"]);
    }
    #[test]
    fn grant_policy_preserves_benign_controls() {
        for sql in [
            "GRANT pg_read_all_data TO r",
            "GRANT SELECT ON TABLE bank_accounts TO r",
            "GRANT SELECT ON healthcheck, public.bank_accounts TO r",
            "GRANT x TO r WITH ADMIN OPTION",
            "GRANT pg_execute_server_program TO r",
        ] {
            assert_eq!(ids(sql), ["DB002"], "{sql}");
        }
        for sql in [
            "GRANT reporting_reader TO r",
            "GRANT SELECT ON public.healthcheck TO r",
            "SELECT 'GRANT pg_read_all_data TO r'",
        ] {
            assert!(ids(sql).is_empty(), "{sql}");
        }
    }
    #[test]
    fn export_nested_query_and_program_signals() {
        assert_eq!(ids("COPY (SELECT * FROM bank.accounts a JOIN public.payments p ON p.id=a.id) TO STDOUT"),["DB004"]);
        assert_eq!(
            ids("COPY public.bank_accounts TO PROGRAM 'local-fixture-only'"),
            ["DB003", "DB004"]
        );
        assert_eq!(
            ids("COPY public.healthcheck TO STDOUT"),
            Vec::<String>::new()
        );
    }
    #[test]
    fn recognizes_logging_forms_without_matching_value_text() {
        for sql in [
            "ALTER SYSTEM SET log_statement = 'none'",
            "ALTER ROLE reader IN DATABASE bank SET log_connections = false",
            "SET LOCAL log_min_duration_statement = -1",
            "SELECT pg_catalog.set_config('log_statement','none',false)",
        ] {
            assert_eq!(ids(sql), ["DB005"], "{sql}");
        }
        assert!(ids("SELECT 'SET log_statement=none'").is_empty());
    }
    #[test]
    fn expression_from_is_not_a_sensitive_relation() {
        for sql in [
            "COPY (SELECT substring('hello' FROM customers) FROM (VALUES (1)) AS t(customers)) TO STDOUT",
            "COPY (SELECT x IS DISTINCT FROM customers FROM healthcheck) TO STDOUT",
            "COPY (SELECT extract(epoch FROM customers) FROM healthcheck) TO STDOUT",
        ] { assert!(ids(sql).is_empty(), "{sql}"); }
        for sql in [
            "COPY (SELECT (SELECT id FROM customers) FROM healthcheck) TO STDOUT",
            "COPY (SELECT substring(name FROM 1) FROM customers) TO STDOUT",
            "COPY (SELECT * FROM healthcheck, public.customers) TO STDOUT",
        ] {
            assert_eq!(ids(sql), ["DB004"], "{sql}");
        }
    }
    #[test]
    fn duration_logging_recognizes_only_native_statement_prefixes() {
        for message in [
            "duration: 1.234 ms  statement: COPY public.bank_accounts TO STDOUT",
            "duration: 0.000 ms  execute <unnamed>: COPY public.bank_accounts TO STDOUT",
        ] {
            let mut e = event("SELECT 1");
            e.message = message.into();
            let findings = analyze(&e);
            assert_eq!(findings[0].rule_id, "DB004");
            assert_eq!(findings[0].outcome, "unknown");
        }
        for message in [
            "application says duration: 1.2 ms  statement: COPY bank_accounts TO STDOUT",
            "duration: NaN ms  statement: COPY bank_accounts TO STDOUT",
            "duration: 1.2 ms  statement: SELECT 'COPY bank_accounts TO STDOUT'",
            "duration: 1.2 ms",
        ] {
            let mut e = event("SELECT 1");
            e.message = message.into();
            assert!(analyze(&e).is_empty(), "{message}");
        }
    }
    #[test]
    fn error_statement_and_extended_protocol_are_supported() {
        let mut e = event("SELECT 1");
        e.error_severity = "ERROR".into();
        e.state_code = "42501".into();
        e.statement = Some("ALTER ROLE r SUPERUSER".into());
        let f = analyze(&e);
        assert_eq!(
            f.iter().map(|x| x.rule_id.as_str()).collect::<Vec<_>>(),
            ["DB001", "DB006"]
        );
        assert!(f.iter().all(|x| x.outcome == "failure_observed"));
        e.statement = None;
        e.error_severity = "LOG".into();
        e.state_code.clear();
        e.message = "execute <unnamed>: COPY bank_accounts TO STDOUT".into();
        assert_eq!(analyze(&e)[0].rule_id, "DB004");
    }
    #[test]
    fn malformed_bounded_and_dynamic_sql_report_coverage_gaps() {
        for sql in [
            "SELECT 'unclosed",
            "SELECT (((1)",
            "SELECT )1",
            "DO $$BEGIN EXECUTE 'anything'; END$$",
            "EXECUTE prepared_name",
        ] {
            assert_eq!(ids(sql), ["DB900"], "{sql}");
        }
        assert_eq!(ids(&"x".repeat(MAX_SQL_BYTES + 1)), ["DB900"]);
        assert_eq!(ids(&"x ".repeat(MAX_TOKENS + 1)), ["DB900"]);
        assert_eq!(
            ids(&format!("SELECT {}1{}", "(".repeat(33), ")".repeat(33))),
            ["DB900"]
        );
    }
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]
        #[test]
        fn arbitrary_sql_never_panics_or_claims_success(sql in ".{0,2048}") {
            let f=analyze(&event(&sql));
            prop_assert!(f.len()<=7);
            prop_assert!(f.iter().all(|x|x.outcome=="unknown"));
        }
        #[test]
        fn literal_payload_never_triggers_dangerous_command(payload in "[a-zA-Z0-9_ ;]{0,256}") {
            let sql = format!("SELECT '{payload}'");
            prop_assert!(ids(&sql).is_empty());
        }
    }
}
