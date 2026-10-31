use serde::{Deserialize, Serialize};

/// Selected PostgreSQL 15+ jsonlog fields. Unknown fields are retained only in raw evidence.
#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct PgLog {
    #[serde(default)]
    pub timestamp: String,
    #[serde(default)]
    pub user: String,
    #[serde(default)]
    pub dbname: String,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub line_num: u64,
    #[serde(default)]
    pub error_severity: String,
    #[serde(default)]
    pub state_code: String,
    #[serde(default)]
    pub message: String,
    #[serde(default)]
    pub statement: Option<String>,
    #[serde(default)]
    pub application_name: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    /// Always describes a logged attempt/observation; log_statement is pre-execution.
    pub outcome: String,
}
