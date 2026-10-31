//! Bounded, strict PostgreSQL jsonlog ingestion. Original bytes are never rewritten.
//!
//! The callback receives validated records in physical file order, not timestamp order.
//! A failure can occur after earlier callbacks ran; callers must not finalize an evidence
//! bundle after any error. The scanner does not authenticate the logging host or infer
//! whether a statement completed successfully.
use crate::model::PgLog;
use anyhow::{ensure, Context, Result};
use serde::Serialize;
use std::io::BufRead;

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Maximum original record length, including any terminating LF or CRLF.
    pub max_line_bytes: usize,
    /// Maximum bytes consumed from this input, including record terminators.
    pub max_total_bytes: u64,
    pub max_records: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_line_bytes: 1024 * 1024,
            max_total_bytes: 256 * 1024 * 1024,
            max_records: 1_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct ScanStats {
    pub records: u64,
    pub bytes: u64,
}

/// Read bounded records without `read_line`/`read_until` allocating an entire hostile line.
///
/// Memory for the scanner's reusable byte vector is bounded by `max_line_bytes`
/// (apart from allocator rounding). JSON decoding also consumes memory proportional to
/// that bound. The supplied reader and anything retained by the callback are caller-owned.
/// Empty files return zero records; blank lines are invalid, including a lone final LF.
pub fn scan<R: BufRead>(
    mut reader: R,
    limits: Limits,
    mut consume: impl FnMut(u64, &[u8], PgLog) -> Result<()>,
) -> Result<ScanStats> {
    ensure!(
        limits.max_line_bytes > 0,
        "Line byte limit must be positive"
    );
    ensure!(
        limits.max_total_bytes > 0,
        "Total byte limit must be positive"
    );
    ensure!(limits.max_records > 0, "Record limit must be positive");
    let mut stats = ScanStats::default();
    let mut raw = Vec::<u8>::new();
    loop {
        raw.clear();
        let line = stats
            .records
            .checked_add(1)
            .context("Record count overflow")?;
        let start_offset = stats.bytes;
        loop {
            let available = reader.fill_buf().with_context(|| {
                format!("Input read failed at record {line}, byte {}", stats.bytes)
            })?;
            if available.is_empty() {
                break;
            }
            ensure!(
                stats.records < limits.max_records,
                "Record limit exceeded at record {line}"
            );
            let terminator = available.iter().position(|&b| b == b'\n');
            let count = terminator.map_or(available.len(), |i| i + 1);
            let new_len = raw
                .len()
                .checked_add(count)
                .context("Record length overflow")?;
            ensure!(
                new_len <= limits.max_line_bytes,
                "Record {line} exceeds line byte limit at byte {start_offset}"
            );
            let next_total = stats
                .bytes
                .checked_add(u64::try_from(count).context("Input length overflow")?)
                .context("Total byte count overflow")?;
            ensure!(
                next_total <= limits.max_total_bytes,
                "Total byte limit exceeded at record {line}"
            );
            // Explicit capped growth avoids Vec's geometric reserve growing beyond the
            // configured line budget; reserve occurs only after both byte checks.
            if new_len > raw.capacity() {
                let capacity = new_len
                    .max(raw.capacity().saturating_mul(2))
                    .min(limits.max_line_bytes);
                raw.try_reserve_exact(capacity - raw.len())
                    .context("Unable to reserve bounded record buffer")?;
            }
            raw.extend_from_slice(&available[..count]);
            reader.consume(count);
            stats.bytes = next_total;
            if terminator.is_some() {
                break;
            }
        }
        if raw.is_empty() {
            return Ok(stats);
        }
        ensure!(
            !raw.iter().all(u8::is_ascii_whitespace),
            "Blank record at line {line}, byte {start_offset}"
        );
        // serde_json rejects invalid UTF-8, duplicate known fields and excessive nesting.
        let event: PgLog = serde_json::from_slice(&raw).map_err(|error| {
            // serde data errors can quote the offending value. Avoid leaking log
            // contents into terminal/CI output while retaining actionable positions.
            anyhow::anyhow!(
                "Invalid PostgreSQL JSON at line {line}, byte {start_offset}: {:?} error at JSON line {}, column {}",
                error.classify(), error.line(), error.column()
            )
        })?;
        validate_metadata(&event).with_context(|| {
            format!("Invalid PostgreSQL metadata at line {line}, byte {start_offset}")
        })?;
        consume(line, &raw, event)
            .with_context(|| format!("Record callback failed at line {line}"))?;
        stats.records = line;
    }
}

fn validate_metadata(event: &PgLog) -> Result<()> {
    // PostgreSQL timestamps are preserved as emitted. Time-zone names depend on
    // log_timezone, so this is bounded metadata validation, not time normalization.
    ensure!(
        !event.timestamp.trim().is_empty()
            && event.timestamp.len() <= 128
            && !event.timestamp.chars().any(char::is_control),
        "Missing or invalid timestamp"
    );
    ensure!(!event.message.trim().is_empty(), "Missing or empty message");
    ensure!(event.user.len() <= 512, "User metadata exceeds bound");
    ensure!(event.dbname.len() <= 512, "Database metadata exceeds bound");
    ensure!(
        event.session_id.len() <= 128,
        "Session metadata exceeds bound"
    );
    ensure!(
        event.application_name.len() <= 512,
        "Application metadata exceeds bound"
    );
    ensure!(
        event.error_severity.len() <= 32,
        "Severity metadata exceeds bound"
    );
    ensure!(
        event.state_code.is_empty()
            || (event.state_code.len() == 5
                && event
                    .state_code
                    .bytes()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())),
        "Invalid SQLSTATE metadata"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::{self, BufReader, Cursor, Read};

    fn record(message: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "timestamp": "2026-10-31 19:00:00.123 UTC", "message": message,
            "user": "lab_reader", "session_id": "abcdef.123", "line_num": 1,
            "state_code": "00000", "error_severity": "LOG",
            "future_pg_field": {"allowed": true}
        }))
        .unwrap()
    }

    #[test]
    fn preserves_bytes_crlf_unknown_fields_and_unterminated_final_record() {
        let mut first = record("statement: SELECT 'Olá\\nworld';");
        first.extend_from_slice(b"\r\n");
        let second = record("statement: SELECT 2;");
        let all = [first.clone(), second.clone()].concat();
        let mut seen = vec![];
        let stats = scan(Cursor::new(&all), Limits::default(), |line, raw, event| {
            seen.push((line, raw.to_vec(), event.message));
            Ok(())
        })
        .unwrap();
        assert_eq!(seen[0].0, 1);
        assert_eq!(seen[1].0, 2);
        assert_eq!(seen[0].1, first);
        assert_eq!(seen[1].1, second);
        assert_eq!(
            stats,
            ScanStats {
                records: 2,
                bytes: all.len() as u64
            }
        );
    }

    #[test]
    fn fragmented_reader_matches_contiguous_input() {
        let input = [record("statement: SELECT 1;"), b"\n".to_vec()].concat();
        for capacity in [1, 2, 7, 64, 8192] {
            let reader = BufReader::with_capacity(capacity, Cursor::new(&input));
            let mut raw_seen = vec![];
            let stats = scan(reader, Limits::default(), |_, raw, _| {
                raw_seen.extend_from_slice(raw);
                Ok(())
            })
            .unwrap();
            assert_eq!(raw_seen, input);
            assert_eq!(stats.records, 1);
        }
    }

    #[test]
    fn exact_byte_and_record_limits_are_inclusive() {
        let input = [record("ok"), b"\n".to_vec()].concat();
        let limits = Limits {
            max_line_bytes: input.len(),
            max_total_bytes: input.len() as u64,
            max_records: 1,
        };
        assert_eq!(
            scan(Cursor::new(&input), limits, |_, _, _| Ok(()))
                .unwrap()
                .records,
            1
        );
        assert!(scan(
            Cursor::new(&input),
            Limits {
                max_line_bytes: input.len() - 1,
                ..limits
            },
            |_, _, _| Ok(())
        )
        .is_err());
        assert!(scan(
            Cursor::new(&input),
            Limits {
                max_total_bytes: input.len() as u64 - 1,
                ..limits
            },
            |_, _, _| Ok(())
        )
        .is_err());
        let twice = [input.clone(), input].concat();
        let mut seen = 0;
        let error = scan(
            Cursor::new(twice),
            Limits {
                max_total_bytes: 10000,
                ..limits
            },
            |_, _, _| {
                seen += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(error.to_string().contains("record 2"));
        assert_eq!(seen, 1);
    }

    #[test]
    fn missing_or_invalid_metadata_is_rejected() {
        for value in [
            serde_json::json!({"message":"ok"}),
            serde_json::json!({"timestamp":"2026-10-31"}),
            serde_json::json!({"timestamp":" ","message":"ok"}),
            serde_json::json!({"timestamp":"x\ny","message":"ok"}),
            serde_json::json!({"timestamp":"x","message":"ok","state_code":"no"}),
            serde_json::json!({"timestamp":"x","message":"ok","state_code":"1234!"}),
            serde_json::json!({"timestamp":"x","message":"ok","line_num":-1}),
            serde_json::json!({"timestamp":"x","message":"ok","user":"a".repeat(513)}),
        ] {
            let bytes = serde_json::to_vec(&value).unwrap();
            assert!(
                scan(Cursor::new(bytes), Limits::default(), |_, _, _| panic!(
                    "invalid record delivered"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn malformed_json_utf8_blank_and_duplicate_fields_fail_closed() {
        for input in [
            b"\n".to_vec(),
            b" \r\n".to_vec(),
            b"{".to_vec(),
            vec![0xff],
            b"[]".to_vec(),
            b"null".to_vec(),
            b"{\"timestamp\":\"x\",\"message\":\"one\",\"message\":\"two\"}".to_vec(),
            [record("ok"), b"trailing".to_vec()].concat(),
        ] {
            assert!(
                scan(Cursor::new(input), Limits::default(), |_, _, _| panic!(
                    "invalid record delivered"
                ))
                .is_err()
            );
        }
    }

    #[test]
    fn callback_error_stops_before_later_records() {
        let input = [record("first"), b"\n".to_vec(), record("second")].concat();
        let mut count = 0;
        let error = scan(Cursor::new(input), Limits::default(), |_, _, _| {
            count += 1;
            anyhow::bail!("callback unavailable")
        })
        .unwrap_err();
        assert_eq!(count, 1);
        assert!(format!("{error:#}").contains("callback unavailable"));
        assert!(error.to_string().contains("line 1"));
    }

    #[test]
    fn decoder_errors_do_not_echo_sensitive_values() {
        let input = br#"{"timestamp":"x","message":"ok","line_num":"private-access-token"}"#;
        let error = scan(Cursor::new(input), Limits::default(), |_, _, _| Ok(())).unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("line 1"));
        assert!(!text.contains("private-access-token"));
    }

    #[test]
    fn empty_file_has_zero_records_but_invalid_limits_are_errors() {
        assert_eq!(
            scan(Cursor::new([]), Limits::default(), |_, _, _| Ok(())).unwrap(),
            ScanStats::default()
        );
        for limits in [
            Limits {
                max_line_bytes: 0,
                ..Limits::default()
            },
            Limits {
                max_total_bytes: 0,
                ..Limits::default()
            },
            Limits {
                max_records: 0,
                ..Limits::default()
            },
        ] {
            assert!(scan(Cursor::new([]), limits, |_, _, _| Ok(())).is_err());
        }
    }

    struct NeverEnding;
    impl Read for NeverEnding {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            buf.fill(b'x');
            Ok(buf.len())
        }
    }
    #[test]
    fn infinite_unterminated_line_stops_at_budget() {
        let mut delivered = 0;
        let err = scan(
            BufReader::with_capacity(7, NeverEnding),
            Limits {
                max_line_bytes: 32,
                ..Limits::default()
            },
            |_, _, _| {
                delivered += 1;
                Ok(())
            },
        )
        .unwrap_err();
        assert!(err.to_string().contains("line byte limit"));
        assert_eq!(delivered, 0);
    }

    struct Failure;
    impl Read for Failure {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("synthetic read failure"))
        }
    }
    #[test]
    fn input_read_failure_has_position_context() {
        let err = scan(BufReader::new(Failure), Limits::default(), |_, _, _| Ok(())).unwrap_err();
        assert!(err.to_string().contains("record 1, byte 0"));
        assert!(format!("{err:#}").contains("synthetic read failure"));
    }

    proptest! {
        #[test]
        fn arbitrary_fragmentation_preserves_valid_record(message in "[a-zA-Z0-9é中 \\n\\t]{1,200}", width in 1usize..128) {
            prop_assume!(!message.trim().is_empty());
            let bytes = record(&message);
            let mut output = vec![];
            let mut decoded = String::new();
            let stats = scan(BufReader::with_capacity(width, Cursor::new(&bytes)), Limits::default(), |_, raw, event| {
                output.extend_from_slice(raw); decoded = event.message; Ok(())
            }).unwrap();
            prop_assert_eq!(output, bytes.clone());
            prop_assert_eq!(decoded, message);
            prop_assert_eq!(stats.bytes, bytes.len() as u64);
        }
    }
}
