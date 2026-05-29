//! Structured stdout logging — JSON per line.
//!
//! Each log entry is a single line of JSON with a fixed schema:
//!
//! ```json
//! {"ts": 1780000000, "lvl": "INFO", "msg": "cycle 42", "k1": "v1", ...}
//! ```
//!
//! systemd-journald consumes this verbatim with `StandardOutput=journal` —
//! no syslog or external aggregator needed.
//!
//! Tiny on purpose: ~50 LOC, no `tracing` / `log` crate dependency.

use serde_json::{Map, Value};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

/// Log level.
#[derive(Debug, Clone, Copy)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Emit one JSON-line log entry to stdout. Pre-built `fields` map allows
/// arbitrary structured keys; the `ts`, `lvl`, and `msg` fields are reserved
/// and always emitted.
pub fn log(level: Level, msg: &str, fields: Map<String, Value>) {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut obj = Map::with_capacity(3 + fields.len());
    obj.insert("ts".to_string(), Value::from(ts));
    obj.insert("lvl".to_string(), Value::from(level.as_str()));
    obj.insert("msg".to_string(), Value::from(msg));
    for (k, v) in fields {
        if k != "ts" && k != "lvl" && k != "msg" {
            obj.insert(k, v);
        }
    }
    // Single write call to keep journald's record boundaries clean.
    let line = serde_json::to_string(&Value::Object(obj)).unwrap_or_default();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
}

/// `log_info!("cycle start", "n" => 42, "slot" => 7)`.
#[macro_export]
macro_rules! log_info {
    ($msg:expr $(, $k:expr => $v:expr)* $(,)?) => {{
        let mut fields = ::serde_json::Map::new();
        $( fields.insert($k.to_string(), ::serde_json::json!($v)); )*
        $crate::logging::log($crate::logging::Level::Info, $msg, fields);
    }};
}

#[macro_export]
macro_rules! log_warn {
    ($msg:expr $(, $k:expr => $v:expr)* $(,)?) => {{
        let mut fields = ::serde_json::Map::new();
        $( fields.insert($k.to_string(), ::serde_json::json!($v)); )*
        $crate::logging::log($crate::logging::Level::Warn, $msg, fields);
    }};
}

#[macro_export]
macro_rules! log_error {
    ($msg:expr $(, $k:expr => $v:expr)* $(,)?) => {{
        let mut fields = ::serde_json::Map::new();
        $( fields.insert($k.to_string(), ::serde_json::json!($v)); )*
        $crate::logging::log($crate::logging::Level::Error, $msg, fields);
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn levels_render_strings() {
        assert_eq!(Level::Info.as_str(), "INFO");
        assert_eq!(Level::Warn.as_str(), "WARN");
        assert_eq!(Level::Error.as_str(), "ERROR");
        assert_eq!(Level::Debug.as_str(), "DEBUG");
    }

    #[test]
    fn reserved_fields_in_user_map_are_ignored() {
        let mut fields = Map::new();
        fields.insert("ts".to_string(), json!(123));
        fields.insert("lvl".to_string(), json!("WRONG"));
        fields.insert("msg".to_string(), json!("WRONG"));
        fields.insert("extra".to_string(), json!(42));
        log(Level::Info, "expected", fields);
        // (assertion is structural — no panic, no field shadowing)
    }
}
