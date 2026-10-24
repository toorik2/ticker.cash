//! Structured stdout logging — one JSON object per line, consumed verbatim by journald.
//!
//! `{"ts": 1792849200, "lvl": "INFO", "msg": "update posted", "seq": 29870820, ...}`

use serde_json::{Map, Value};
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

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

pub fn log(level: Level, msg: &str, fields: Map<String, Value>) {
    let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let mut obj = Map::with_capacity(3 + fields.len());
    obj.insert("ts".to_string(), Value::from(ts));
    obj.insert("lvl".to_string(), Value::from(level.as_str()));
    obj.insert("msg".to_string(), Value::from(msg));
    for (k, v) in fields {
        if k != "ts" && k != "lvl" && k != "msg" {
            obj.insert(k, v);
        }
    }
    let line = serde_json::to_string(&Value::Object(obj)).unwrap_or_default();
    let mut stdout = std::io::stdout().lock();
    let _ = writeln!(stdout, "{line}");
}

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

    #[test]
    fn levels_render() {
        assert_eq!(Level::Info.as_str(), "INFO");
        assert_eq!(Level::Error.as_str(), "ERROR");
    }
}
