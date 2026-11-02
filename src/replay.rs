// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::error::{err, SamlError};

/// Remembers which assertions have been accepted.
pub struct MemoryReplayCache {
    entries: Mutex<HashMap<String, i64>>,
    max: usize,
}

impl MemoryReplayCache {
    pub fn new(max_entries: usize) -> Self {
        Self { entries: Mutex::new(HashMap::new()), max: if max_entries == 0 { 10_000 } else { max_entries } }
    }

    /// Reports whether `assertion_id` was already accepted and still live.
    pub fn check_and_record(&self, assertion_id: &str, expires_at_ms: i64) -> Result<bool, SamlError> {
        let now = now_ms();
        let mut entries = self.entries.lock().expect("replay");
        if let Some(until) = entries.get(assertion_id) {
            if *until > now {
                return Ok(true);
            }
        }
        if entries.len() >= self.max {
            entries.retain(|_, until| *until > now);
            if entries.len() >= self.max {
                return Err(err("replay", format!("the replay cache holds {} live assertions and cannot record another", self.max)));
            }
        }
        entries.insert(assertion_id.to_string(), expires_at_ms);
        Ok(false)
    }
}

pub(crate) fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}
