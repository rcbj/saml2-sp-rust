// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::collections::HashMap;
use std::sync::Mutex;

use crate::replay::now_ms;
use crate::response::SamlLogin;

/// The SAML attribute a Shared Signals subject is taken from when none is named.
pub const DEFAULT_SUBJECT_ATTRIBUTE: &str = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier";

const MAIL: &[&str] = &[
    "urn:oid:0.9.2342.19200300.100.1.3",
    "mail",
    "email",
    "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
];
const EMAIL_NAMEID: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

/// One local session the receiver can end.
#[derive(Clone, Debug)]
pub struct SessionRecord {
    pub local_id: String,
    pub person: String,
    pub email: String,
    pub idp_session: String,
    pub expires_at_ms: Option<i64>,
}

/// Which local sessions belong to which person.
pub struct MemorySessionIndex {
    sessions: Mutex<IndexState>,
    max: usize,
}

struct IndexState {
    sessions: HashMap<String, SessionRecord>,
    order: Vec<String>,
}

impl MemorySessionIndex {
    pub fn new(max_entries: usize) -> Self {
        Self {
            sessions: Mutex::new(IndexState { sessions: HashMap::new(), order: Vec::new() }),
            max: if max_entries == 0 { 100_000 } else { max_entries },
        }
    }

    pub fn add(&self, mut session: SessionRecord) {
        if !session.email.is_empty() {
            session.email = session.email.to_ascii_lowercase();
        }
        let mut state = self.sessions.lock().expect("sessions");
        if !state.sessions.contains_key(&session.local_id) && state.sessions.len() >= self.max {
            let now = now_ms();
            let expired: Vec<String> = state.order.iter().filter(|key| {
                state.sessions.get(*key).and_then(|v| v.expires_at_ms).is_some_and(|t| t <= now)
            }).cloned().collect();
            for key in expired {
                drop_locked(&mut state, &key);
            }
            while state.sessions.len() >= self.max && !state.order.is_empty() {
                let key = state.order[0].clone();
                drop_locked(&mut state, &key);
            }
        }
        if !state.sessions.contains_key(&session.local_id) {
            state.order.push(session.local_id.clone());
        }
        state.sessions.insert(session.local_id.clone(), session);
    }

    pub fn remove(&self, local_id: &str) {
        let mut state = self.sessions.lock().expect("sessions");
        drop_locked(&mut state, local_id);
    }

    pub fn by_person(&self, person: &str) -> Vec<String> {
        self.find(|session| session.person == person)
    }

    pub fn by_email(&self, email: &str) -> Vec<String> {
        let wanted = email.to_ascii_lowercase();
        self.find(|session| session.email == wanted)
    }

    pub fn by_idp_session(&self, idp_session: &str) -> Vec<String> {
        self.find(|session| session.idp_session == idp_session)
    }

    fn find(&self, mut matches: impl FnMut(&SessionRecord) -> bool) -> Vec<String> {
        let now = now_ms();
        let mut state = self.sessions.lock().expect("sessions");
        let mut out = Vec::new();
        let mut keep = Vec::new();
        let order = std::mem::take(&mut state.order);
        for key in order {
            let Some(value) = state.sessions.get(&key) else { continue };
            if value.expires_at_ms.is_some_and(|t| t <= now) {
                state.sessions.remove(&key);
                continue;
            }
            if matches(value) {
                out.push(key.clone());
            }
            keep.push(key);
        }
        state.order = keep;
        out
    }
}

fn drop_locked(state: &mut IndexState, local_id: &str) {
    state.sessions.remove(local_id);
    state.order.retain(|id| id != local_id);
}

/// The index record for a SAML login.
pub fn tracked_from(local_id: &str, login: &SamlLogin, subject_attribute: &str, expires_at_ms: Option<i64>) -> SessionRecord {
    let attribute = if subject_attribute.is_empty() { DEFAULT_SUBJECT_ATTRIBUTE } else { subject_attribute };
    let person = login.attributes.get(attribute).and_then(|v| v.first()).cloned().unwrap_or_default();
    let mut email = String::new();
    for name in MAIL {
        if let Some(value) = login.attributes.get(*name).and_then(|v| v.first()) {
            if !value.is_empty() {
                email = value.clone();
                break;
            }
        }
    }
    if email.is_empty() && login.name_id_format == EMAIL_NAMEID {
        email = login.name_id.clone();
    }
    let when = expires_at_ms.or(login.session_not_on_or_after_ms);
    SessionRecord {
        local_id: local_id.to_string(),
        person,
        email,
        idp_session: login.session_index.clone(),
        expires_at_ms: when,
    }
}
