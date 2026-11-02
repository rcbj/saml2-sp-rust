// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use std::fmt;

/// A non-success status an identity provider answered with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SamlStatus {
    pub code: String,
    pub sub_code: String,
    pub message: String,
}

/// Every failure this crate reports. Display is the message alone.
#[derive(Clone, Debug)]
pub struct SamlError {
    pub code: String,
    pub message: String,
    pub status: Option<SamlStatus>,
}

impl fmt::Display for SamlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SamlError {}

pub(crate) fn err(code: &str, message: impl Into<String>) -> SamlError {
    SamlError { code: code.to_string(), message: message.into(), status: None }
}

pub(crate) fn err_status(message: impl Into<String>, status: SamlStatus) -> SamlError {
    SamlError { code: "status".to_string(), message: message.into(), status: Some(status) }
}
