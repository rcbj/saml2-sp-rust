// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

//! SAML 2.0 service provider and Shared Signals poll receiver.

mod artifact;
mod bindings;
mod canon;
mod clock;
mod config;
mod encryption;
mod error;
mod events;
mod http;
mod jws;
mod keys;
mod metadata;
mod provider;
mod receiver;
mod replay;
mod response;
mod session;
mod xml;

pub use bindings::post_form_html;
pub use config::{resolve_config, Config};
pub use error::{SamlError, SamlStatus};
pub use events::{caep_events, default_ending_events, default_events_requested, event, risc_events, subject_of};
pub use http::TlsOptions;
pub use jws::verify_compact_jws;
pub use keys::{create_self_signed_key_pair, KeyMaterial};
pub use metadata::{metadata_document, read_idp_metadata, IdpMetadata};
pub use provider::{AcsBody, LoginOptions, LoginRequest, ServiceProvider};
pub use receiver::{Logger, ReceiverOptions, SignalEvent, SignalsReceiver};
pub use replay::MemoryReplayCache;
pub use response::SamlLogin;
pub use session::{tracked_from, MemorySessionIndex, SessionRecord, DEFAULT_SUBJECT_ATTRIBUTE};

#[cfg(test)]
mod support;
#[cfg(test)]
mod sp_test;
#[cfg(test)]
mod ssf_test;
#[cfg(test)]
mod configure_test;
#[cfg(test)]
mod trust_chain_test;
