#![forbid(unsafe_code)]

mod builder;
mod redaction;

#[cfg(test)]
mod tests;

pub use builder::AuditEventBuilder;
pub use redaction::redact_sensitive_metadata;
