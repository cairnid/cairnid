#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DomainError {
    #[error("field `{field}` cannot be empty")]
    EmptyField { field: &'static str },
    #[error("field `{field}` is too long; maximum length is {max}")]
    FieldTooLong { field: &'static str, max: usize },
    #[error("invalid email address")]
    InvalidEmail,
    #[error("redirect URI must use https, except localhost development URLs")]
    InsecureRedirectUri,
    #[error("redirect URI is not registered for this client")]
    UnregisteredRedirectUri,
}
