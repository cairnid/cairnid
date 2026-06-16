mod constants;
mod lifecycle;
mod provider;

pub use self::constants::{
    REQUIRED_LIFECYCLE_EMAIL_KINDS, lifecycle_email_template_is_allowed,
    lifecycle_email_template_requirement,
};
pub(super) use self::{
    lifecycle::validate_lifecycle_email_smoke, provider::validate_email_provider_smoke,
};

#[cfg(test)]
mod tests;
