use crate::config::EmailProviderConfig;

pub(super) fn email_provider_name(provider: &EmailProviderConfig) -> &'static str {
    match provider {
        EmailProviderConfig::Disabled => "disabled",
        EmailProviderConfig::Stdout => "stdout",
        EmailProviderConfig::Command { .. } => "command",
    }
}
