use super::{
    ConfigError, EmailDeliveryConfig, EmailProviderConfig, optional_i32, optional_i64, required,
};
use cairn_domain::Environment;

pub(super) fn email_delivery_from_env(
    environment: Environment,
) -> Result<EmailDeliveryConfig, ConfigError> {
    let default_provider = match environment {
        Environment::Development => "stdout",
        Environment::Production => "disabled",
    };
    let provider_name =
        std::env::var("CAIRN_EMAIL_PROVIDER").unwrap_or_else(|_| default_provider.into());
    let provider = match provider_name.as_str() {
        "disabled" => EmailProviderConfig::Disabled,
        "stdout" => {
            if matches!(environment, Environment::Production) {
                return Err(ConfigError::InvalidEmailProvider(
                    "CAIRN_EMAIL_PROVIDER=stdout is development-only".to_owned(),
                ));
            }
            EmailProviderConfig::Stdout
        }
        "command" => EmailProviderConfig::Command {
            path: required("CAIRN_EMAIL_COMMAND_PATH")?,
        },
        other => {
            return Err(ConfigError::InvalidEmailProvider(format!(
                "unsupported CAIRN_EMAIL_PROVIDER {other}; expected disabled, stdout, or command"
            )));
        }
    };

    Ok(EmailDeliveryConfig {
        provider,
        batch_size: optional_i64("CAIRN_EMAIL_BATCH_SIZE", 10)?.clamp(1, 100),
        max_attempts: optional_i32("CAIRN_EMAIL_MAX_ATTEMPTS", 5)?.clamp(1, 20),
        retry_seconds: optional_i64("CAIRN_EMAIL_RETRY_SECONDS", 300)?.clamp(1, 86_400),
        sending_timeout_seconds: optional_i64("CAIRN_EMAIL_SENDING_TIMEOUT_SECONDS", 900)?
            .clamp(30, 86_400),
    })
}
