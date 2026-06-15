mod audit;
mod email;
mod network;
mod origin;
mod scim;

use self::{
    audit::audit_operations_from_env, email::email_delivery_from_env,
    network::request_identity_from_env, origin::validate_origin_configuration,
    scim::scim_config_from_env,
};
use cairn_authn::hash_token;
use cairn_domain::Environment;
use cairn_oidc::{KeyEncryptionKey, SigningMaterial};
use secrecy::SecretString;
use serde_json::Value;
use std::{env, net::IpAddr};

pub(crate) const SCIM_BEARER_TOKEN_HASH_MAX_VALUES: usize = 4;
const BOOTSTRAP_SETUP_SECRET_ENV: &str = "CAIRN_BOOTSTRAP_SETUP_SECRET";

#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub environment: Environment,
    pub bind: String,
    pub issuer: String,
    pub public_web_origin: String,
    pub database_url: String,
    pub default_org_slug: String,
    pub scim: ScimConfig,
    pub audit: AuditOperationsConfig,
    pub email_delivery: EmailDeliveryConfig,
    pub request_identity: RequestIdentityConfig,
    pub bootstrap_setup_secret_hash: Option<SecretString>,
    pub signing: Option<SigningMaterial>,
    pub key_encryption_key: Option<KeyEncryptionKey>,
}

#[derive(Debug, Clone)]
pub struct AuditOperationsConfig {
    pub retention_days: i64,
    pub purge_batch_size: i64,
    pub export_max_rows: i64,
}

#[derive(Debug, Clone)]
pub struct ScimConfig {
    pub bearer_token_sha256_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Clone)]
pub struct EmailDeliveryConfig {
    pub provider: EmailProviderConfig,
    pub batch_size: i64,
    pub max_attempts: i32,
    pub retry_seconds: i64,
    pub sending_timeout_seconds: i64,
}

#[derive(Debug, Clone)]
pub struct RequestIdentityConfig {
    pub trusted_proxy_ips: Vec<IpAddr>,
}

#[derive(Debug, Clone)]
pub enum EmailProviderConfig {
    Disabled,
    Stdout,
    Command { path: String },
}

impl ApiConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        let environment = match env::var("CAIRN_ENV")
            .unwrap_or_else(|_| "development".to_owned())
            .as_str()
        {
            "production" => Environment::Production,
            _ => Environment::Development,
        };

        let bind = env::var("CAIRN_API_BIND").unwrap_or_else(|_| {
            env::var("PORT")
                .map(|port| format!("0.0.0.0:{port}"))
                .unwrap_or_else(|_| "127.0.0.1:8080".to_owned())
        });

        let issuer =
            required("CAIRN_ISSUER").unwrap_or_else(|_| "http://localhost:8080".to_owned());
        let public_web_origin = required("CAIRN_PUBLIC_WEB_ORIGIN")
            .unwrap_or_else(|_| "http://localhost:5173".to_owned());
        validate_origin_configuration(environment, &issuer, &public_web_origin)?;

        let database_url = required("DATABASE_URL")?;
        let default_org_slug =
            env::var("CAIRN_DEFAULT_ORG_SLUG").unwrap_or_else(|_| "default".to_owned());
        let scim = scim_config_from_env()?;
        let audit = audit_operations_from_env()?;
        let email_delivery = email_delivery_from_env(environment)?;
        let request_identity = request_identity_from_env()?;
        let bootstrap_setup_secret_hash = bootstrap_setup_secret_hash_from_env(environment)?;
        let key_encryption_key = env::var("CAIRN_KEY_ENCRYPTION_KEY")
            .ok()
            .map(|value| {
                KeyEncryptionKey::from_base64_url_no_pad(&value).map_err(|source| {
                    ConfigError::InvalidKeyEncryptionKey {
                        variable: "CAIRN_KEY_ENCRYPTION_KEY",
                        source,
                    }
                })
            })
            .transpose()?;

        let signing = match (
            env::var("CAIRN_SIGNING_KEY_ID"),
            env::var("CAIRN_SIGNING_PRIVATE_KEY_PEM"),
            env::var("CAIRN_SIGNING_PUBLIC_JWK"),
        ) {
            (Ok(key_id), Ok(private_key_pem), Ok(public_jwk)) => Some(SigningMaterial {
                key_id,
                private_key_pem: private_key_pem.replace("\\n", "\n"),
                public_jwk: serde_json::from_str::<Value>(&public_jwk).map_err(|source| {
                    ConfigError::InvalidJson {
                        variable: "CAIRN_SIGNING_PUBLIC_JWK",
                        source,
                    }
                })?,
            }),
            _ => None,
        };

        Ok(Self {
            environment,
            bind,
            issuer,
            public_web_origin,
            database_url,
            default_org_slug,
            scim,
            audit,
            email_delivery,
            request_identity,
            bootstrap_setup_secret_hash,
            signing,
            key_encryption_key,
        })
    }

    pub fn secure_cookies(&self) -> bool {
        matches!(self.environment, Environment::Production)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("missing required environment variable {0}")]
    Missing(&'static str),
    #[error("invalid JSON in {variable}")]
    InvalidJson {
        variable: &'static str,
        source: serde_json::Error,
    },
    #[error("invalid key encryption key in {variable}")]
    InvalidKeyEncryptionKey {
        variable: &'static str,
        source: cairn_oidc::OidcError,
    },
    #[error("invalid number in {variable}: {value}")]
    InvalidNumber {
        variable: &'static str,
        value: String,
    },
    #[error("invalid SHA-256 token hash in {variable}")]
    InvalidTokenHash { variable: &'static str },
    #[error("{variable} contains duplicate SHA-256 token hashes")]
    DuplicateTokenHash { variable: &'static str },
    #[error("{variable} contains more than {max} SHA-256 token hashes")]
    TooManyTokenHashes { variable: &'static str, max: usize },
    #[error("invalid origin in {variable}: {value} ({reason})")]
    InvalidOrigin {
        variable: &'static str,
        value: String,
        reason: &'static str,
    },
    #[error("invalid IP address in {variable}: {value}")]
    InvalidIpAddress {
        variable: &'static str,
        value: String,
    },
    #[error("{0}")]
    InvalidEmailProvider(String),
    #[error("invalid bootstrap setup secret in {variable}: {reason}")]
    InvalidBootstrapSetupSecret {
        variable: &'static str,
        reason: &'static str,
    },
}

fn bootstrap_setup_secret_hash_from_env(
    environment: Environment,
) -> Result<Option<SecretString>, ConfigError> {
    bootstrap_setup_secret_hash(environment, env::var(BOOTSTRAP_SETUP_SECRET_ENV).ok())
}

fn bootstrap_setup_secret_hash(
    environment: Environment,
    value: Option<String>,
) -> Result<Option<SecretString>, ConfigError> {
    match value {
        Some(secret) => {
            let secret = secret.trim();
            if secret.is_empty() {
                return Err(ConfigError::InvalidBootstrapSetupSecret {
                    variable: BOOTSTRAP_SETUP_SECRET_ENV,
                    reason: "must not be empty",
                });
            }
            Ok(Some(SecretString::from(hash_token(secret))))
        }
        None if matches!(environment, Environment::Production) => {
            Err(ConfigError::Missing(BOOTSTRAP_SETUP_SECRET_ENV))
        }
        None => Ok(None),
    }
}

fn required(name: &'static str) -> Result<String, ConfigError> {
    env::var(name).map_err(|_| ConfigError::Missing(name))
}

fn optional_i64(name: &'static str, default: i64) -> Result<i64, ConfigError> {
    match env::var(name) {
        Ok(value) => value
            .parse::<i64>()
            .map_err(|_| ConfigError::InvalidNumber {
                variable: name,
                value,
            }),
        Err(_) => Ok(default),
    }
}

fn optional_i32(name: &'static str, default: i32) -> Result<i32, ConfigError> {
    match env::var(name) {
        Ok(value) => value
            .parse::<i32>()
            .map_err(|_| ConfigError::InvalidNumber {
                variable: name,
                value,
            }),
        Err(_) => Ok(default),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_authn::verify_token_hash;
    use secrecy::ExposeSecret;

    #[test]
    fn production_requires_bootstrap_setup_secret() {
        assert!(matches!(
            bootstrap_setup_secret_hash(Environment::Production, None),
            Err(ConfigError::Missing("CAIRN_BOOTSTRAP_SETUP_SECRET"))
        ));
    }

    #[test]
    fn development_allows_missing_bootstrap_setup_secret() {
        assert!(
            bootstrap_setup_secret_hash(Environment::Development, None)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn bootstrap_setup_secret_hashes_non_empty_values() {
        let hash =
            bootstrap_setup_secret_hash(Environment::Production, Some(" setup-secret ".to_owned()))
                .unwrap()
                .expect("secret hash");

        assert!(verify_token_hash("setup-secret", hash.expose_secret()));
        assert!(!verify_token_hash("wrong-secret", hash.expose_secret()));
        assert!(!hash.expose_secret().contains("setup-secret"));
    }

    #[test]
    fn bootstrap_setup_secret_rejects_empty_values() {
        assert!(matches!(
            bootstrap_setup_secret_hash(Environment::Development, Some(" ".to_owned())),
            Err(ConfigError::InvalidBootstrapSetupSecret {
                variable: "CAIRN_BOOTSTRAP_SETUP_SECRET",
                reason: "must not be empty"
            })
        ));
    }
}
