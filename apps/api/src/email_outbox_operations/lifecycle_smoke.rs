use super::{
    errors::{config_error, config_error_owned},
    report,
};
use crate::{
    config::{ApiConfig, EmailProviderConfig},
    email::deliver_once,
    operations_evidence::REQUIRED_LIFECYCLE_EMAIL_KINDS,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cairn_authn::generate_hashed_secret;
use cairn_database::{Database, EmailOutboxQueueSummary};
use cairn_domain::{
    AccountToken, AccountTokenKind, EmailOutboxMessage, Environment, Organization, OrganizationId,
};
use cairn_oidc::{KeyEncryptionKey, encrypt_secret};
use secrecy::ExposeSecret;
use serde_json::json;
use std::{fs, path::PathBuf};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

pub(super) const LOCAL_LIFECYCLE_SMOKE_RECIPIENT: &str = "lifecycle-smoke@example.invalid";
const LOCAL_FAKE_PROVIDER_MESSAGE_ID: &str = "local-fake-lifecycle-smoke";

#[derive(Debug, Clone, Copy)]
pub(super) struct LifecycleSmokeMessageSpec {
    pub(super) kind: &'static str,
    pub(super) template: &'static str,
    pub(super) subject: &'static str,
    pub(super) action_path: Option<&'static str>,
    pub(super) body_intro: &'static str,
    pub(super) token_kind: Option<AccountTokenKind>,
    ttl_seconds: Option<i64>,
}

pub(super) async fn run_local_lifecycle_smoke_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    validate_lifecycle_smoke_local_args(args)?;
    refuse_production_environment()?;

    let mut config = ApiConfig::from_env()?;
    if matches!(config.environment, Environment::Production) {
        return Err(config_error(
            "lifecycle-smoke-local is development-only and refuses production environment",
        ));
    }
    if !recipient_is_reserved_local_address(LOCAL_LIFECYCLE_SMOKE_RECIPIENT) {
        return Err(config_error(
            "lifecycle-smoke-local recipient must use a reserved .invalid domain",
        ));
    }

    let database = Database::connect(&config.database_url).await?;
    database.migrate().await?;
    let organization = ensure_local_organization(&database, &config).await?;
    let queue = unfinished_queue_summary(&database, &config).await?;
    if queue.unfinished != 0 {
        return Err(config_error_owned(format!(
            "lifecycle-smoke-local refuses to run with unfinished email_outbox rows: queued={}, retry={}, sending={}, failed={}",
            queue.queued, queue.retry, queue.sending, queue.failed
        )));
    }

    let fake_provider = LocalFakeProviderCommand::create()?;
    config.email_delivery.provider = EmailProviderConfig::Command {
        path: fake_provider.path_string(),
    };
    config.email_delivery.batch_size = REQUIRED_LIFECYCLE_EMAIL_KINDS.len() as i64;
    config.email_delivery.max_attempts = 1;
    if config.key_encryption_key.is_none() {
        config.key_encryption_key = Some(local_smoke_key()?);
    }

    let now = OffsetDateTime::now_utc();
    queue_lifecycle_smoke_messages(
        &database,
        organization.id,
        LOCAL_LIFECYCLE_SMOKE_RECIPIENT,
        config
            .key_encryption_key
            .as_ref()
            .ok_or_else(|| config_error("lifecycle-smoke-local missing local KEK"))?,
        now,
    )
    .await?;

    let delivery = deliver_once(&database, &config).await?;
    let completed_at = OffsetDateTime::now_utc();
    let evidence = report::lifecycle_email_smoke_evidence_report(
        &database,
        &config,
        organization.id,
        completed_at,
    )
    .await?;
    let ready = evidence.is_ready();
    println!("{}", serde_json::to_string_pretty(&evidence)?);

    let expected = REQUIRED_LIFECYCLE_EMAIL_KINDS.len();
    if delivery.claimed != expected
        || delivery.sent != expected
        || delivery.retried != 0
        || delivery.failed != 0
    {
        return Err(config_error_owned(format!(
            "lifecycle-smoke-local delivery incomplete: claimed={}, sent={}, retried={}, failed={}",
            delivery.claimed, delivery.sent, delivery.retried, delivery.failed
        )));
    }
    if ready {
        Ok(())
    } else {
        Err(config_error(
            "lifecycle-smoke-local evidence is incomplete after fake-provider delivery",
        ))
    }
}

pub(super) fn validate_lifecycle_smoke_local_args(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    if args.is_empty() {
        Ok(())
    } else {
        Err(config_error(
            "usage: cairn-api email-outbox lifecycle-smoke-local",
        ))
    }
}

pub(super) fn recipient_is_reserved_local_address(value: &str) -> bool {
    let value = value.trim();
    value.contains('@')
        && value.ends_with(".invalid")
        && !value.chars().any(char::is_whitespace)
        && !value.chars().any(char::is_control)
}

pub(super) fn lifecycle_smoke_message_specs() -> &'static [LifecycleSmokeMessageSpec] {
    &[
        LifecycleSmokeMessageSpec {
            kind: "invitation",
            template: "account_invitation",
            subject: "Accept your Cairn Identity invitation",
            action_path: Some("/accept-invitation"),
            body_intro: "You have been invited to Cairn Identity.",
            token_kind: Some(AccountTokenKind::Invitation),
            ttl_seconds: Some(7 * 24 * 60 * 60),
        },
        LifecycleSmokeMessageSpec {
            kind: "email_verification",
            template: "email_verification",
            subject: "Verify your Cairn Identity email",
            action_path: Some("/verify-email"),
            body_intro: "Verify this email address for Cairn Identity.",
            token_kind: Some(AccountTokenKind::EmailVerification),
            ttl_seconds: Some(24 * 60 * 60),
        },
        LifecycleSmokeMessageSpec {
            kind: "password_recovery",
            template: "password_recovery",
            subject: "Reset your Cairn Identity password",
            action_path: Some("/reset-password"),
            body_intro: "Reset your Cairn Identity password.",
            token_kind: Some(AccountTokenKind::PasswordRecovery),
            ttl_seconds: Some(60 * 60),
        },
        LifecycleSmokeMessageSpec {
            kind: "password_recovered_notification",
            template: "password_recovered_notification",
            subject: "Your Cairn Identity password was reset",
            action_path: None,
            body_intro: "Your Cairn Identity password was reset using account recovery.",
            token_kind: None,
            ttl_seconds: None,
        },
        LifecycleSmokeMessageSpec {
            kind: "password_changed_notification",
            template: "password_changed_notification",
            subject: "Your Cairn Identity password was changed",
            action_path: None,
            body_intro: "Your Cairn Identity password was changed.",
            token_kind: None,
            ttl_seconds: None,
        },
        LifecycleSmokeMessageSpec {
            kind: "new_login_notification",
            template: "new_login_notification",
            subject: "New Cairn Identity sign-in",
            action_path: None,
            body_intro: "A new Cairn Identity sign-in was detected.",
            token_kind: None,
            ttl_seconds: None,
        },
    ]
}

async fn unfinished_queue_summary(
    database: &Database,
    config: &ApiConfig,
) -> Result<EmailOutboxQueueSummary, Box<dyn std::error::Error>> {
    let now = OffsetDateTime::now_utc();
    let stale_sending_before =
        now - Duration::seconds(config.email_delivery.sending_timeout_seconds);
    Ok(database
        .email_outbox_queue_summary(now, stale_sending_before)
        .await?)
}

async fn ensure_local_organization(
    database: &Database,
    config: &ApiConfig,
) -> Result<Organization, Box<dyn std::error::Error>> {
    match database
        .get_organization_by_slug(&config.default_org_slug)
        .await?
    {
        Some(organization) => Ok(organization),
        None => {
            let organization = Organization::new(&config.default_org_slug, "Default Organization")?;
            database.create_organization(&organization).await?;
            Ok(organization)
        }
    }
}

async fn queue_lifecycle_smoke_messages(
    database: &Database,
    organization_id: OrganizationId,
    recipient_email: &str,
    key: &KeyEncryptionKey,
    now: OffsetDateTime,
) -> Result<(), Box<dyn std::error::Error>> {
    let run_id = Uuid::new_v4();
    for spec in lifecycle_smoke_message_specs() {
        let message = lifecycle_smoke_message(spec, organization_id, recipient_email, run_id, now);
        match (spec.token_kind, spec.ttl_seconds) {
            (Some(token_kind), Some(ttl_seconds)) => {
                let secret = generate_hashed_secret(32);
                let encrypted = encrypt_secret(
                    secret.value.expose_secret(),
                    key,
                    &account_token_aad(spec.kind, secret.id),
                )?;
                let token = AccountToken {
                    id: secret.id,
                    organization_id,
                    kind: token_kind,
                    user_id: None,
                    email: recipient_email.to_owned(),
                    token_hash: secret.hash,
                    created_by_user_id: None,
                    created_at: now,
                    expires_at: now + Duration::seconds(ttl_seconds),
                    consumed_at: None,
                    metadata: json!({
                        "lifecycle_smoke": true,
                        "smoke_run_id": run_id,
                    }),
                };
                let mut message = message;
                message.delivery_token_ciphertext = Some(encrypted.ciphertext);
                message.delivery_token_nonce = Some(encrypted.nonce);
                message.metadata["account_token_id"] = json!(token.id);
                database
                    .insert_account_token_and_email_outbox_message(&token, &message)
                    .await?;
            }
            (None, None) => {
                database.insert_email_outbox_message(&message).await?;
            }
            _ => {
                return Err(config_error(
                    "lifecycle smoke message spec has inconsistent token settings",
                ));
            }
        }
    }
    Ok(())
}

fn lifecycle_smoke_message(
    spec: &LifecycleSmokeMessageSpec,
    organization_id: OrganizationId,
    recipient_email: &str,
    run_id: Uuid,
    now: OffsetDateTime,
) -> EmailOutboxMessage {
    let body_text = if spec.action_path.is_some() {
        format!(
            "{}\n\nOpen this link to continue: {{{{action_url}}}}\n\nIf you did not request this email, ignore it.",
            spec.body_intro
        )
    } else {
        format!(
            "{}\n\nTime: {}\nIP address: Unknown\nBrowser: lifecycle-smoke-local\n\nThis local smoke message contains no account token.",
            spec.body_intro,
            now.format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_else(|_| "unknown".to_owned())
        )
    };

    EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id,
        recipient_email: recipient_email.to_owned(),
        subject: spec.subject.to_owned(),
        body_text,
        template: spec.template.to_owned(),
        action_path: spec.action_path.map(str::to_owned),
        delivery_token_ciphertext: None,
        delivery_token_nonce: None,
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({
            "kind": spec.kind,
            "lifecycle_smoke": true,
            "smoke_run_id": run_id,
        }),
        created_at: now,
        updated_at: now,
        next_attempt_at: None,
        sent_at: None,
    }
}

fn account_token_aad(kind: &str, token_id: Uuid) -> String {
    format!("cairnid:account-token-delivery:{kind}:{token_id}")
}

fn local_smoke_key() -> Result<KeyEncryptionKey, cairn_oidc::OidcError> {
    KeyEncryptionKey::from_base64_url_no_pad(&URL_SAFE_NO_PAD.encode([42_u8; 32]))
}

fn refuse_production_environment() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var("CAIRN_ENV").is_ok_and(|value| value == "production") {
        return Err(config_error(
            "lifecycle-smoke-local is development-only and refuses CAIRN_ENV=production",
        ));
    }
    Ok(())
}

struct LocalFakeProviderCommand {
    root: PathBuf,
    path: PathBuf,
}

impl LocalFakeProviderCommand {
    fn create() -> Result<Self, std::io::Error> {
        let root = std::env::temp_dir().join(format!(
            "cairnid-lifecycle-smoke-provider-{}",
            Uuid::new_v4()
        ));
        fs::create_dir(&root)?;

        #[cfg(windows)]
        let path = root.join("cairnid-local-fake-email-provider.cmd");
        #[cfg(not(windows))]
        let path = root.join("cairnid-local-fake-email-provider");

        fs::write(&path, local_fake_provider_script())?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut permissions = fs::metadata(&path)?.permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions)?;
        }

        Ok(Self { root, path })
    }

    fn path_string(&self) -> String {
        self.path.to_string_lossy().into_owned()
    }
}

impl Drop for LocalFakeProviderCommand {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[cfg(windows)]
fn local_fake_provider_script() -> String {
    format!(
        "@echo off\r\nmore > nul\r\necho {{\"provider_message_id\":\"{LOCAL_FAKE_PROVIDER_MESSAGE_ID}\"}}\r\n"
    )
}

#[cfg(not(windows))]
fn local_fake_provider_script() -> String {
    format!(
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{{\"provider_message_id\":\"{LOCAL_FAKE_PROVIDER_MESSAGE_ID}\"}}'\n"
    )
}
