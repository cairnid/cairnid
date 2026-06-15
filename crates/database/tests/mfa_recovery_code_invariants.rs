#![forbid(unsafe_code)]

use std::error::Error;

use cairn_database::Database;
use cairn_domain::{MfaCredential, MfaKind, Organization, User};
use serde_json::json;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

#[tokio::test]
async fn recovery_code_consumption_is_atomic_and_single_use() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::now_utc();
    let organization = Organization::new(
        format!("mfa-recovery-consume-{}", Uuid::new_v4()),
        "Test Organization",
    )?;
    database.create_organization(&organization).await?;
    let user = User::new(
        organization.id,
        format!("mfa-recovery-{}@example.com", Uuid::new_v4()),
        "Test User",
    )?;
    database.create_user(&user, None).await?;

    let code_hash = format!("test-recovery-code-hash-{}", Uuid::new_v4());
    let recovery_credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "code_hash": code_hash.clone()
        }),
        created_at: now,
        last_used_at: None,
    };
    database.create_mfa_credential(&recovery_credential).await?;

    let first_database = database.clone();
    let second_database = database.clone();
    let first_used_at = now + Duration::minutes(1);
    let second_used_at = now + Duration::minutes(2);
    let (first_result, second_result) = tokio::join!(
        first_database.consume_active_recovery_code(
            organization.id,
            user.id,
            &code_hash,
            first_used_at,
        ),
        second_database.consume_active_recovery_code(
            organization.id,
            user.id,
            &code_hash,
            second_used_at,
        )
    );
    let first_consumed = first_result?;
    let second_consumed = second_result?;

    assert_ne!(
        first_consumed, second_consumed,
        "exactly one concurrent consume should win"
    );
    assert!(
        !database
            .consume_active_recovery_code(
                organization.id,
                user.id,
                &code_hash,
                now + Duration::minutes(3),
            )
            .await?
    );

    let credentials = database
        .list_mfa_credentials(organization.id, user.id, MfaKind::RecoveryCode)
        .await?;
    let consumed_credential = credentials
        .iter()
        .find(|credential| credential.id == recovery_credential.id)
        .expect("recovery credential exists");
    assert_eq!(
        consumed_credential.secret_metadata["status"],
        json!("consumed")
    );
    assert_eq!(
        consumed_credential.secret_metadata["code_hash"],
        json!(code_hash)
    );
    let expected_used_at = if first_consumed {
        first_used_at
    } else {
        second_used_at
    };
    assert_eq!(
        consumed_credential.last_used_at.map(unix_timestamp_micros),
        Some(unix_timestamp_micros(expected_used_at))
    );
    Ok(())
}

fn unix_timestamp_micros(timestamp: OffsetDateTime) -> i128 {
    timestamp.unix_timestamp_nanos() / 1_000
}

async fn test_database() -> Result<Option<Database>, Box<dyn Error>> {
    let Some(database_url) = std::env::var("CAIRN_DATABASE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipping MFA recovery-code invariants; CAIRN_DATABASE_TEST_URL is not set");
        return Ok(None);
    };

    let database = Database::connect(&database_url).await?;
    database.migrate().await?;
    Ok(Some(database))
}
