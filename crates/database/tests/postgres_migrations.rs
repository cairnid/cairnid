#![forbid(unsafe_code)]

use std::{collections::BTreeSet, error::Error, path::Path};

use cairn_database::Database;

#[test]
fn migration_files_have_unique_contiguous_versions() -> Result<(), Box<dyn Error>> {
    let migrations = migration_versions()?;
    assert!(
        !migrations.is_empty(),
        "migration directory must contain SQL migrations"
    );

    for (index, version) in migrations.iter().enumerate() {
        let expected = (index + 1) as i64;
        assert_eq!(
            *version, expected,
            "migration versions must be contiguous; expected {expected:04}, found {version:04}"
        );
    }

    Ok(())
}

#[tokio::test]
async fn migrations_apply_to_postgres() -> Result<(), Box<dyn Error>> {
    let Some(database_url) = std::env::var("CAIRN_DATABASE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipping Postgres migration smoke; CAIRN_DATABASE_TEST_URL is not set");
        return Ok(());
    };

    let database = Database::connect(&database_url).await?;
    database.migrate().await?;
    database.health_check().await?;

    let applied_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations WHERE success = TRUE")
            .fetch_one(database.pool())
            .await?;
    assert_eq!(applied_count, expected_migration_count()?);

    let tables: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT table_name
        FROM information_schema.tables
        WHERE table_schema = 'public'
          AND table_type = 'BASE TABLE'
        ORDER BY table_name
        "#,
    )
    .fetch_all(database.pool())
    .await?;

    for table in [
        "account_tokens",
        "access_tokens",
        "audit_events",
        "authorization_codes",
        "auth_sessions",
        "consent_authorizations",
        "consent_grants",
        "consent_policy_templates",
        "email_outbox",
        "groups",
        "memberships",
        "mfa_credentials",
        "oidc_clients",
        "organizations",
        "rate_limit_buckets",
        "refresh_tokens",
        "signing_keys",
        "users",
        "webauthn_challenges",
    ] {
        assert!(
            tables.iter().any(|candidate| candidate == table),
            "missing migrated table {table}"
        );
    }

    let user_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'users'
        "#,
    )
    .fetch_all(database.pool())
    .await?;
    assert!(
        user_columns
            .iter()
            .any(|candidate| candidate == "email_verified"),
        "missing users column email_verified"
    );

    let signing_key_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'signing_keys'
        "#,
    )
    .fetch_all(database.pool())
    .await?;

    for column in [
        "private_key_ciphertext",
        "private_key_nonce",
        "signing_active",
    ] {
        assert!(
            signing_key_columns
                .iter()
                .any(|candidate| candidate == column),
            "missing signing_keys column {column}"
        );
    }

    let access_token_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'access_tokens'
        "#,
    )
    .fetch_all(database.pool())
    .await?;
    assert!(
        access_token_columns
            .iter()
            .any(|candidate| candidate == "refresh_family_id"),
        "missing access_tokens column refresh_family_id"
    );

    let email_outbox_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'email_outbox'
        "#,
    )
    .fetch_all(database.pool())
    .await?;

    for column in [
        "attempts",
        "last_error",
        "provider_message_id",
        "next_attempt_at",
        "updated_at",
    ] {
        assert!(
            email_outbox_columns
                .iter()
                .any(|candidate| candidate == column),
            "missing email_outbox column {column}"
        );
    }

    let webauthn_challenge_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'webauthn_challenges'
        "#,
    )
    .fetch_all(database.pool())
    .await?;

    for column in ["kind", "state", "expires_at", "consumed_at"] {
        assert!(
            webauthn_challenge_columns
                .iter()
                .any(|candidate| candidate == column),
            "missing webauthn_challenges column {column}"
        );
    }

    let oidc_client_columns: Vec<String> = sqlx::query_scalar(
        r#"
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'public'
          AND table_name = 'oidc_clients'
        "#,
    )
    .fetch_all(database.pool())
    .await?;
    assert!(
        oidc_client_columns
            .iter()
            .any(|candidate| candidate == "consent_policy_template_id"),
        "missing oidc_clients column consent_policy_template_id"
    );
    assert!(
        oidc_client_columns
            .iter()
            .any(|candidate| candidate == "status"),
        "missing oidc_clients column status"
    );

    Ok(())
}

fn expected_migration_count() -> Result<i64, Box<dyn Error>> {
    Ok(migration_versions()?.len() as i64)
}

fn migration_versions() -> Result<Vec<i64>, Box<dyn Error>> {
    let migrations_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../infra/migrations");
    let mut versions = BTreeSet::new();

    for entry in std::fs::read_dir(migrations_dir)? {
        let entry = entry?;
        let path = entry.path();
        let is_sql = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension == "sql");
        if !is_sql {
            continue;
        }

        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or("migration filename must be valid UTF-8")?;
        let (version, _) = file_name
            .split_once('_')
            .ok_or("migration filename must start with a numeric version and underscore")?;
        assert_eq!(
            version.len(),
            4,
            "migration version prefix must be four digits in {file_name}"
        );
        let version = version
            .parse::<i64>()
            .map_err(|_| format!("migration version must be numeric in {file_name}"))?;
        assert!(
            versions.insert(version),
            "duplicate migration version {version:04} in {file_name}"
        );
    }

    Ok(versions.into_iter().collect())
}
