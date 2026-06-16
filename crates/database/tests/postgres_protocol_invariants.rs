#![forbid(unsafe_code)]

use std::{cmp::Reverse, error::Error};

use cairn_authn::hash_token;
use cairn_database::{
    AccessTokenRecord, AuditEventListFilter, AuthSessionCreationInput,
    ConsentAuthorizationConsumption, ConsentGrantListFilter, Database, DatabaseError, ListCursor,
    MembershipMutationOutcome, OidcClientListFilter, OidcClientStatusMutationOutcome,
    PasswordChangeInput, PasswordChangeOutcome, PasswordRecoveryInput, PasswordRecoveryOutcome,
    ScimUserListFilter, ScimUserUpdateInput, ScimUserUpdateOutcome, SessionRequestContext,
    UserListFilter, UserStatusMutationOutcome,
};
use cairn_domain::{
    AccountToken, AccountTokenKind, AuditActorKind, AuditEvent, AuthSession, AuthorizationCode,
    ConsentAuthorization, ConsentGrant, ConsentGrantMode, ConsentPolicyTemplate,
    EmailOutboxMessage, Group, Membership, MembershipRole, MfaCredential, MfaKind, OidcClient,
    OidcClientStatus, OidcGrantType, Organization, PkceMethod, RedirectUri, RefreshToken,
    SigningKeyMaterial, User, UserStatus, WebAuthnChallenge, WebAuthnChallengeKind,
};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

static EMAIL_OUTBOX_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn assert_db_timestamp_eq(actual: OffsetDateTime, expected: OffsetDateTime) {
    assert_eq!(
        unix_timestamp_micros(actual),
        unix_timestamp_micros(expected),
        "timestamp mismatch: actual={actual}, expected={expected}"
    );
}

fn assert_db_optional_timestamp_eq(
    actual: Option<OffsetDateTime>,
    expected: Option<OffsetDateTime>,
) {
    match (actual, expected) {
        (Some(actual), Some(expected)) => assert_db_timestamp_eq(actual, expected),
        (actual, expected) => assert_eq!(actual, expected),
    }
}

fn unix_timestamp_micros(timestamp: OffsetDateTime) -> i128 {
    timestamp.unix_timestamp_nanos() / 1_000
}

#[tokio::test]
async fn authorization_code_exchange_is_atomic() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "auth-code").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let code_hash = hash_token("auth-code-secret");

    database
        .insert_authorization_code(&AuthorizationCode {
            code_hash: code_hash.clone(),
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            session_id: fixture.session.id,
            client_id: fixture.client.id,
            redirect_uri: "http://localhost:3000/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            nonce: Some("nonce-1".to_owned()),
            code_challenge: "challenge".to_owned(),
            code_challenge_method: PkceMethod::S256,
            created_at: now,
            expires_at: now + Duration::minutes(5),
            used_at: None,
        })
        .await?;

    let first_access = access_token(&fixture, "access-1", now);
    let first_refresh = refresh_token(&fixture, "refresh-1", Uuid::new_v4(), now);
    let second_access = access_token(&fixture, "access-2", now);
    let second_refresh = refresh_token(&fixture, "refresh-2", Uuid::new_v4(), now);

    assert!(
        database
            .consume_authorization_code_and_insert_tokens(
                &code_hash,
                &first_access,
                Some(&first_refresh),
                now
            )
            .await?
    );
    assert!(
        !database
            .consume_authorization_code_and_insert_tokens(
                &code_hash,
                &second_access,
                Some(&second_refresh),
                now
            )
            .await?
    );

    let issued_access_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens WHERE token_hash IN ($1, $2)")
            .bind(&first_access.token_hash)
            .bind(&second_access.token_hash)
            .fetch_one(database.pool())
            .await?;
    let issued_refresh_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE token_hash IN ($1, $2)")
            .bind(&first_refresh.token_hash)
            .bind(&second_refresh.token_hash)
            .fetch_one(database.pool())
            .await?;
    let used_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT used_at FROM authorization_codes WHERE code_hash = $1")
            .bind(&code_hash)
            .fetch_one(database.pool())
            .await?;

    assert_eq!(issued_access_count, 1);
    assert_eq!(issued_refresh_count, 1);
    assert!(used_at.is_some());
    Ok(())
}

#[tokio::test]
async fn authorization_code_exchange_can_omit_refresh_token() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "auth-code-no-refresh").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let code_hash = hash_token("auth-code-no-refresh-secret");

    database
        .insert_authorization_code(&AuthorizationCode {
            code_hash: code_hash.clone(),
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            session_id: fixture.session.id,
            client_id: fixture.client.id,
            redirect_uri: "http://localhost:3000/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "profile".to_owned()],
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: PkceMethod::S256,
            created_at: now,
            expires_at: now + Duration::minutes(5),
            used_at: None,
        })
        .await?;

    let access = access_token(&fixture, "access-no-refresh", now);
    assert!(
        database
            .consume_authorization_code_and_insert_tokens(&code_hash, &access, None, now)
            .await?
    );

    let issued_access_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens WHERE token_hash = $1")
            .bind(&access.token_hash)
            .fetch_one(database.pool())
            .await?;
    let issued_refresh_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE client_id = $1")
            .bind(fixture.client.id)
            .fetch_one(database.pool())
            .await?;

    assert_eq!(issued_access_count, 1);
    assert_eq!(issued_refresh_count, 0);
    Ok(())
}

#[tokio::test]
async fn refresh_token_rotation_is_atomic() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "refresh").await?;
    let now = OffsetDateTime::now_utc();
    let family_id = Uuid::new_v4();
    let original_hash = hash_token("refresh-original");
    let original = RefreshToken {
        id: Uuid::new_v4(),
        token_hash: original_hash.clone(),
        family_id,
        organization_id: fixture.organization.id,
        user_id: Some(fixture.user.id),
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        created_at: now,
        expires_at: now + Duration::days(30),
        rotated_at: None,
        revoked_at: None,
    };
    database.insert_refresh_token(&original).await?;

    let first_access = access_token(&fixture, "refresh-access-1", now);
    let first_refresh = refresh_token(&fixture, "refresh-next-1", family_id, now);
    let second_access = access_token(&fixture, "refresh-access-2", now);
    let second_refresh = refresh_token(&fixture, "refresh-next-2", family_id, now);

    assert!(
        database
            .rotate_refresh_token_and_insert_tokens(
                &original_hash,
                &first_access,
                Some(&first_refresh),
                now
            )
            .await?
    );
    assert!(
        !database
            .rotate_refresh_token_and_insert_tokens(
                &original_hash,
                &second_access,
                Some(&second_refresh),
                now
            )
            .await?
    );

    let issued_access_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM access_tokens WHERE token_hash IN ($1, $2)")
            .bind(&first_access.token_hash)
            .bind(&second_access.token_hash)
            .fetch_one(database.pool())
            .await?;
    let issued_refresh_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM refresh_tokens WHERE token_hash IN ($1, $2)")
            .bind(&first_refresh.token_hash)
            .bind(&second_refresh.token_hash)
            .fetch_one(database.pool())
            .await?;
    let rotated_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT rotated_at FROM refresh_tokens WHERE token_hash = $1")
            .bind(&original_hash)
            .fetch_one(database.pool())
            .await?;

    assert_eq!(issued_access_count, 1);
    assert_eq!(issued_refresh_count, 1);
    assert!(rotated_at.is_some());
    Ok(())
}

#[tokio::test]
async fn refresh_family_revocation_revokes_linked_access_tokens() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "refresh-family-revoke").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let family_id = Uuid::new_v4();
    let first_refresh = refresh_token(&fixture, "family-refresh-1", family_id, now);
    let second_refresh = refresh_token(&fixture, "family-refresh-2", family_id, now);
    let mut linked_access = access_token(&fixture, "family-access-linked", now);
    linked_access.refresh_family_id = Some(family_id);
    let mut unrelated_family_access = access_token(&fixture, "family-access-unrelated", now);
    unrelated_family_access.refresh_family_id = Some(Uuid::new_v4());
    let unlinked_access = access_token(&fixture, "family-access-unlinked", now);

    database.insert_refresh_token(&first_refresh).await?;
    database.insert_refresh_token(&second_refresh).await?;
    database.insert_access_token(&linked_access).await?;
    database
        .insert_access_token(&unrelated_family_access)
        .await?;
    database.insert_access_token(&unlinked_access).await?;

    database
        .revoke_refresh_token_family_and_access_tokens(family_id, now)
        .await?;

    let revoked_refresh_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM refresh_tokens WHERE family_id = $1 AND revoked_at IS NOT NULL",
    )
    .bind(family_id)
    .fetch_one(database.pool())
    .await?;
    let linked = database
        .get_access_token(&linked_access.token_hash)
        .await?
        .expect("linked access token exists");
    let unrelated = database
        .get_access_token(&unrelated_family_access.token_hash)
        .await?
        .expect("unrelated access token exists");
    let unlinked = database
        .get_access_token(&unlinked_access.token_hash)
        .await?
        .expect("unlinked access token exists");

    assert_eq!(revoked_refresh_count, 2);
    assert_db_optional_timestamp_eq(linked.revoked_at, Some(now));
    assert_eq!(unrelated.revoked_at, None);
    assert_eq!(unlinked.revoked_at, None);
    Ok(())
}

#[tokio::test]
async fn account_token_consumption_updates_user_once() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "account-token").await?;
    let now = OffsetDateTime::now_utc();
    let token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        kind: AccountTokenKind::EmailVerification,
        user_id: Some(fixture.user.id),
        email: fixture.user.email.clone(),
        token_hash: hash_token("verify-email-token"),
        created_by_user_id: None,
        created_at: now,
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    database.insert_account_token(&token).await?;

    let first_database = database.clone();
    let second_database = database.clone();
    let token_id = token.id;
    let user_id = fixture.user.id;
    let (first, second) = tokio::join!(
        first_database.consume_account_token_and_set_user_email_verified(token_id, user_id, now),
        second_database.consume_account_token_and_set_user_email_verified(token_id, user_id, now)
    );
    let successes = [first?, second?]
        .into_iter()
        .filter(|consumed| *consumed)
        .count();
    let user = database
        .get_user(fixture.user.id)
        .await?
        .expect("fixture user exists");
    let consumed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM account_tokens WHERE id = $1")
            .bind(token.id)
            .fetch_one(database.pool())
            .await?;

    assert_eq!(successes, 1);
    assert!(user.email_verified);
    assert!(consumed_at.is_some());
    Ok(())
}

#[tokio::test]
async fn account_lifecycle_tokens_require_current_active_account_state()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let now = OffsetDateTime::from_unix_timestamp(1_800_001_000)?;
    let token_for = |kind: AccountTokenKind, user: &User, seed: &str| AccountToken {
        id: Uuid::new_v4(),
        organization_id: user.organization_id,
        kind,
        user_id: Some(user.id),
        email: user.email.clone(),
        token_hash: hash_token(seed),
        created_by_user_id: None,
        created_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };

    let inactive_passwordless =
        create_fixture(&database, "inactive-lifecycle-passwordless").await?;
    let verification_token = token_for(
        AccountTokenKind::EmailVerification,
        &inactive_passwordless.user,
        "inactive-email-verification",
    );
    let invitation_token = token_for(
        AccountTokenKind::Invitation,
        &inactive_passwordless.user,
        "inactive-invitation",
    );
    database.insert_account_token(&verification_token).await?;
    database.insert_account_token(&invitation_token).await?;
    assert!(matches!(
        database
            .update_user_status(
                inactive_passwordless.organization.id,
                inactive_passwordless.user.id,
                UserStatus::Suspended,
                "administrators",
                now
            )
            .await?,
        UserStatusMutationOutcome::Applied(_)
    ));

    assert!(
        !database
            .consume_account_token_and_set_user_email_verified(
                verification_token.id,
                inactive_passwordless.user.id,
                now + Duration::seconds(1)
            )
            .await?
    );
    assert!(
        !database
            .consume_account_token_and_set_user_password(
                invitation_token.id,
                inactive_passwordless.user.id,
                "inactive-invitation-password",
                true,
                false,
                now + Duration::seconds(1)
            )
            .await?
    );

    let inactive_password_user = create_fixture(&database, "inactive-lifecycle-recovery").await?;
    database
        .set_user_password_and_email_verified(
            inactive_password_user.user.id,
            "existing-recovery-password",
            true,
            now,
        )
        .await?;
    let recovery_token = token_for(
        AccountTokenKind::PasswordRecovery,
        &inactive_password_user.user,
        "inactive-password-recovery",
    );
    database.insert_account_token(&recovery_token).await?;
    assert!(matches!(
        database
            .update_user_status(
                inactive_password_user.organization.id,
                inactive_password_user.user.id,
                UserStatus::Locked,
                "administrators",
                now + Duration::seconds(1)
            )
            .await?,
        UserStatusMutationOutcome::Applied(_)
    ));
    assert!(matches!(
        database
            .consume_password_recovery_token_and_reset_user_password(PasswordRecoveryInput {
                organization_id: inactive_password_user.organization.id,
                user_id: inactive_password_user.user.id,
                token_id: recovery_token.id,
                password_hash: "inactive-recovered-password",
                notification: None,
                at: now + Duration::seconds(2),
            })
            .await?,
        PasswordRecoveryOutcome::NotFound
    ));

    let active_password_user = create_fixture(&database, "active-invitation-stale").await?;
    let stale_invitation_token = token_for(
        AccountTokenKind::Invitation,
        &active_password_user.user,
        "active-stale-invitation",
    );
    database
        .insert_account_token(&stale_invitation_token)
        .await?;
    database
        .set_user_password_and_email_verified(
            active_password_user.user.id,
            "current-active-password",
            true,
            now,
        )
        .await?;
    assert!(
        !database
            .consume_account_token_and_set_user_password(
                stale_invitation_token.id,
                active_password_user.user.id,
                "stale-invitation-password",
                true,
                false,
                now + Duration::seconds(1)
            )
            .await?
    );

    let active_password: String =
        sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
            .bind(active_password_user.user.id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(active_password, "current-active-password");

    let consumed_token_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM account_tokens
        WHERE id IN ($1, $2, $3, $4)
          AND consumed_at IS NOT NULL
        "#,
    )
    .bind(verification_token.id)
    .bind(invitation_token.id)
    .bind(recovery_token.id)
    .bind(stale_invitation_token.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(consumed_token_count, 0);

    Ok(())
}

#[tokio::test]
async fn password_recovery_reset_revokes_sessions_tokens_and_pending_recovery_links()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    let fixture = create_fixture(&database, "password-recovery-reset").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_001_500)?;
    database
        .set_user_password_and_email_verified(
            fixture.user.id,
            "existing-password-hash",
            true,
            now - Duration::minutes(10),
        )
        .await?;
    let second_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password".to_owned(),
        amr: vec!["pwd".to_owned()],
        created_at: now - Duration::hours(1),
        expires_at: now + Duration::hours(1),
        revoked_at: None,
    };
    database.create_auth_session(&second_session).await?;

    let family_id = Uuid::new_v4();
    let access = access_token(&fixture, "password-recovery-access", now);
    let refresh = refresh_token(&fixture, "password-recovery-refresh", family_id, now);
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;

    let recovery_token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        kind: AccountTokenKind::PasswordRecovery,
        user_id: Some(fixture.user.id),
        email: fixture.user.email.clone(),
        token_hash: hash_token("password-recovery-reset"),
        created_by_user_id: None,
        created_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    let sibling_recovery_token = AccountToken {
        id: Uuid::new_v4(),
        token_hash: hash_token("password-recovery-reset-sibling"),
        ..recovery_token.clone()
    };
    let expired_recovery_token = AccountToken {
        id: Uuid::new_v4(),
        token_hash: hash_token("password-recovery-reset-expired"),
        expires_at: now - Duration::seconds(1),
        ..recovery_token.clone()
    };
    database.insert_account_token(&recovery_token).await?;
    database
        .insert_account_token(&sibling_recovery_token)
        .await?;
    database
        .insert_account_token(&expired_recovery_token)
        .await?;
    let notification = EmailOutboxMessage {
        template: "password_recovered_notification".to_owned(),
        subject: "Password recovered".to_owned(),
        metadata: json!({
            "kind": "password_recovered_notification",
            "user_id": fixture.user.id,
            "account_token_id": recovery_token.id
        }),
        ..email_message(fixture.organization.id, fixture.user.email.clone(), now)
    };

    let mutation = match database
        .consume_password_recovery_token_and_reset_user_password(PasswordRecoveryInput {
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            token_id: recovery_token.id,
            password_hash: "recovered-password-hash",
            notification: Some(&notification),
            at: now,
        })
        .await?
    {
        PasswordRecoveryOutcome::Applied(mutation) => *mutation,
        PasswordRecoveryOutcome::NotFound => panic!("fixture recovery token should apply"),
    };

    assert_eq!(mutation.sessions_revoked, 2);
    assert_eq!(mutation.access_tokens_revoked, 1);
    assert_eq!(mutation.refresh_tokens_revoked, 1);
    assert_eq!(mutation.account_tokens_consumed, 2);
    assert_eq!(mutation.notification_email_outbox_id, Some(notification.id));

    let stored_user: (String, bool) =
        sqlx::query_as("SELECT password_hash, email_verified FROM users WHERE id = $1")
            .bind(fixture.user.id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(stored_user.0, "recovered-password-hash");
    assert!(stored_user.1);
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(fixture.session.id)
            .await?
            .expect("fixture session exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(second_session.id)
            .await?
            .expect("second session exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(now),
    );

    let token_states: Vec<(Uuid, Option<OffsetDateTime>)> = sqlx::query_as(
        r#"
        SELECT id, consumed_at
        FROM account_tokens
        WHERE id IN ($1, $2, $3)
        ORDER BY id
        "#,
    )
    .bind(recovery_token.id)
    .bind(sibling_recovery_token.id)
    .bind(expired_recovery_token.id)
    .fetch_all(database.pool())
    .await?;
    assert_eq!(token_states.len(), 3);
    assert_eq!(
        token_states
            .iter()
            .filter(|(_, consumed_at)| {
                consumed_at.map(unix_timestamp_micros) == Some(unix_timestamp_micros(now))
            })
            .count(),
        2
    );
    assert!(
        token_states
            .iter()
            .any(|(id, consumed_at)| *id == expired_recovery_token.id && consumed_at.is_none())
    );
    type PasswordRecoveredNotificationOutboxRow = (
        String,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        sqlx::types::Json<Value>,
    );

    let (
        notification_recipient,
        notification_template,
        notification_action_path,
        notification_ciphertext,
        notification_nonce,
        sqlx::types::Json(notification_metadata),
    ): PasswordRecoveredNotificationOutboxRow = sqlx::query_as(
        r#"
        SELECT recipient_email, template, action_path, delivery_token_ciphertext,
               delivery_token_nonce, metadata
        FROM email_outbox
        WHERE id = $1
        "#,
    )
    .bind(notification.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(notification_recipient, fixture.user.email);
    assert_eq!(notification_template, "password_recovered_notification");
    assert_eq!(notification_action_path, None);
    assert_eq!(notification_ciphertext, None);
    assert_eq!(notification_nonce, None);
    assert_eq!(
        notification_metadata["kind"],
        json!("password_recovered_notification")
    );
    assert!(matches!(
        database
            .consume_password_recovery_token_and_reset_user_password(PasswordRecoveryInput {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                token_id: recovery_token.id,
                password_hash: "second-recovered-password-hash",
                notification: None,
                at: now + Duration::seconds(1),
            })
            .await?,
        PasswordRecoveryOutcome::NotFound
    ));

    Ok(())
}

#[tokio::test]
async fn password_change_rotates_session_and_revokes_user_credentials_transactionally()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    let fixture = create_fixture(&database, "password-change").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_002_000)?;
    let second_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password".to_owned(),
        amr: vec!["pwd".to_owned()],
        created_at: now - Duration::hours(1),
        expires_at: now + Duration::hours(1),
        revoked_at: None,
    };
    database.create_auth_session(&second_session).await?;

    let family_id = Uuid::new_v4();
    let access = access_token(&fixture, "password-change-access", now);
    let refresh = refresh_token(&fixture, "password-change-refresh", family_id, now);
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;

    let recovery_token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        kind: AccountTokenKind::PasswordRecovery,
        user_id: Some(fixture.user.id),
        email: fixture.user.email.clone(),
        token_hash: hash_token("password-change-recovery"),
        created_by_user_id: None,
        created_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    database.insert_account_token(&recovery_token).await?;

    let new_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password+totp".to_owned(),
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        created_at: now - Duration::minutes(2),
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    };
    let notification = EmailOutboxMessage {
        template: "password_changed_notification".to_owned(),
        subject: "Password changed".to_owned(),
        metadata: json!({
            "kind": "password_changed_notification",
            "user_id": fixture.user.id,
            "session_id": new_session.id
        }),
        ..email_message(fixture.organization.id, fixture.user.email.clone(), now)
    };
    let mutation = match database
        .change_user_password_and_rotate_session(PasswordChangeInput {
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            password_hash: "new-password-hash",
            new_session: &new_session,
            request_context: SessionRequestContext::new(
                Some("203.0.113.10"),
                Some("Session Test/1.0"),
            ),
            notification: Some(&notification),
            at: now,
        })
        .await?
    {
        PasswordChangeOutcome::Applied(mutation) => *mutation,
        PasswordChangeOutcome::NotFound => panic!("fixture user should exist"),
    };

    assert_eq!(mutation.session.id, new_session.id);
    assert_eq!(mutation.sessions_revoked, 2);
    assert_eq!(mutation.access_tokens_revoked, 1);
    assert_eq!(mutation.refresh_tokens_revoked, 1);
    assert_eq!(mutation.account_tokens_consumed, 1);
    assert_eq!(mutation.notification_email_outbox_id, Some(notification.id));

    let stored_hash: String = sqlx::query_scalar("SELECT password_hash FROM users WHERE id = $1")
        .bind(fixture.user.id)
        .fetch_one(database.pool())
        .await?;
    assert_eq!(stored_hash, "new-password-hash");
    assert_eq!(
        database
            .get_auth_session(new_session.id)
            .await?
            .expect("new session exists")
            .revoked_at,
        None
    );
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(fixture.session.id)
            .await?
            .expect("fixture session exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(second_session.id)
            .await?
            .expect("second session exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(now),
    );
    let consumed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM account_tokens WHERE id = $1")
            .bind(recovery_token.id)
            .fetch_one(database.pool())
            .await?;
    assert_db_optional_timestamp_eq(consumed_at, Some(now));
    type PasswordChangeNotificationOutboxRow = (
        String,
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        sqlx::types::Json<Value>,
    );

    let (
        notification_recipient,
        notification_template,
        notification_action_path,
        notification_ciphertext,
        notification_nonce,
        sqlx::types::Json(notification_metadata),
    ): PasswordChangeNotificationOutboxRow = sqlx::query_as(
        r#"
        SELECT recipient_email, template, action_path, delivery_token_ciphertext,
               delivery_token_nonce, metadata
        FROM email_outbox
        WHERE id = $1
        "#,
    )
    .bind(notification.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(notification_recipient, fixture.user.email);
    assert_eq!(notification_template, "password_changed_notification");
    assert_eq!(notification_action_path, None);
    assert_eq!(notification_ciphertext, None);
    assert_eq!(notification_nonce, None);
    assert_eq!(
        notification_metadata["kind"],
        json!("password_changed_notification")
    );

    let active_sessions = database
        .list_active_browser_sessions_for_user(fixture.organization.id, fixture.user.id, now, 10)
        .await?;
    assert_eq!(active_sessions.len(), 1);
    assert_eq!(active_sessions[0].id, new_session.id);
    assert_eq!(
        active_sessions[0].created_ip_address.as_deref(),
        Some("203.0.113.10")
    );
    assert_eq!(
        active_sessions[0].created_user_agent.as_deref(),
        Some("Session Test/1.0")
    );
    assert!(
        database
            .revoke_user_browser_session(
                fixture.organization.id,
                fixture.user.id,
                fixture.session.id,
                now + Duration::minutes(1),
            )
            .await?
            .is_none()
    );
    assert!(
        database
            .revoke_user_browser_session(
                fixture.organization.id,
                fixture.user.id,
                new_session.id,
                now + Duration::minutes(1),
            )
            .await?
            .is_some()
    );
    assert!(
        database
            .list_active_browser_sessions_for_user(
                fixture.organization.id,
                fixture.user.id,
                now + Duration::minutes(1),
                10,
            )
            .await?
            .is_empty()
    );

    Ok(())
}

#[tokio::test]
async fn auth_session_new_context_notification_is_transactional_and_suppressed_for_known_context()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    let fixture = create_fixture(&database, "session-new-context").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_002_500)?;
    let first_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password".to_owned(),
        amr: vec!["pwd".to_owned()],
        created_at: now,
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    };
    let first_notification = EmailOutboxMessage {
        template: "new_login_notification".to_owned(),
        subject: "New login".to_owned(),
        metadata: json!({
            "kind": "new_login_notification",
            "user_id": fixture.user.id,
            "session_id": first_session.id
        }),
        ..email_message(fixture.organization.id, fixture.user.email.clone(), now)
    };
    let context = SessionRequestContext::new(Some("203.0.113.77"), Some("Session Test/2.0"));

    let queued_notification_id = database
        .create_auth_session_with_new_context_notification(AuthSessionCreationInput {
            session: &first_session,
            request_context: context,
            new_context_notification: Some(&first_notification),
        })
        .await?;

    assert_eq!(queued_notification_id, Some(first_notification.id));

    type LoginNotificationOutboxRow = (
        String,
        Option<String>,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        sqlx::types::Json<Value>,
    );
    let (
        first_template,
        first_action_path,
        first_ciphertext,
        first_nonce,
        sqlx::types::Json(first_metadata),
    ): LoginNotificationOutboxRow = sqlx::query_as(
        r#"
        SELECT template, action_path, delivery_token_ciphertext,
               delivery_token_nonce, metadata
        FROM email_outbox
        WHERE id = $1
        "#,
    )
    .bind(first_notification.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(first_template, "new_login_notification");
    assert_eq!(first_action_path, None);
    assert_eq!(first_ciphertext, None);
    assert_eq!(first_nonce, None);
    assert_eq!(first_metadata["kind"], json!("new_login_notification"));

    let repeated_session = AuthSession {
        id: Uuid::new_v4(),
        created_at: now + Duration::minutes(1),
        expires_at: now + Duration::hours(12),
        ..first_session.clone()
    };
    let repeated_notification = EmailOutboxMessage {
        template: "new_login_notification".to_owned(),
        subject: "Repeated login".to_owned(),
        metadata: json!({
            "kind": "new_login_notification",
            "user_id": fixture.user.id,
            "session_id": repeated_session.id
        }),
        ..email_message(
            fixture.organization.id,
            fixture.user.email.clone(),
            now + Duration::minutes(1),
        )
    };

    let repeated_notification_id = database
        .create_auth_session_with_new_context_notification(AuthSessionCreationInput {
            session: &repeated_session,
            request_context: context,
            new_context_notification: Some(&repeated_notification),
        })
        .await?;

    assert_eq!(repeated_notification_id, None);
    let repeated_notification_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM email_outbox WHERE id = $1")
            .bind(repeated_notification.id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(repeated_notification_count, 0);

    let new_network_session = AuthSession {
        id: Uuid::new_v4(),
        created_at: now + Duration::minutes(2),
        expires_at: now + Duration::hours(12),
        ..first_session.clone()
    };
    let new_network_notification = EmailOutboxMessage {
        template: "new_login_notification".to_owned(),
        subject: "New network login".to_owned(),
        metadata: json!({
            "kind": "new_login_notification",
            "user_id": fixture.user.id,
            "session_id": new_network_session.id
        }),
        ..email_message(
            fixture.organization.id,
            fixture.user.email.clone(),
            now + Duration::minutes(2),
        )
    };

    let new_network_notification_id = database
        .create_auth_session_with_new_context_notification(AuthSessionCreationInput {
            session: &new_network_session,
            request_context: SessionRequestContext::new(
                Some("203.0.113.78"),
                Some("Session Test/2.0"),
            ),
            new_context_notification: Some(&new_network_notification),
        })
        .await?;

    assert_eq!(
        new_network_notification_id,
        Some(new_network_notification.id)
    );
    let active_context_count: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM auth_sessions
        WHERE organization_id = $1
          AND user_id = $2
          AND created_ip_address IS NOT NULL
        "#,
    )
    .bind(fixture.organization.id)
    .bind(fixture.user.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(active_context_count, 3);

    Ok(())
}

#[tokio::test]
async fn email_outbox_claim_retry_sent_and_stale_reclaim_are_stateful() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    sqlx::query("DELETE FROM email_outbox")
        .execute(database.pool())
        .await?;
    let organization = create_organization(&database, "outbox").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_900_000_000)?;
    let message = email_message(organization.id, "outbox-queued@example.com", now);
    database.insert_email_outbox_message(&message).await?;

    let initial_summary = database
        .email_outbox_queue_summary(now, now - Duration::hours(1))
        .await?;
    assert_eq!(initial_summary.queued, 1);
    assert_eq!(initial_summary.retry, 0);
    assert_eq!(initial_summary.sending, 0);
    assert_eq!(initial_summary.failed, 0);
    assert_eq!(initial_summary.sent, 0);
    assert_eq!(initial_summary.unfinished, 1);
    assert_eq!(
        initial_summary
            .oldest_unfinished_at
            .map(unix_timestamp_micros),
        Some(unix_timestamp_micros(message.created_at))
    );

    let claimed = database
        .claim_email_outbox_messages(1, now, now - Duration::hours(1))
        .await?;
    assert_eq!(claimed.len(), 1);
    assert_eq!(claimed[0].status, "sending");
    assert_eq!(claimed[0].attempts, 1);

    let sending_summary = database
        .email_outbox_queue_summary(now + Duration::seconds(10), now - Duration::seconds(1))
        .await?;
    assert_eq!(sending_summary.queued, 0);
    assert_eq!(sending_summary.sending, 1);
    assert_eq!(sending_summary.stale_sending, 0);

    let not_stale = database
        .claim_email_outbox_messages(1, now + Duration::seconds(10), now - Duration::seconds(1))
        .await?;
    assert!(not_stale.is_empty());

    let stale_summary = database
        .email_outbox_queue_summary(now + Duration::minutes(20), now + Duration::seconds(1))
        .await?;
    assert_eq!(stale_summary.sending, 1);
    assert_eq!(stale_summary.stale_sending, 1);

    let reclaimed = database
        .claim_email_outbox_messages(1, now + Duration::minutes(20), now + Duration::seconds(1))
        .await?;
    assert_eq!(reclaimed.len(), 1);
    assert_eq!(reclaimed[0].attempts, 2);

    assert!(
        database
            .mark_email_outbox_sent(
                message.id,
                Some("provider-message-1"),
                now + Duration::minutes(21)
            )
            .await?
    );
    assert!(
        !database
            .mark_email_outbox_retry(
                message.id,
                "should not update sent row",
                now + Duration::minutes(22),
                now + Duration::minutes(21)
            )
            .await?
    );

    let sent_row: (
        String,
        i32,
        Option<String>,
        Option<String>,
        Option<OffsetDateTime>,
    ) = sqlx::query_as(
        r#"
            SELECT status, attempts, provider_message_id, last_error, sent_at
            FROM email_outbox
            WHERE id = $1
            "#,
    )
    .bind(message.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(sent_row.0, "sent");
    assert_eq!(sent_row.1, 2);
    assert_eq!(sent_row.2.as_deref(), Some("provider-message-1"));
    assert!(sent_row.3.is_none());
    assert!(sent_row.4.is_some());

    let retry_message = email_message(organization.id, "outbox-retry@example.com", now);
    database.insert_email_outbox_message(&retry_message).await?;
    let retry_claim = database
        .claim_email_outbox_messages(1, now, now - Duration::hours(1))
        .await?;
    assert_eq!(retry_claim.len(), 1);
    let next_attempt_at = now + Duration::minutes(5);
    assert!(
        database
            .mark_email_outbox_retry(
                retry_message.id,
                "temporary provider failure",
                next_attempt_at,
                now + Duration::seconds(1)
            )
            .await?
    );
    let retry_summary = database
        .email_outbox_queue_summary(now + Duration::minutes(4), now - Duration::hours(1))
        .await?;
    assert_eq!(retry_summary.retry, 1);
    assert_eq!(retry_summary.retry_due, 0);
    assert_db_optional_timestamp_eq(retry_summary.next_retry_at, Some(next_attempt_at));

    let before_retry = database
        .claim_email_outbox_messages(1, now + Duration::minutes(4), now - Duration::hours(1))
        .await?;
    assert!(before_retry.is_empty());
    let due_retry_summary = database
        .email_outbox_queue_summary(now + Duration::minutes(5), now - Duration::hours(1))
        .await?;
    assert_eq!(due_retry_summary.retry, 1);
    assert_eq!(due_retry_summary.retry_due, 1);

    let after_retry = database
        .claim_email_outbox_messages(1, now + Duration::minutes(5), now - Duration::hours(1))
        .await?;
    assert_eq!(after_retry.len(), 1);
    assert_eq!(after_retry[0].attempts, 2);
    assert!(
        database
            .mark_email_outbox_failed(
                retry_message.id,
                "permanent provider failure",
                now + Duration::minutes(6)
            )
            .await?
    );
    let failed_row: (String, Option<String>, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT status, last_error, next_attempt_at FROM email_outbox WHERE id = $1",
    )
    .bind(retry_message.id)
    .fetch_one(database.pool())
    .await?;
    assert_eq!(failed_row.0, "failed");
    assert_eq!(failed_row.1.as_deref(), Some("permanent provider failure"));
    assert!(failed_row.2.is_none());

    let final_summary = database
        .email_outbox_queue_summary(now + Duration::minutes(7), now - Duration::hours(1))
        .await?;
    assert_eq!(final_summary.queued, 0);
    assert_eq!(final_summary.retry, 0);
    assert_eq!(final_summary.retry_due, 0);
    assert_eq!(final_summary.sending, 0);
    assert_eq!(final_summary.stale_sending, 0);
    assert_eq!(final_summary.sent, 1);
    assert_eq!(final_summary.failed, 1);
    assert_eq!(final_summary.unfinished, 1);
    assert!(final_summary.oldest_unfinished_at.is_some());
    assert!(final_summary.next_retry_at.is_none());
    Ok(())
}

#[tokio::test]
async fn lifecycle_email_evidence_lists_latest_sent_message_per_required_kind()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    let organization = create_organization(&database, "lifecycle-email-evidence").await?;
    let other_organization =
        create_organization(&database, "lifecycle-email-evidence-other").await?;
    let now = OffsetDateTime::now_utc();
    let required_kinds = [
        "invitation",
        "email_verification",
        "password_recovery",
        "password_recovered_notification",
        "password_changed_notification",
        "new_login_notification",
    ];
    let required_kind_values = required_kinds
        .iter()
        .map(|kind| (*kind).to_owned())
        .collect::<Vec<_>>();

    let mut older_invitation = lifecycle_email_message(
        organization.id,
        "invitation",
        true,
        now - Duration::hours(1),
    );
    older_invitation.provider_message_id = Some("provider-invitation-old".to_owned());
    database
        .insert_email_outbox_message(&older_invitation)
        .await?;

    for kind in required_kinds {
        let action_url_present = matches!(
            kind,
            "invitation" | "email_verification" | "password_recovery"
        );
        let message = lifecycle_email_message(organization.id, kind, action_url_present, now);
        database.insert_email_outbox_message(&message).await?;
    }

    let mut queued = lifecycle_email_message(organization.id, "new_login_notification", false, now);
    queued.id = Uuid::new_v4();
    queued.status = "queued".to_owned();
    queued.sent_at = None;
    database.insert_email_outbox_message(&queued).await?;

    let mut latest_invalid_template = lifecycle_email_message(
        organization.id,
        "password_recovery",
        true,
        now + Duration::seconds(1),
    );
    latest_invalid_template.id = Uuid::new_v4();
    latest_invalid_template.template = "email_verification".to_owned();
    database
        .insert_email_outbox_message(&latest_invalid_template)
        .await?;

    let other_message = lifecycle_email_message(
        other_organization.id,
        "invitation",
        true,
        now + Duration::minutes(1),
    );
    database.insert_email_outbox_message(&other_message).await?;

    let evidence = database
        .list_lifecycle_email_evidence_messages(organization.id, &required_kind_values)
        .await?;

    assert_eq!(evidence.len(), required_kind_values.len());
    let invitation = evidence
        .iter()
        .find(|message| message.kind == "invitation")
        .expect("invitation evidence");
    assert_eq!(
        invitation.provider_message_id.as_deref(),
        Some("provider-invitation")
    );
    assert!(invitation.action_url_present);
    assert_eq!(invitation.template, "account_invitation");
    assert_db_timestamp_eq(invitation.sent_at, now);
    let password_recovery = evidence
        .iter()
        .find(|message| message.kind == "password_recovery")
        .expect("password recovery evidence");
    assert_eq!(password_recovery.template, "email_verification");
    assert_db_timestamp_eq(password_recovery.sent_at, now + Duration::seconds(1));
    assert!(
        evidence
            .iter()
            .any(|message| message.kind == "password_changed_notification"
                && !message.action_url_present)
    );

    Ok(())
}

#[tokio::test]
async fn key_encryption_rotation_updates_encrypted_columns_transactionally()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let _email_outbox_guard = EMAIL_OUTBOX_TEST_LOCK.lock().await;
    let organization = create_organization(&database, "kek-rotation").await?;
    let now = OffsetDateTime::now_utc();
    let signing_key = SigningKeyMaterial {
        kid: format!("rs256-{}", Uuid::new_v4()),
        algorithm: "RS256".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "test",
            "use": "sig",
            "alg": "RS256",
            "n": "abc",
            "e": "AQAB"
        }),
        private_key_ciphertext: vec![1, 2, 3],
        private_key_nonce: vec![4, 5, 6],
        signing_active: true,
        created_at: now,
        retired_at: None,
    };
    database.upsert_signing_key_material(&signing_key).await?;
    let rollover_key = SigningKeyMaterial {
        kid: format!("rs256-rollover-{}", Uuid::new_v4()),
        algorithm: "RS256".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "rollover",
            "use": "sig",
            "alg": "RS256",
            "n": "def",
            "e": "AQAB"
        }),
        private_key_ciphertext: vec![30, 31, 32],
        private_key_nonce: vec![33, 34, 35],
        signing_active: false,
        created_at: now + Duration::minutes(1),
        retired_at: None,
    };
    database.upsert_signing_key_material(&rollover_key).await?;
    let retired_key = SigningKeyMaterial {
        kid: format!("rs256-retired-{}", Uuid::new_v4()),
        algorithm: "RS256".to_owned(),
        public_jwk: json!({
            "kty": "RSA",
            "kid": "retired",
            "use": "sig",
            "alg": "RS256",
            "n": "ghi",
            "e": "AQAB"
        }),
        private_key_ciphertext: vec![40, 41, 42],
        private_key_nonce: vec![43, 44, 45],
        signing_active: false,
        created_at: now + Duration::minutes(2),
        retired_at: Some(now + Duration::minutes(3)),
    };
    database.upsert_signing_key_material(&retired_key).await?;

    let signing_summary = database.signing_key_lifecycle_summary().await?;
    assert_eq!(signing_summary.total, 3);
    assert_eq!(signing_summary.active, 1);
    assert_eq!(signing_summary.active_with_private_material, 1);
    assert_eq!(signing_summary.unretired, 2);
    assert_eq!(signing_summary.retired, 1);
    assert_eq!(signing_summary.rollover, 1);
    assert_eq!(signing_summary.encrypted_private_material, 3);
    assert_db_optional_timestamp_eq(
        signing_summary.active_created_at,
        Some(signing_key.created_at),
    );
    assert_db_optional_timestamp_eq(
        signing_summary.oldest_unretired_created_at,
        Some(signing_key.created_at),
    );
    assert_db_optional_timestamp_eq(signing_summary.newest_retired_at, retired_key.retired_at);

    let mut message = email_message(organization.id, "kek-outbox@example.com", now);
    message.delivery_token_ciphertext = Some(vec![7, 8, 9]);
    message.delivery_token_nonce = Some(vec![10, 11, 12]);
    message.metadata = json!({
        "kind": "password_recovery",
        "account_token_id": Uuid::new_v4()
    });
    database.insert_email_outbox_message(&message).await?;

    let mut reencrypted_signing_key = signing_key.clone();
    reencrypted_signing_key.private_key_ciphertext = vec![13, 14, 15];
    reencrypted_signing_key.private_key_nonce = vec![16, 17, 18];
    database
        .apply_key_encryption_rotation(
            &[reencrypted_signing_key.clone()],
            &[cairn_database::ReencryptedEmailOutboxDeliveryToken {
                id: message.id,
                delivery_token_ciphertext: vec![19, 20, 21],
                delivery_token_nonce: vec![22, 23, 24],
            }],
        )
        .await?;

    let stored_signing_key = database
        .list_encrypted_signing_key_materials()
        .await?
        .into_iter()
        .find(|candidate| candidate.kid == signing_key.kid)
        .expect("reencrypted signing key exists");
    let stored_outbox = database
        .list_email_outbox_delivery_tokens()
        .await?
        .into_iter()
        .find(|candidate| candidate.id == message.id)
        .expect("reencrypted outbox token exists");

    assert_eq!(
        stored_signing_key.private_key_ciphertext,
        reencrypted_signing_key.private_key_ciphertext
    );
    assert_eq!(
        stored_signing_key.private_key_nonce,
        reencrypted_signing_key.private_key_nonce
    );
    assert_eq!(
        stored_signing_key.signing_active,
        signing_key.signing_active
    );
    assert_db_timestamp_eq(stored_signing_key.created_at, signing_key.created_at);
    assert_eq!(stored_outbox.delivery_token_ciphertext, vec![19, 20, 21]);
    assert_eq!(stored_outbox.delivery_token_nonce, vec![22, 23, 24]);
    Ok(())
}

#[tokio::test]
async fn consent_grants_are_scope_and_organization_bound() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "consent").await?;
    let other_fixture = create_fixture(&database, "consent-other").await?;
    let now = OffsetDateTime::now_utc();
    let grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now,
        revoked_at: None,
    };
    database.create_consent_grant(&grant).await?;

    assert!(
        database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );
    assert!(
        database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                fixture.client.id,
                &["openid".to_owned(), "profile".to_owned()]
            )
            .await?
    );
    assert!(
        !database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                fixture.client.id,
                &["openid".to_owned(), "offline_access".to_owned()]
            )
            .await?
    );
    assert!(
        !database
            .has_active_consent_grant(
                other_fixture.organization.id,
                fixture.user.id,
                fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );
    assert!(
        !database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                other_fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );

    let revoked_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: other_fixture.organization.id,
        user_id: other_fixture.user.id,
        client_id: other_fixture.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now,
        revoked_at: Some(now),
    };
    database.create_consent_grant(&revoked_grant).await?;

    assert!(
        !database
            .has_active_consent_grant(
                other_fixture.organization.id,
                other_fixture.user.id,
                other_fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn consent_grant_admin_review_is_client_scoped_and_keyset_paginated()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "consent-review").await?;
    let other_fixture = create_fixture(&database, "consent-review-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let second_user = User::new(
        fixture.organization.id,
        format!("consent-review-second-{}@example.com", Uuid::new_v4()),
        "Second Consent User",
    )?;
    database.create_user(&second_user, None).await?;
    let other_client = oidc_client(
        fixture.organization.id,
        format!("consent-review-other-client-{}", Uuid::new_v4()),
        "Other Consent Client",
        true,
        vec!["openid".to_owned(), "email".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    database.create_oidc_client(&other_client).await?;

    let active_newer = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        created_at: now + Duration::seconds(20),
        revoked_at: None,
    };
    let active_older = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: second_user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now + Duration::seconds(10),
        revoked_at: None,
    };
    let revoked_latest = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "groups".to_owned()],
        created_at: now + Duration::seconds(30),
        revoked_at: Some(now + Duration::seconds(31)),
    };
    let other_client_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: other_client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(40),
        revoked_at: None,
    };
    let other_organization_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: other_fixture.organization.id,
        user_id: other_fixture.user.id,
        client_id: other_fixture.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(50),
        revoked_at: None,
    };

    for grant in [
        &active_newer,
        &active_older,
        &revoked_latest,
        &other_client_grant,
        &other_organization_grant,
    ] {
        database.create_consent_grant(grant).await?;
    }

    let first_page = database
        .list_active_consent_grants_for_client_page(
            fixture.organization.id,
            fixture.client.id,
            None,
            1,
        )
        .await?;
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].id, active_newer.id);
    assert_eq!(first_page[0].user_id, fixture.user.id);
    assert_eq!(first_page[0].user_email, fixture.user.email);
    assert_eq!(first_page[0].user_display_name, fixture.user.display_name);
    assert_eq!(first_page[0].scopes, active_newer.scopes);

    let second_page = database
        .list_active_consent_grants_for_client_page(
            fixture.organization.id,
            fixture.client.id,
            Some(ListCursor::new(first_page[0].created_at, first_page[0].id)),
            10,
        )
        .await?;
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].id, active_older.id);
    assert_eq!(second_page[0].user_id, second_user.id);
    assert_eq!(second_page[0].user_email, second_user.email);

    let empty_other_org_page = database
        .list_active_consent_grants_for_client_page(
            other_fixture.organization.id,
            fixture.client.id,
            None,
            10,
        )
        .await?;
    assert!(empty_other_org_page.is_empty());

    let all_grants = database
        .list_consent_grants_for_client_page_filtered(
            fixture.organization.id,
            fixture.client.id,
            &ConsentGrantListFilter::default(),
            None,
            10,
        )
        .await?;
    assert_eq!(
        all_grants.iter().map(|grant| grant.id).collect::<Vec<_>>(),
        vec![revoked_latest.id, active_newer.id, active_older.id]
    );

    let revoked_grants = database
        .list_consent_grants_for_client_page_filtered(
            fixture.organization.id,
            fixture.client.id,
            &ConsentGrantListFilter {
                revoked: Some(true),
            },
            None,
            10,
        )
        .await?;
    assert_eq!(revoked_grants.len(), 1);
    assert_eq!(revoked_grants[0].id, revoked_latest.id);
    Ok(())
}

#[tokio::test]
async fn consent_revocation_marks_user_client_grants_and_runtime_credentials()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "consent-revoke").await?;
    let other_fixture = create_fixture(&database, "consent-revoke-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let revoke_at = now + Duration::minutes(10);
    let other_client = oidc_client(
        fixture.organization.id,
        format!("consent-revoke-other-client-{}", Uuid::new_v4()),
        "Other Consent Revoke Client",
        true,
        vec!["openid".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    database.create_oidc_client(&other_client).await?;

    let first_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "email".to_owned()],
        created_at: now,
        revoked_at: None,
    };
    let second_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now + Duration::seconds(1),
        revoked_at: None,
    };
    let other_client_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: other_client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(2),
        revoked_at: None,
    };
    let other_organization_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: other_fixture.organization.id,
        user_id: other_fixture.user.id,
        client_id: other_fixture.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(3),
        revoked_at: None,
    };
    for grant in [
        &first_grant,
        &second_grant,
        &other_client_grant,
        &other_organization_grant,
    ] {
        database.create_consent_grant(grant).await?;
    }

    let code_hash = hash_token("consent-revoke-code");
    database
        .insert_authorization_code(&AuthorizationCode {
            code_hash: code_hash.clone(),
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            session_id: fixture.session.id,
            client_id: fixture.client.id,
            redirect_uri: "http://localhost:3000/callback".to_owned(),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            nonce: None,
            code_challenge: "challenge".to_owned(),
            code_challenge_method: PkceMethod::S256,
            created_at: now,
            expires_at: revoke_at + Duration::minutes(5),
            used_at: None,
        })
        .await?;

    let family_id = Uuid::new_v4();
    let access = access_token(&fixture, "consent-revoke-access", now);
    let refresh = refresh_token(&fixture, "consent-revoke-refresh", family_id, now);
    let other_client_access = AccessTokenRecord {
        token_hash: hash_token("consent-revoke-other-client-access"),
        organization_id: fixture.organization.id,
        user_id: Some(fixture.user.id),
        client_id: other_client.id,
        scopes: vec!["openid".to_owned()],
        refresh_family_id: None,
        created_at: now,
        expires_at: now + Duration::minutes(15),
        revoked_at: None,
    };
    database.insert_access_token(&access).await?;
    database.insert_access_token(&other_client_access).await?;
    database.insert_refresh_token(&refresh).await?;

    let revocation = database
        .revoke_user_client_consent_and_tokens(
            fixture.organization.id,
            fixture.client.id,
            first_grant.id,
            revoke_at,
        )
        .await?
        .expect("consent grant can be revoked");
    assert_eq!(revocation.grant.id, first_grant.id);
    assert_db_optional_timestamp_eq(revocation.grant.revoked_at, Some(revoke_at));
    assert_eq!(revocation.consent_grants_revoked, 2);
    assert_eq!(revocation.authorization_codes_invalidated, 1);
    assert_eq!(revocation.access_tokens_revoked, 1);
    assert_eq!(revocation.refresh_tokens_revoked, 1);

    assert!(
        !database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );
    assert!(
        database
            .has_active_consent_grant(
                fixture.organization.id,
                fixture.user.id,
                other_client.id,
                &["openid".to_owned()]
            )
            .await?
    );

    let stored_code = database
        .get_authorization_code(&code_hash)
        .await?
        .expect("authorization code exists");
    assert_db_optional_timestamp_eq(stored_code.used_at, Some(revoke_at));
    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(revoke_at),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(revoke_at),
    );
    assert_eq!(
        database
            .get_access_token(&other_client_access.token_hash)
            .await?
            .expect("other client access token exists")
            .revoked_at,
        None
    );

    let revoked_grants = database
        .list_consent_grants_for_client_page_filtered(
            fixture.organization.id,
            fixture.client.id,
            &ConsentGrantListFilter {
                revoked: Some(true),
            },
            None,
            10,
        )
        .await?;
    assert_eq!(
        revoked_grants
            .iter()
            .map(|grant| grant.id)
            .collect::<Vec<_>>(),
        vec![second_grant.id, first_grant.id]
    );

    let repeated = database
        .revoke_user_client_consent_and_tokens(
            fixture.organization.id,
            fixture.client.id,
            first_grant.id,
            revoke_at + Duration::minutes(1),
        )
        .await?
        .expect("revoked consent grant remains addressable");
    assert_eq!(repeated.consent_grants_revoked, 0);
    assert_eq!(repeated.authorization_codes_invalidated, 0);
    assert_eq!(repeated.access_tokens_revoked, 0);
    assert_eq!(repeated.refresh_tokens_revoked, 0);

    assert!(
        database
            .revoke_user_client_consent_and_tokens(
                other_fixture.organization.id,
                fixture.client.id,
                first_grant.id,
                revoke_at,
            )
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn user_consent_review_and_revocation_are_user_scoped() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "user-consent").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000)?;
    let second_user = User::new(
        fixture.organization.id,
        format!("user-consent-second-{}@example.com", Uuid::new_v4()),
        "Second User Consent",
    )?;
    database.create_user(&second_user, None).await?;

    let active_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now + Duration::seconds(10),
        revoked_at: None,
    };
    let revoked_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now,
        revoked_at: Some(now + Duration::seconds(1)),
    };
    let second_user_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: second_user.id,
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(20),
        revoked_at: None,
    };
    for grant in [&active_grant, &revoked_grant, &second_user_grant] {
        database.create_consent_grant(grant).await?;
    }

    let family_id = Uuid::new_v4();
    let access = access_token(&fixture, "user-consent-access", now);
    let refresh = refresh_token(&fixture, "user-consent-refresh", family_id, now);
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;

    let all_grants = database
        .list_consent_grants_for_user_page_filtered(
            fixture.organization.id,
            fixture.user.id,
            &ConsentGrantListFilter::default(),
            None,
            10,
        )
        .await?;
    assert_eq!(
        all_grants.iter().map(|grant| grant.id).collect::<Vec<_>>(),
        vec![active_grant.id, revoked_grant.id]
    );
    assert_eq!(all_grants[0].client_id, fixture.client.id);
    assert_eq!(all_grants[0].client_public_id, fixture.client.client_id);
    assert_eq!(all_grants[0].client_name, fixture.client.name);

    let active_grants = database
        .list_consent_grants_for_user_page_filtered(
            fixture.organization.id,
            fixture.user.id,
            &ConsentGrantListFilter {
                revoked: Some(false),
            },
            None,
            10,
        )
        .await?;
    assert_eq!(active_grants.len(), 1);
    assert_eq!(active_grants[0].id, active_grant.id);

    let revoke_at = now + Duration::minutes(5);
    assert!(
        database
            .revoke_current_user_consent_and_tokens(
                fixture.organization.id,
                fixture.user.id,
                second_user_grant.id,
                revoke_at,
            )
            .await?
            .is_none()
    );

    let revocation = database
        .revoke_current_user_consent_and_tokens(
            fixture.organization.id,
            fixture.user.id,
            active_grant.id,
            revoke_at,
        )
        .await?
        .expect("current user grant can be revoked");
    assert_eq!(revocation.grant.id, active_grant.id);
    assert_eq!(revocation.consent_grants_revoked, 1);
    assert_eq!(revocation.access_tokens_revoked, 1);
    assert_eq!(revocation.refresh_tokens_revoked, 1);

    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(revoke_at),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(revoke_at),
    );
    assert!(
        database
            .has_active_consent_grant(
                fixture.organization.id,
                second_user.id,
                fixture.client.id,
                &["openid".to_owned()]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn multi_organization_list_queries_are_isolated() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "tenant-a").await?;
    let second = create_fixture(&database, "tenant-b").await?;
    let now = OffsetDateTime::now_utc();
    let first_group = Group {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        slug: format!("first-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "First Group".to_owned(),
        created_at: now,
    };
    let second_group = Group {
        id: Uuid::new_v4(),
        organization_id: second.organization.id,
        slug: format!("second-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "Second Group".to_owned(),
        created_at: now,
    };
    database.create_group(&first_group).await?;
    database.create_group(&second_group).await?;

    let first_users = database.list_users(first.organization.id, 100).await?;
    assert!(first_users.iter().any(|user| user.id == first.user.id));
    assert!(!first_users.iter().any(|user| user.id == second.user.id));
    assert_eq!(database.count_users(first.organization.id).await?, 1);
    assert!(
        database
            .find_user_by_email(first.organization.id, &second.user.email)
            .await?
            .is_none()
    );

    let first_groups = database.list_groups(first.organization.id, 100).await?;
    assert!(first_groups.iter().any(|group| group.id == first_group.id));
    assert!(!first_groups.iter().any(|group| group.id == second_group.id));

    let first_clients = database
        .list_oidc_clients(first.organization.id, 100)
        .await?;
    assert!(
        first_clients
            .iter()
            .any(|client| client.id == first.client.id)
    );
    assert!(
        !first_clients
            .iter()
            .any(|client| client.id == second.client.id)
    );
    let first_client_by_id = database
        .get_oidc_client(first.client.id)
        .await?
        .expect("fixture client exists");
    assert_eq!(first_client_by_id.organization_id, first.organization.id);
    assert_eq!(first_client_by_id.client_id, first.client.client_id);
    Ok(())
}

#[tokio::test]
async fn admin_user_list_keyset_pagination_is_stable() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "admin-keyset").await?;
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let mut expected_users = Vec::new();

    for index in 0..3 {
        let mut user = User::new(
            organization.id,
            format!("keyset-{index}-{}@example.com", Uuid::new_v4()),
            format!("Keyset User {index}"),
        )?;
        user.created_at = created_at;
        user.updated_at = created_at;
        database.create_user(&user, None).await?;
        expected_users.push(user);
    }
    expected_users.sort_by_key(|user| Reverse(user.id));

    let first_page = database.list_users_page(organization.id, None, 2).await?;
    assert_eq!(
        first_page.iter().map(|user| user.id).collect::<Vec<_>>(),
        expected_users
            .iter()
            .take(2)
            .map(|user| user.id)
            .collect::<Vec<_>>()
    );

    let cursor_source = first_page.last().expect("first page has a cursor source");
    let second_page = database
        .list_users_page(
            organization.id,
            Some(ListCursor::new(cursor_source.created_at, cursor_source.id)),
            2,
        )
        .await?;
    assert_eq!(
        second_page.iter().map(|user| user.id).collect::<Vec<_>>(),
        expected_users
            .iter()
            .skip(2)
            .map(|user| user.id)
            .collect::<Vec<_>>()
    );

    let mut suspended_user = User::new(
        organization.id,
        format!("filtered-suspended-{}@example.com", Uuid::new_v4()),
        "Filtered Suspended",
    )?;
    suspended_user.status = UserStatus::Suspended;
    suspended_user.created_at = created_at + Duration::seconds(1);
    suspended_user.updated_at = suspended_user.created_at;
    database.create_user(&suspended_user, None).await?;

    let filtered_page = database
        .list_users_page_filtered(
            organization.id,
            &UserListFilter {
                search_prefix: Some("filtered".to_owned()),
                status: Some(UserStatus::Suspended),
            },
            None,
            10,
        )
        .await?;
    assert_eq!(filtered_page.len(), 1);
    assert_eq!(filtered_page[0].id, suspended_user.id);

    Ok(())
}

#[tokio::test]
async fn active_user_count_is_tenant_scoped_and_excludes_inactive_users()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "active-seat-count").await?;
    let other_fixture = create_fixture(&database, "active-seat-count-other").await?;

    let active_user = User::new(
        fixture.organization.id,
        format!("active-seat-{}@example.com", Uuid::new_v4()),
        "Active Seat",
    )?;
    database.create_user(&active_user, None).await?;

    let mut suspended_user = User::new(
        fixture.organization.id,
        format!("suspended-seat-{}@example.com", Uuid::new_v4()),
        "Suspended Seat",
    )?;
    suspended_user.status = UserStatus::Suspended;
    database.create_user(&suspended_user, None).await?;

    let mut locked_user = User::new(
        fixture.organization.id,
        format!("locked-seat-{}@example.com", Uuid::new_v4()),
        "Locked Seat",
    )?;
    locked_user.status = UserStatus::Locked;
    database.create_user(&locked_user, None).await?;

    assert_eq!(
        database.active_user_count(fixture.organization.id).await?,
        2
    );
    assert_eq!(
        database
            .active_user_count(other_fixture.organization.id)
            .await?,
        1
    );

    Ok(())
}

#[tokio::test]
async fn oidc_client_list_filters_and_keyset_pagination_are_stable() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "client-filter").await?;
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_050)?;
    let search_prefix = format!("FilterClient{}", Uuid::new_v4().simple());
    let first_match = oidc_client(
        organization.id,
        format!("{search_prefix}-one"),
        "Filtered Confidential One",
        false,
        vec!["openid".to_owned(), "email".to_owned()],
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ],
        created_at,
    )?;
    let second_match = oidc_client(
        organization.id,
        format!("{search_prefix}-two"),
        "Filtered Confidential Two",
        false,
        vec!["openid".to_owned(), "email".to_owned()],
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ],
        created_at,
    )?;
    let ignored_public = oidc_client(
        organization.id,
        format!("{search_prefix}-public"),
        "Filtered Public",
        true,
        vec!["openid".to_owned(), "email".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        created_at,
    )?;
    let ignored_scope = oidc_client(
        organization.id,
        format!("{search_prefix}-wrong-scope"),
        "Filtered Wrong Scope",
        false,
        vec!["openid".to_owned(), "profile".to_owned()],
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
            OidcGrantType::ClientCredentials,
        ],
        created_at,
    )?;
    let ignored_grant = oidc_client(
        organization.id,
        format!("{search_prefix}-wrong-grant"),
        "Filtered Wrong Grant",
        false,
        vec!["openid".to_owned(), "email".to_owned()],
        vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
        ],
        created_at,
    )?;

    for client in [
        &first_match,
        &second_match,
        &ignored_public,
        &ignored_scope,
        &ignored_grant,
    ] {
        database.create_oidc_client(client).await?;
    }

    let mut expected = [first_match.clone(), second_match.clone()];
    expected.sort_by_key(|client| Reverse(client.id));
    let filter = OidcClientListFilter {
        search_prefix: Some(search_prefix.to_ascii_lowercase()),
        public_client: Some(false),
        status: None,
        grant_type: Some(OidcGrantType::ClientCredentials),
        scope: Some("email".to_owned()),
    };

    let first_page = database
        .list_oidc_clients_page_filtered(organization.id, &filter, None, 1)
        .await?;
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].id, expected[0].id);

    let cursor_source = first_page.last().expect("first client page has a cursor");
    let second_page = database
        .list_oidc_clients_page_filtered(
            organization.id,
            &filter,
            Some(ListCursor::new(cursor_source.created_at, cursor_source.id)),
            1,
        )
        .await?;
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].id, expected[1].id);

    Ok(())
}

#[tokio::test]
async fn consent_policy_templates_are_tenant_scoped_and_assignable_to_clients()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "consent-policy").await?;
    let other_organization = create_organization(&database, "consent-policy-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_075)?;

    let template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("always-{}", Uuid::new_v4()),
        name: "Always Require Consent".to_owned(),
        grant_mode: ConsentGrantMode::AlwaysRequired,
        created_at: now + Duration::seconds(2),
    };
    let older_template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("once-{}", Uuid::new_v4()),
        name: "Required Once".to_owned(),
        grant_mode: ConsentGrantMode::RequiredOnce,
        created_at: now + Duration::seconds(1),
    };
    let other_template = ConsentPolicyTemplate {
        id: Uuid::new_v4(),
        organization_id: other_organization.id,
        slug: format!("foreign-{}", Uuid::new_v4()),
        name: "Foreign Policy".to_owned(),
        grant_mode: ConsentGrantMode::AlwaysRequired,
        created_at: now + Duration::seconds(3),
    };
    for policy in [&older_template, &template, &other_template] {
        database.create_consent_policy_template(policy).await?;
    }

    let listed = database
        .list_consent_policy_templates(organization.id, None, 10)
        .await?;
    assert_eq!(
        listed.iter().map(|policy| policy.id).collect::<Vec<_>>(),
        vec![template.id, older_template.id]
    );
    assert_eq!(listed[0].grant_mode, ConsentGrantMode::AlwaysRequired);
    assert_eq!(
        database
            .get_consent_policy_template(organization.id, template.id)
            .await?
            .expect("template exists")
            .slug,
        template.slug
    );
    assert!(
        database
            .get_consent_policy_template(organization.id, other_template.id)
            .await?
            .is_none()
    );

    let mut client = oidc_client(
        organization.id,
        format!("policy-client-{}", Uuid::new_v4()),
        "Policy Client",
        true,
        vec!["openid".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    client.consent_policy_template_id = Some(template.id);
    database.create_oidc_client(&client).await?;
    let stored = database
        .get_oidc_client(client.id)
        .await?
        .expect("client exists");
    assert_eq!(stored.consent_policy_template_id, Some(template.id));

    let mut cross_tenant_client = oidc_client(
        organization.id,
        format!("policy-cross-client-{}", Uuid::new_v4()),
        "Policy Cross Client",
        true,
        vec!["openid".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    cross_tenant_client.consent_policy_template_id = Some(other_template.id);
    assert!(
        database
            .create_oidc_client(&cross_tenant_client)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn oidc_client_secret_rotation_is_tenant_scoped_and_confidential_only()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "client-secret-rotation").await?;
    let other_organization = create_organization(&database, "client-secret-rotation-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_085)?;

    let confidential_client = oidc_client(
        organization.id,
        format!("secret-client-{}", Uuid::new_v4()),
        "Secret Client",
        false,
        vec!["openid".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    let public_client = oidc_client(
        organization.id,
        format!("public-secret-client-{}", Uuid::new_v4()),
        "Public Secret Client",
        true,
        vec!["openid".to_owned()],
        vec![OidcGrantType::AuthorizationCode],
        now,
    )?;
    database.create_oidc_client(&confidential_client).await?;
    database.create_oidc_client(&public_client).await?;

    assert!(
        !database
            .rotate_oidc_client_secret(other_organization.id, confidential_client.id, "new-hash")
            .await?
    );
    assert!(
        !database
            .rotate_oidc_client_secret(organization.id, public_client.id, "new-hash")
            .await?
    );
    assert!(
        database
            .rotate_oidc_client_secret(organization.id, confidential_client.id, "new-hash")
            .await?
    );

    let rotated = database
        .get_oidc_client(confidential_client.id)
        .await?
        .expect("confidential client exists");
    assert_eq!(rotated.client_secret_hash.as_deref(), Some("new-hash"));
    let stored_public = database
        .get_oidc_client(public_client.id)
        .await?
        .expect("public client exists");
    assert!(stored_public.client_secret_hash.is_none());

    Ok(())
}

#[tokio::test]
async fn oidc_client_status_disable_is_tenant_scoped_and_revokes_runtime_credentials()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "client-status-disable").await?;
    let other_organization = create_organization(&database, "client-status-disable-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_087)?;
    let raw_code = format!("status-code-{}", Uuid::new_v4());
    let authorization_code = AuthorizationCode {
        code_hash: hash_token(&raw_code),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        session_id: fixture.session.id,
        client_id: fixture.client.id,
        redirect_uri: "http://localhost:3000/callback".to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        nonce: None,
        code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".to_owned(),
        code_challenge_method: PkceMethod::S256,
        created_at: now,
        expires_at: now + Duration::minutes(5),
        used_at: None,
    };
    let family_id = Uuid::new_v4();
    let access = access_token(&fixture, "client-status-access", now);
    let refresh = refresh_token(&fixture, "client-status-refresh", family_id, now);
    database
        .insert_authorization_code(&authorization_code)
        .await?;
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;

    assert!(matches!(
        database
            .update_oidc_client_status(
                other_organization.id,
                fixture.client.id,
                OidcClientStatus::Disabled,
                now + Duration::seconds(1),
            )
            .await?,
        OidcClientStatusMutationOutcome::NotFound
    ));

    let mutation = match database
        .update_oidc_client_status(
            fixture.organization.id,
            fixture.client.id,
            OidcClientStatus::Disabled,
            now + Duration::seconds(2),
        )
        .await?
    {
        OidcClientStatusMutationOutcome::Applied(mutation) => *mutation,
        OidcClientStatusMutationOutcome::NotFound => panic!("client should be found"),
    };
    assert_eq!(mutation.client.status, OidcClientStatus::Disabled);
    assert_eq!(mutation.authorization_codes_invalidated, 1);
    assert_eq!(mutation.access_tokens_revoked, 1);
    assert_eq!(mutation.refresh_tokens_revoked, 1);
    assert_eq!(
        database
            .get_oidc_client(fixture.client.id)
            .await?
            .expect("client exists")
            .status,
        OidcClientStatus::Disabled
    );
    assert!(
        database
            .get_authorization_code(&authorization_code.code_hash)
            .await?
            .expect("authorization code exists")
            .used_at
            .is_some()
    );
    assert!(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at
            .is_some()
    );
    assert!(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at
            .is_some()
    );

    let reactivation = match database
        .update_oidc_client_status(
            fixture.organization.id,
            fixture.client.id,
            OidcClientStatus::Active,
            now + Duration::seconds(3),
        )
        .await?
    {
        OidcClientStatusMutationOutcome::Applied(mutation) => *mutation,
        OidcClientStatusMutationOutcome::NotFound => panic!("client should be found"),
    };
    assert_eq!(reactivation.client.status, OidcClientStatus::Active);
    assert_eq!(reactivation.authorization_codes_invalidated, 0);
    assert_eq!(reactivation.access_tokens_revoked, 0);
    assert_eq!(reactivation.refresh_tokens_revoked, 0);
    assert!(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at
            .is_some()
    );

    Ok(())
}

#[tokio::test]
async fn consent_authorizations_are_session_scoped_one_use_and_expiring()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "consent-authorization").await?;
    let other = create_fixture(&database, "consent-authorization-other").await?;
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_090)?;

    let authorization = ConsentAuthorization {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        session_id: fixture.session.id,
        client_id: fixture.client.id,
        authorization_request_hash: "request-hash-1".to_owned(),
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        created_at: now,
        expires_at: now + Duration::minutes(5),
        consumed_at: None,
    };
    database
        .create_consent_authorization(&authorization)
        .await?;
    let openid_scope = vec!["openid".to_owned()];
    let openid_email_scopes = vec!["openid".to_owned(), "email".to_owned()];

    assert!(
        !database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: other.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-1",
                scopes: &openid_scope,
                at: now + Duration::seconds(1),
            })
            .await?
    );
    assert!(
        !database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: fixture.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-2",
                scopes: &openid_scope,
                at: now + Duration::seconds(2),
            })
            .await?
    );
    assert!(
        database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: fixture.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-1",
                scopes: &openid_scope,
                at: now + Duration::seconds(3),
            })
            .await?
    );
    assert!(
        !database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: fixture.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-1",
                scopes: &openid_scope,
                at: now + Duration::seconds(4),
            })
            .await?
    );

    let narrow_authorization = ConsentAuthorization {
        id: Uuid::new_v4(),
        authorization_request_hash: "request-hash-3".to_owned(),
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(5),
        expires_at: now + Duration::minutes(5),
        ..authorization.clone()
    };
    database
        .create_consent_authorization(&narrow_authorization)
        .await?;
    assert!(
        !database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: fixture.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-3",
                scopes: &openid_email_scopes,
                at: now + Duration::seconds(6),
            })
            .await?
    );

    let expired_authorization = ConsentAuthorization {
        id: Uuid::new_v4(),
        authorization_request_hash: "request-hash-4".to_owned(),
        scopes: vec!["openid".to_owned()],
        created_at: now + Duration::seconds(7),
        expires_at: now + Duration::seconds(8),
        ..authorization
    };
    database
        .create_consent_authorization(&expired_authorization)
        .await?;
    assert!(
        !database
            .consume_consent_authorization(ConsentAuthorizationConsumption {
                organization_id: fixture.organization.id,
                user_id: fixture.user.id,
                session_id: fixture.session.id,
                client_id: fixture.client.id,
                authorization_request_hash: "request-hash-4",
                scopes: &openid_scope,
                at: now + Duration::seconds(9),
            })
            .await?
    );

    Ok(())
}

#[tokio::test]
async fn audit_event_list_filters_and_keyset_pagination_are_stable() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "audit-filter").await?;
    let actor_id = Uuid::new_v4();
    let other_actor_id = Uuid::new_v4();
    let created_at = OffsetDateTime::from_unix_timestamp(1_800_000_100)?;
    let target_prefix = format!("Target-{}", Uuid::new_v4());
    let first_match = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(actor_id),
        "Admin.User_Created",
        format!("{target_prefix}-one"),
        created_at,
    );
    let second_match = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(actor_id),
        "admin.user_status_updated",
        format!("{target_prefix}-two"),
        created_at,
    );
    let ignored_action = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(actor_id),
        "account.email_verified",
        format!("{target_prefix}-ignored-action"),
        created_at,
    );
    let ignored_actor = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(other_actor_id),
        "admin.user_deleted",
        format!("{target_prefix}-ignored-actor"),
        created_at,
    );
    let ignored_kind = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "admin.user_created",
        format!("{target_prefix}-ignored-kind"),
        created_at,
    );
    let ignored_time = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(actor_id),
        "admin.user_created",
        format!("{target_prefix}-ignored-time"),
        created_at - Duration::days(1),
    );

    for event in [
        &first_match,
        &second_match,
        &ignored_action,
        &ignored_actor,
        &ignored_kind,
        &ignored_time,
    ] {
        database.insert_audit_event(event).await?;
    }

    let mut expected = [first_match.clone(), second_match.clone()];
    expected.sort_by_key(|event| Reverse(event.id));
    let filter = AuditEventListFilter {
        action_prefix: Some("ADMIN.USER".to_owned()),
        target_prefix: Some(target_prefix.to_ascii_lowercase()),
        actor_kind: Some(AuditActorKind::User),
        actor_id: Some(actor_id),
        created_from: Some(created_at - Duration::minutes(1)),
        created_to: Some(created_at + Duration::minutes(1)),
    };

    let first_page = database
        .list_audit_events_page_filtered(organization.id, &filter, None, 1)
        .await?;
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].id, expected[0].id);

    let cursor_source = first_page.last().expect("first audit page has a cursor");
    let second_page = database
        .list_audit_events_page_filtered(
            organization.id,
            &filter,
            Some(ListCursor::new(cursor_source.created_at, cursor_source.id)),
            1,
        )
        .await?;
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].id, expected[1].id);

    Ok(())
}

#[tokio::test]
async fn user_security_event_list_collects_actor_target_and_metadata_matches()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "user-security-events").await?;
    let other_organization = create_organization(&database, "user-security-events-other").await?;
    let user_id = Uuid::new_v4();
    let other_user_id = Uuid::new_v4();
    let admin_id = Uuid::new_v4();
    let now = OffsetDateTime::from_unix_timestamp(1_800_000_200)?;

    let target_match = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "account.password_changed",
        user_id.to_string(),
        now + Duration::seconds(1),
    );
    let actor_match = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(user_id),
        "session.logged_in",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(2),
    );
    let mut subject_metadata_match = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(admin_id),
        "admin.user_session_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(3),
    );
    subject_metadata_match.metadata = json!({ "subject_user_id": user_id });
    let mut user_metadata_match = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(admin_id),
        "admin.consent_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(4),
    );
    user_metadata_match.metadata = json!({ "user_id": user_id });
    let unrelated_actor = audit_event(
        organization.id,
        AuditActorKind::User,
        Some(other_user_id),
        "session.logged_in",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(5),
    );
    let mut foreign_metadata_match = audit_event(
        other_organization.id,
        AuditActorKind::User,
        Some(admin_id),
        "admin.user_session_revoked",
        Uuid::new_v4().to_string(),
        now + Duration::seconds(6),
    );
    foreign_metadata_match.metadata = json!({ "subject_user_id": user_id });

    for event in [
        &target_match,
        &actor_match,
        &subject_metadata_match,
        &user_metadata_match,
        &unrelated_actor,
        &foreign_metadata_match,
    ] {
        database.insert_audit_event(event).await?;
    }

    let first_page = database
        .list_user_security_events_page(organization.id, user_id, None, 3)
        .await?;
    assert_eq!(
        first_page.iter().map(|event| event.id).collect::<Vec<_>>(),
        vec![
            user_metadata_match.id,
            subject_metadata_match.id,
            actor_match.id
        ]
    );

    let cursor_source = first_page.last().expect("first user security page");
    let second_page = database
        .list_user_security_events_page(
            organization.id,
            user_id,
            Some(ListCursor::new(cursor_source.created_at, cursor_source.id)),
            3,
        )
        .await?;
    assert_eq!(second_page.len(), 1);
    assert_eq!(second_page[0].id, target_match.id);

    Ok(())
}

#[tokio::test]
async fn audit_event_retention_purge_deletes_expired_rows_in_batches() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "audit-retention").await?;
    let cutoff = OffsetDateTime::from_unix_timestamp(1_800_000_000)?;
    let oldest = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "retention.oldest",
        "oldest",
        cutoff - Duration::days(3),
    );
    let expired = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "retention.expired",
        "expired",
        cutoff - Duration::days(1),
    );
    let retained = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "retention.retained",
        "retained",
        cutoff,
    );

    for event in [&oldest, &expired, &retained] {
        database.insert_audit_event(event).await?;
    }

    assert_eq!(
        database
            .delete_audit_events_before(organization.id, cutoff, 0)
            .await?,
        0
    );
    assert_eq!(
        database
            .delete_audit_events_before(organization.id, cutoff, 1)
            .await?,
        1
    );

    let after_first_batch = database.list_audit_events(organization.id, 10).await?;
    assert!(after_first_batch.iter().all(|event| event.id != oldest.id));
    assert!(after_first_batch.iter().any(|event| event.id == expired.id));

    assert_eq!(
        database
            .delete_audit_events_before(organization.id, cutoff, 100)
            .await?,
        1
    );
    assert_eq!(
        database
            .delete_audit_events_before(organization.id, cutoff, 100)
            .await?,
        0
    );

    let remaining = database.list_audit_events(organization.id, 10).await?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, retained.id);

    Ok(())
}

#[tokio::test]
async fn bootstrap_admin_creation_is_atomic_and_assigns_owner_role() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "bootstrap-admin").await?;
    let now = OffsetDateTime::now_utc();
    let mut user = User::new(
        organization.id,
        format!("bootstrap-{}@example.com", Uuid::new_v4()),
        "Bootstrap Admin",
    )?;
    user.email_verified = true;
    let admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    let admin_membership = Membership {
        organization_id: organization.id,
        user_id: user.id,
        group_id: admin_group.id,
        role: MembershipRole::Owner,
        created_at: now,
    };

    assert!(
        database
            .create_bootstrap_admin(&user, "password-hash", &admin_group, &admin_membership)
            .await?
    );
    assert_eq!(database.count_users(organization.id).await?, 1);
    let stored_group = database
        .get_group_by_slug(organization.id, "administrators")
        .await?
        .expect("bootstrap admin group exists");
    assert_eq!(stored_group.id, admin_group.id);
    assert!(
        database
            .user_has_group_role(
                organization.id,
                user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    assert!(
        !database
            .user_has_group_role(
                organization.id,
                user.id,
                "administrators",
                &[MembershipRole::Member]
            )
            .await?
    );

    let second_user = User::new(
        organization.id,
        format!("second-bootstrap-{}@example.com", Uuid::new_v4()),
        "Second Bootstrap",
    )?;
    let second_group = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: format!("administrators-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "Second Administrators".to_owned(),
        created_at: now,
    };
    let second_membership = Membership {
        organization_id: organization.id,
        user_id: second_user.id,
        group_id: second_group.id,
        role: MembershipRole::Owner,
        created_at: now,
    };

    assert!(
        !database
            .create_bootstrap_admin(
                &second_user,
                "password-hash",
                &second_group,
                &second_membership
            )
            .await?
    );
    assert_eq!(database.count_users(organization.id).await?, 1);
    Ok(())
}

#[tokio::test]
async fn break_glass_admin_recovery_reactivates_user_and_grants_owner() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let organization = create_organization(&database, "break-glass").await?;
    let now = OffsetDateTime::now_utc();
    let mut user = User::new(
        organization.id,
        format!("break-glass-{}@example.com", Uuid::new_v4()),
        "Break Glass User",
    )?;
    user.status = UserStatus::Locked;
    user.updated_at = now;
    database.create_user(&user, Some("password-hash")).await?;

    let admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    let audit = audit_event(
        organization.id,
        AuditActorKind::System,
        None,
        "operator.break_glass_owner_granted",
        user.id.to_string(),
        now,
    );

    let recovery = database
        .break_glass_grant_admin_owner(organization.id, user.id, &admin_group, now, &audit)
        .await?
        .expect("recovery applies to existing user");

    assert_eq!(recovery.organization_id, organization.id);
    assert_eq!(recovery.user_id, user.id);
    assert_eq!(recovery.user_email, user.email);
    assert_eq!(recovery.user_status_before, UserStatus::Locked);
    assert_eq!(recovery.user_status_after, UserStatus::Active);
    assert_eq!(recovery.admin_group_id, admin_group.id);
    assert!(recovery.admin_group_created);
    assert_eq!(recovery.membership_role_before, None);
    assert_eq!(recovery.membership_role_after, MembershipRole::Owner);

    let stored_user = database.get_user(user.id).await?.expect("user exists");
    assert_eq!(stored_user.status, UserStatus::Active);
    assert!(
        database
            .user_has_group_role(
                organization.id,
                user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    let audit_events = database.list_audit_events(organization.id, 10).await?;
    assert!(audit_events.iter().any(|event| event.id == audit.id
        && event.action == "operator.break_glass_owner_granted"
        && event.target == user.id.to_string()));

    Ok(())
}

#[tokio::test]
async fn group_role_checks_are_tenant_and_role_scoped() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "admin-role-a").await?;
    let second = create_fixture(&database, "admin-role-b").await?;
    let now = OffsetDateTime::now_utc();
    let first_admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    let second_admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: second.organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    database.create_group(&first_admin_group).await?;
    database.create_group(&second_admin_group).await?;
    database
        .create_membership(&Membership {
            organization_id: first.organization.id,
            user_id: first.user.id,
            group_id: first_admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;
    database
        .create_membership(&Membership {
            organization_id: second.organization.id,
            user_id: second.user.id,
            group_id: second_admin_group.id,
            role: MembershipRole::Member,
            created_at: now,
        })
        .await?;

    assert!(
        database
            .user_has_group_role(
                first.organization.id,
                first.user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    assert!(
        !database
            .user_has_group_role(
                first.organization.id,
                first.user.id,
                "administrators",
                &[MembershipRole::Member]
            )
            .await?
    );
    assert!(
        !database
            .user_has_group_role(
                second.organization.id,
                second.user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    assert!(
        database
            .user_has_group_role(
                second.organization.id,
                second.user.id,
                "administrators",
                &[MembershipRole::Member]
            )
            .await?
    );
    assert!(
        !database
            .user_has_group_role(
                first.organization.id,
                second.user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn group_membership_mutations_are_tenant_scoped_and_persisted() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "membership-a").await?;
    let second = create_fixture(&database, "membership-b").await?;
    let now = OffsetDateTime::now_utc();
    let first_group = Group {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        slug: format!("engineering-{}", Uuid::new_v4()),
        scim_external_id: None,
        display_name: "Engineering".to_owned(),
        created_at: now,
    };
    database.create_group(&first_group).await?;

    let membership = Membership {
        organization_id: first.organization.id,
        user_id: first.user.id,
        group_id: first_group.id,
        role: MembershipRole::Member,
        created_at: now,
    };
    assert_eq!(
        database
            .upsert_group_membership(&membership, "administrators")
            .await?,
        MembershipMutationOutcome::Applied
    );
    let memberships = database
        .list_group_memberships(first.organization.id, first_group.id, 100)
        .await?;
    assert_eq!(memberships.len(), 1);
    assert_eq!(memberships[0].user_id, first.user.id);
    assert_eq!(memberships[0].role, MembershipRole::Member);
    assert!(
        database
            .list_group_memberships(second.organization.id, first_group.id, 100)
            .await?
            .is_empty()
    );

    let elevated = Membership {
        role: MembershipRole::Owner,
        ..membership.clone()
    };
    assert_eq!(
        database
            .upsert_group_membership(&elevated, "administrators")
            .await?,
        MembershipMutationOutcome::Applied
    );
    let stored = database
        .get_group_membership(first.organization.id, first_group.id, first.user.id)
        .await?
        .expect("membership exists");
    assert_eq!(stored.role, MembershipRole::Owner);
    assert_db_timestamp_eq(stored.created_at, now);
    assert_eq!(
        database
            .list_user_group_slugs(first.organization.id, first.user.id)
            .await?,
        vec![first_group.slug.clone()]
    );
    assert!(
        database
            .list_user_group_slugs(second.organization.id, first.user.id)
            .await?
            .is_empty()
    );

    let cross_tenant_membership = Membership {
        organization_id: first.organization.id,
        user_id: second.user.id,
        group_id: first_group.id,
        role: MembershipRole::Member,
        created_at: now,
    };
    assert_eq!(
        database
            .upsert_group_membership(&cross_tenant_membership, "administrators")
            .await?,
        MembershipMutationOutcome::NotFound
    );

    assert_eq!(
        database
            .delete_group_membership(
                first.organization.id,
                first_group.id,
                first.user.id,
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::Applied
    );
    assert!(
        database
            .get_group_membership(first.organization.id, first_group.id, first.user.id)
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn protected_admin_group_keeps_at_least_one_owner() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "protected-admin").await?;
    let now = OffsetDateTime::now_utc();
    let admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    database.create_group(&admin_group).await?;
    let owner_membership = Membership {
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        group_id: admin_group.id,
        role: MembershipRole::Owner,
        created_at: now,
    };
    assert_eq!(
        database
            .upsert_group_membership(&owner_membership, "administrators")
            .await?,
        MembershipMutationOutcome::Applied
    );
    assert_eq!(
        database
            .upsert_group_membership(
                &Membership {
                    role: MembershipRole::Member,
                    ..owner_membership.clone()
                },
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::WouldRemoveLastOwner
    );
    assert_eq!(
        database
            .delete_group_membership(
                fixture.organization.id,
                admin_group.id,
                fixture.user.id,
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::WouldRemoveLastOwner
    );

    let inactive_owner = User::new(
        fixture.organization.id,
        format!("inactive-owner-{}@example.com", Uuid::new_v4()),
        "Inactive Owner",
    )?;
    database.create_user(&inactive_owner, None).await?;
    assert_eq!(
        database
            .upsert_group_membership(
                &Membership {
                    organization_id: fixture.organization.id,
                    user_id: inactive_owner.id,
                    group_id: admin_group.id,
                    role: MembershipRole::Owner,
                    created_at: now,
                },
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::Applied
    );
    let UserStatusMutationOutcome::Applied(inactive_owner) = database
        .update_user_status(
            fixture.organization.id,
            inactive_owner.id,
            UserStatus::Locked,
            "administrators",
            now,
        )
        .await?
    else {
        panic!("expected inactive owner status update to apply");
    };
    assert_eq!(inactive_owner.status, UserStatus::Locked);
    assert_eq!(
        database
            .upsert_group_membership(
                &Membership {
                    role: MembershipRole::Member,
                    ..owner_membership.clone()
                },
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::WouldRemoveLastOwner
    );
    assert_eq!(
        database
            .delete_group_membership(
                fixture.organization.id,
                admin_group.id,
                fixture.user.id,
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::WouldRemoveLastOwner
    );

    let second_user = User::new(
        fixture.organization.id,
        format!("second-owner-{}@example.com", Uuid::new_v4()),
        "Second Owner",
    )?;
    database.create_user(&second_user, None).await?;
    assert_eq!(
        database
            .upsert_group_membership(
                &Membership {
                    organization_id: fixture.organization.id,
                    user_id: second_user.id,
                    group_id: admin_group.id,
                    role: MembershipRole::Owner,
                    created_at: now,
                },
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::Applied
    );
    assert_eq!(
        database
            .delete_group_membership(
                fixture.organization.id,
                admin_group.id,
                fixture.user.id,
                "administrators"
            )
            .await?,
        MembershipMutationOutcome::Applied
    );
    assert!(
        database
            .user_has_group_role(
                fixture.organization.id,
                second_user.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn user_status_deactivation_revokes_runtime_credentials() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "user-status").await?;
    let now = OffsetDateTime::now_utc();
    let access = access_token(&fixture, "status-access", now);
    let refresh = refresh_token(&fixture, "status-refresh", Uuid::new_v4(), now);
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;

    let outcome = database
        .update_user_status(
            fixture.organization.id,
            fixture.user.id,
            UserStatus::Suspended,
            "administrators",
            now,
        )
        .await?;
    let UserStatusMutationOutcome::Applied(updated_user) = outcome else {
        panic!("expected user status update to apply");
    };
    assert_eq!(updated_user.status, UserStatus::Suspended);
    assert_db_timestamp_eq(updated_user.updated_at, now);
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(fixture.session.id)
            .await?
            .expect("session exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(now),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(now),
    );

    let reactivated_at = now + Duration::minutes(1);
    let reactivation = database
        .update_user_status(
            fixture.organization.id,
            fixture.user.id,
            UserStatus::Active,
            "administrators",
            reactivated_at,
        )
        .await?;
    let UserStatusMutationOutcome::Applied(reactivated_user) = reactivation else {
        panic!("expected user reactivation to apply");
    };
    assert_eq!(reactivated_user.status, UserStatus::Active);
    assert_db_timestamp_eq(reactivated_user.updated_at, reactivated_at);
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(fixture.session.id)
            .await?
            .expect("session exists")
            .revoked_at,
        Some(now),
    );
    Ok(())
}

#[tokio::test]
async fn scim_user_profile_replace_filters_and_deactivation_are_tenant_scoped()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "scim-user").await?;
    let now = OffsetDateTime::now_utc();
    let pending_email_token = AccountToken {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        kind: AccountTokenKind::EmailVerification,
        user_id: Some(fixture.user.id),
        email: fixture.user.email.clone(),
        token_hash: hash_token("scim-user-pending-email-token"),
        created_by_user_id: None,
        created_at: now - Duration::minutes(5),
        expires_at: now + Duration::hours(1),
        consumed_at: None,
        metadata: json!({}),
    };
    database.insert_account_token(&pending_email_token).await?;

    let replacement = database
        .update_user_from_scim(ScimUserUpdateInput {
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            email: "scim-user-updated@example.com",
            scim_external_id: Some("hr-123"),
            email_verified: true,
            display_name: "SCIM User",
            status: UserStatus::Active,
            protected_owner_group_slug: "administrators",
            at: now,
        })
        .await?;
    let ScimUserUpdateOutcome::Applied(updated_user) = replacement else {
        panic!("expected SCIM replacement to apply");
    };
    assert_eq!(updated_user.email, "scim-user-updated@example.com");
    assert_eq!(updated_user.scim_external_id.as_deref(), Some("hr-123"));
    assert!(!updated_user.email_verified);
    let pending_email_token_consumed_at: Option<OffsetDateTime> =
        sqlx::query_scalar("SELECT consumed_at FROM account_tokens WHERE id = $1")
            .bind(pending_email_token.id)
            .fetch_one(database.pool())
            .await?;
    assert_db_optional_timestamp_eq(pending_email_token_consumed_at, Some(now));

    let external_lookup = database
        .find_user_by_scim_external_id(fixture.organization.id, "hr-123")
        .await?
        .expect("SCIM external id lookup should find user");
    assert_eq!(external_lookup.id, fixture.user.id);

    let (total_results, users) = database
        .list_scim_users_page_filtered(
            fixture.organization.id,
            &ScimUserListFilter {
                user_name_eq: Some("scim-user-updated@example.com".to_owned()),
                external_id_eq: Some("hr-123".to_owned()),
                active_eq: Some(true),
            },
            1,
            10,
        )
        .await?;
    assert_eq!(total_results, 1);
    assert_eq!(users.len(), 1);
    assert_eq!(users[0].id, fixture.user.id);

    let access = access_token(&fixture, "scim-access", now);
    let refresh = refresh_token(&fixture, "scim-refresh", Uuid::new_v4(), now);
    database.insert_access_token(&access).await?;
    database.insert_refresh_token(&refresh).await?;
    let deactivation_at = now + Duration::minutes(1);
    let deactivation = database
        .update_user_from_scim(ScimUserUpdateInput {
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            email: "scim-user-updated@example.com",
            scim_external_id: Some("hr-123"),
            email_verified: true,
            display_name: "SCIM User",
            status: UserStatus::Suspended,
            protected_owner_group_slug: "administrators",
            at: deactivation_at,
        })
        .await?;
    let ScimUserUpdateOutcome::Applied(deactivated_user) = deactivation else {
        panic!("expected SCIM deactivation to apply");
    };
    assert_eq!(deactivated_user.status, UserStatus::Suspended);
    assert_db_optional_timestamp_eq(
        database
            .get_access_token(&access.token_hash)
            .await?
            .expect("access token exists")
            .revoked_at,
        Some(deactivation_at),
    );
    assert_db_optional_timestamp_eq(
        database
            .get_refresh_token(&refresh.token_hash)
            .await?
            .expect("refresh token exists")
            .revoked_at,
        Some(deactivation_at),
    );

    let (inactive_total, inactive_users) = database
        .list_scim_users_page_filtered(
            fixture.organization.id,
            &ScimUserListFilter {
                user_name_eq: Some("scim-user-updated@example.com".to_owned()),
                external_id_eq: Some("hr-123".to_owned()),
                active_eq: Some(false),
            },
            1,
            10,
        )
        .await?;
    assert_eq!(inactive_total, 1);
    assert_eq!(inactive_users[0].status, UserStatus::Suspended);
    Ok(())
}

#[tokio::test]
async fn auth_session_rotation_revokes_old_session_and_persists_new_session()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "session-rotation").await?;
    let now = OffsetDateTime::now_utc();
    let new_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password+totp".to_owned(),
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        created_at: now,
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    };

    database
        .rotate_auth_session(fixture.session.id, &new_session, now)
        .await?;

    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(fixture.session.id)
            .await?
            .expect("old session exists")
            .revoked_at,
        Some(now),
    );
    let stored_new_session = database
        .get_auth_session(new_session.id)
        .await?
        .expect("new session exists");
    assert_eq!(stored_new_session.organization_id, fixture.organization.id);
    assert_eq!(stored_new_session.user_id, fixture.user.id);
    assert_eq!(stored_new_session.acr, "urn:cairn:acr:password+totp");
    assert_eq!(
        stored_new_session.amr,
        vec!["pwd".to_owned(), "otp".to_owned()]
    );
    assert_eq!(stored_new_session.revoked_at, None);
    Ok(())
}

#[tokio::test]
async fn auth_session_rotation_is_single_use_under_concurrency() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "session-rotation-race").await?;
    let now = OffsetDateTime::now_utc();
    let first_new_session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        acr: "urn:cairn:acr:password+totp".to_owned(),
        amr: vec!["pwd".to_owned(), "otp".to_owned()],
        created_at: now,
        expires_at: now + Duration::hours(12),
        revoked_at: None,
    };
    let second_new_session = AuthSession {
        id: Uuid::new_v4(),
        ..first_new_session.clone()
    };
    let first_new_session_id = first_new_session.id;
    let second_new_session_id = second_new_session.id;
    let old_session_id = fixture.session.id;

    let first_database = database.clone();
    let second_database = database.clone();
    let (first_result, second_result) = tokio::join!(
        async {
            first_database
                .rotate_auth_session(old_session_id, &first_new_session, now)
                .await
        },
        async {
            second_database
                .rotate_auth_session(old_session_id, &second_new_session, now)
                .await
        }
    );

    let mut applied = 0;
    let mut stale = 0;
    for result in [first_result, second_result] {
        match result {
            Ok(()) => applied += 1,
            Err(DatabaseError::NotFound) => stale += 1,
            Err(error) => return Err(Box::new(error) as Box<dyn Error>),
        }
    }
    assert_eq!(applied, 1);
    assert_eq!(stale, 1);

    let minted_replacements: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM auth_sessions WHERE id IN ($1, $2)")
            .bind(first_new_session_id)
            .bind(second_new_session_id)
            .fetch_one(database.pool())
            .await?;
    assert_eq!(minted_replacements, 1);
    assert_db_optional_timestamp_eq(
        database
            .get_auth_session(old_session_id)
            .await?
            .expect("old session exists")
            .revoked_at,
        Some(now),
    );
    Ok(())
}

#[tokio::test]
async fn user_status_deactivation_preserves_active_admin_owner() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "admin-status").await?;
    let now = OffsetDateTime::now_utc();
    let admin_group = Group {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        slug: "administrators".to_owned(),
        scim_external_id: None,
        display_name: "Administrators".to_owned(),
        created_at: now,
    };
    database.create_group(&admin_group).await?;
    database
        .create_membership(&Membership {
            organization_id: fixture.organization.id,
            user_id: fixture.user.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;

    assert!(matches!(
        database
            .update_user_status(
                fixture.organization.id,
                fixture.user.id,
                UserStatus::Suspended,
                "administrators",
                now
            )
            .await?,
        UserStatusMutationOutcome::WouldDeactivateLastOwner
    ));
    assert_eq!(
        database
            .get_user(fixture.user.id)
            .await?
            .expect("user exists")
            .status,
        UserStatus::Active
    );

    let second_owner = User::new(
        fixture.organization.id,
        format!("status-owner-{}@example.com", Uuid::new_v4()),
        "Status Owner",
    )?;
    database.create_user(&second_owner, None).await?;
    database
        .create_membership(&Membership {
            organization_id: fixture.organization.id,
            user_id: second_owner.id,
            group_id: admin_group.id,
            role: MembershipRole::Owner,
            created_at: now,
        })
        .await?;

    let outcome = database
        .update_user_status(
            fixture.organization.id,
            fixture.user.id,
            UserStatus::Locked,
            "administrators",
            now,
        )
        .await?;
    let UserStatusMutationOutcome::Applied(updated_user) = outcome else {
        panic!("expected update with another active owner to apply");
    };
    assert_eq!(updated_user.status, UserStatus::Locked);
    assert!(
        database
            .user_has_group_role(
                fixture.organization.id,
                second_owner.id,
                "administrators",
                &[MembershipRole::Owner]
            )
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn tenant_foreign_keys_reject_cross_organization_consent_grants() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "tenant-fk-a").await?;
    let second = create_fixture(&database, "tenant-fk-b").await?;
    let now = OffsetDateTime::now_utc();
    let cross_organization_grant = ConsentGrant {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        client_id: second.client.id,
        scopes: vec!["openid".to_owned()],
        created_at: now,
        revoked_at: None,
    };

    assert!(
        database
            .create_consent_grant(&cross_organization_grant)
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn mfa_credentials_are_user_scoped_and_metadata_updates_last_used()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "mfa-a").await?;
    let second = create_fixture(&database, "mfa-b").await?;
    let now = OffsetDateTime::now_utc();
    let first_credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: MfaKind::Totp,
        label: "First authenticator".to_owned(),
        secret_metadata: json!({
            "status": "pending",
            "secret_ciphertext": "encrypted-first",
            "secret_nonce": "nonce-first"
        }),
        created_at: now,
        last_used_at: None,
    };
    let second_credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: second.organization.id,
        user_id: second.user.id,
        kind: MfaKind::Totp,
        label: "Second authenticator".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "secret_ciphertext": "encrypted-second",
            "secret_nonce": "nonce-second"
        }),
        created_at: now,
        last_used_at: None,
    };
    database.create_mfa_credential(&first_credential).await?;
    database.create_mfa_credential(&second_credential).await?;

    let first_credentials = database
        .list_mfa_credentials(first.organization.id, first.user.id, MfaKind::Totp)
        .await?;
    assert_eq!(first_credentials.len(), 1);
    assert_eq!(first_credentials[0].id, first_credential.id);
    assert_eq!(
        first_credentials[0].secret_metadata["status"],
        json!("pending")
    );

    let activated_metadata = json!({
        "status": "active",
        "secret_ciphertext": "encrypted-first",
        "secret_nonce": "nonce-first"
    });
    let used_at = now + Duration::minutes(1);
    database
        .update_mfa_credential_metadata(first_credential.id, &activated_metadata, Some(used_at))
        .await?;

    let updated = database
        .list_mfa_credentials(first.organization.id, first.user.id, MfaKind::Totp)
        .await?;
    assert_eq!(updated.len(), 1);
    assert_eq!(updated[0].secret_metadata["status"], json!("active"));
    assert_db_optional_timestamp_eq(updated[0].last_used_at, Some(used_at));
    assert!(
        database
            .list_mfa_credentials(first.organization.id, second.user.id, MfaKind::Totp)
            .await?
            .is_empty()
    );

    let recovery_credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "code_hash": "hashed-recovery-code"
        }),
        created_at: now,
        last_used_at: None,
    };
    database.create_mfa_credential(&recovery_credential).await?;
    let recovery_credentials = database
        .list_mfa_credentials(first.organization.id, first.user.id, MfaKind::RecoveryCode)
        .await?;
    assert_eq!(recovery_credentials.len(), 1);
    assert_eq!(recovery_credentials[0].id, recovery_credential.id);

    let consumed_at = now + Duration::minutes(2);
    database
        .update_mfa_credential_metadata(
            recovery_credential.id,
            &json!({
                "status": "consumed",
                "code_hash": "hashed-recovery-code"
            }),
            Some(consumed_at),
        )
        .await?;
    let consumed_recovery_credentials = database
        .list_mfa_credentials(first.organization.id, first.user.id, MfaKind::RecoveryCode)
        .await?;
    assert_eq!(
        consumed_recovery_credentials[0].secret_metadata["status"],
        json!("consumed")
    );
    assert_db_optional_timestamp_eq(
        consumed_recovery_credentials[0].last_used_at,
        Some(consumed_at),
    );
    Ok(())
}

#[tokio::test]
async fn recovery_code_replacement_revokes_only_active_codes() -> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let fixture = create_fixture(&database, "recovery-rotate").await?;
    let now = OffsetDateTime::now_utc();
    let active_old = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "code_hash": "old-active"
        }),
        created_at: now,
        last_used_at: None,
    };
    let consumed_old = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "consumed",
            "code_hash": "old-consumed"
        }),
        created_at: now,
        last_used_at: Some(now),
    };
    database.create_mfa_credential(&active_old).await?;
    database.create_mfa_credential(&consumed_old).await?;

    let rotated_at = now + Duration::minutes(1);
    assert_eq!(
        database
            .revoke_active_mfa_credentials_by_kind(
                fixture.organization.id,
                fixture.user.id,
                MfaKind::RecoveryCode,
                rotated_at,
            )
            .await?,
        1
    );
    let new_code = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: fixture.organization.id,
        user_id: fixture.user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "code_hash": "new-active"
        }),
        created_at: rotated_at,
        last_used_at: None,
    };
    database.create_mfa_credential(&new_code).await?;

    let credentials = database
        .list_mfa_credentials(
            fixture.organization.id,
            fixture.user.id,
            MfaKind::RecoveryCode,
        )
        .await?;
    assert_eq!(credentials.len(), 3);
    let active_old = credentials
        .iter()
        .find(|credential| credential.id == active_old.id)
        .expect("active old code exists");
    assert_eq!(active_old.secret_metadata["status"], json!("revoked"));
    assert_db_optional_timestamp_eq(active_old.last_used_at, Some(rotated_at));
    let consumed_old = credentials
        .iter()
        .find(|credential| credential.id == consumed_old.id)
        .expect("consumed old code exists");
    assert_eq!(consumed_old.secret_metadata["status"], json!("consumed"));
    assert_db_optional_timestamp_eq(consumed_old.last_used_at, Some(now));
    let new_code = credentials
        .iter()
        .find(|credential| credential.id == new_code.id)
        .expect("new code exists");
    assert_eq!(new_code.secret_metadata["status"], json!("active"));
    assert_eq!(new_code.last_used_at, None);
    Ok(())
}

#[tokio::test]
async fn webauthn_challenges_are_one_use_expiring_and_tenant_scoped() -> Result<(), Box<dyn Error>>
{
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "webauthn-a").await?;
    let second = create_fixture(&database, "webauthn-b").await?;
    let now = OffsetDateTime::now_utc();
    let challenge = WebAuthnChallenge {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: WebAuthnChallengeKind::Authentication,
        state: json!({ "challenge": "server-side-state" }),
        created_at: now,
        expires_at: now + Duration::minutes(5),
        consumed_at: None,
    };
    database.insert_webauthn_challenge(&challenge).await?;

    assert!(
        database
            .consume_webauthn_challenge(
                challenge.id,
                first.organization.id,
                first.user.id,
                WebAuthnChallengeKind::Authentication,
                now + Duration::minutes(1),
            )
            .await?
            .is_some()
    );
    assert!(
        database
            .consume_webauthn_challenge(
                challenge.id,
                first.organization.id,
                first.user.id,
                WebAuthnChallengeKind::Authentication,
                now + Duration::minutes(2),
            )
            .await?
            .is_none()
    );

    let expired_challenge = WebAuthnChallenge {
        id: Uuid::new_v4(),
        expires_at: now - Duration::seconds(1),
        ..challenge.clone()
    };
    database
        .insert_webauthn_challenge(&expired_challenge)
        .await?;
    assert!(
        database
            .consume_webauthn_challenge(
                expired_challenge.id,
                first.organization.id,
                first.user.id,
                WebAuthnChallengeKind::Authentication,
                now,
            )
            .await?
            .is_none()
    );

    let other_user_challenge = WebAuthnChallenge {
        id: Uuid::new_v4(),
        expires_at: now + Duration::minutes(5),
        ..challenge
    };
    database
        .insert_webauthn_challenge(&other_user_challenge)
        .await?;
    assert!(
        database
            .consume_webauthn_challenge(
                other_user_challenge.id,
                second.organization.id,
                second.user.id,
                WebAuthnChallengeKind::Authentication,
                now,
            )
            .await?
            .is_none()
    );

    let credential = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: MfaKind::WebAuthn,
        label: "Passkey".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "credential_id": "credential-a",
            "passkey": { "serialized": true }
        }),
        created_at: now,
        last_used_at: None,
    };
    database.create_mfa_credential(&credential).await?;

    assert_eq!(
        database
            .find_active_webauthn_credential_by_credential_id(
                first.organization.id,
                "credential-a",
            )
            .await?
            .map(|credential| credential.id),
        Some(credential.id)
    );
    assert!(
        database
            .find_active_webauthn_credential_by_credential_id(
                second.organization.id,
                "credential-a",
            )
            .await?
            .is_none()
    );
    Ok(())
}

#[tokio::test]
async fn mfa_credential_revocation_is_user_scoped_and_preserves_metadata()
-> Result<(), Box<dyn Error>> {
    let Some(database) = test_database().await? else {
        return Ok(());
    };
    let first = create_fixture(&database, "mfa-revoke-a").await?;
    let second = create_fixture(&database, "mfa-revoke-b").await?;
    let now = OffsetDateTime::now_utc();
    let totp = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: MfaKind::Totp,
        label: "Authenticator".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "secret_ciphertext": "encrypted",
            "secret_nonce": "nonce"
        }),
        created_at: now,
        last_used_at: None,
    };
    let recovery = MfaCredential {
        id: Uuid::new_v4(),
        organization_id: first.organization.id,
        user_id: first.user.id,
        kind: MfaKind::RecoveryCode,
        label: "Recovery code".to_owned(),
        secret_metadata: json!({
            "status": "active",
            "code_hash": "hash"
        }),
        created_at: now,
        last_used_at: None,
    };
    database.create_mfa_credential(&totp).await?;
    database.create_mfa_credential(&recovery).await?;

    assert!(
        database
            .revoke_mfa_credential(second.organization.id, second.user.id, totp.id, now)
            .await?
            .is_none()
    );

    let revoked_at = now + Duration::minutes(1);
    let revoked = database
        .revoke_mfa_credential(first.organization.id, first.user.id, totp.id, revoked_at)
        .await?
        .expect("credential should be revoked");
    assert_eq!(revoked.secret_metadata["status"], json!("revoked"));
    assert_eq!(
        revoked.secret_metadata["secret_ciphertext"],
        json!("encrypted")
    );
    assert_db_optional_timestamp_eq(revoked.last_used_at, Some(revoked_at));

    let recovery_revoked = database
        .revoke_active_mfa_credentials_by_kind(
            first.organization.id,
            first.user.id,
            MfaKind::RecoveryCode,
            revoked_at,
        )
        .await?;
    assert_eq!(recovery_revoked, 1);
    let recovery_credentials = database
        .list_mfa_credentials(first.organization.id, first.user.id, MfaKind::RecoveryCode)
        .await?;
    assert_eq!(
        recovery_credentials[0].secret_metadata["status"],
        json!("revoked")
    );
    assert_eq!(
        recovery_credentials[0].secret_metadata["code_hash"],
        json!("hash")
    );
    Ok(())
}

async fn test_database() -> Result<Option<Database>, Box<dyn Error>> {
    let Some(database_url) = std::env::var("CAIRN_DATABASE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("skipping Postgres protocol invariants; CAIRN_DATABASE_TEST_URL is not set");
        return Ok(None);
    };

    let database = Database::connect(&database_url).await?;
    database.migrate().await?;
    Ok(Some(database))
}

struct Fixture {
    organization: Organization,
    user: User,
    client: OidcClient,
    session: AuthSession,
}

async fn create_fixture(database: &Database, slug_prefix: &str) -> Result<Fixture, Box<dyn Error>> {
    let organization = create_organization(database, slug_prefix).await?;
    let user = User::new(
        organization.id,
        format!("{slug_prefix}-{}@example.com", Uuid::new_v4()),
        "Test User",
    )?;
    database.create_user(&user, None).await?;
    let client = OidcClient {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        client_id: format!("{slug_prefix}-client-{}", Uuid::new_v4()),
        client_secret_hash: None,
        consent_policy_template_id: None,
        name: "Test Client".to_owned(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes: vec![
            "openid".to_owned(),
            "profile".to_owned(),
            "offline_access".to_owned(),
        ],
        grant_types: vec![
            OidcGrantType::AuthorizationCode,
            OidcGrantType::RefreshToken,
        ],
        public_client: true,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: OffsetDateTime::now_utc(),
    };
    database.create_oidc_client(&client).await?;
    let session = AuthSession {
        id: Uuid::new_v4(),
        organization_id: organization.id,
        user_id: user.id,
        acr: "urn:cairn:acr:password".to_owned(),
        amr: vec!["pwd".to_owned()],
        created_at: OffsetDateTime::now_utc(),
        expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        revoked_at: None,
    };
    database.create_auth_session(&session).await?;

    Ok(Fixture {
        organization,
        user,
        client,
        session,
    })
}

async fn create_organization(
    database: &Database,
    slug_prefix: &str,
) -> Result<Organization, Box<dyn Error>> {
    let slug = format!("{slug_prefix}-{}", Uuid::new_v4());
    let organization = Organization::new(slug, "Test Organization")?;
    database.create_organization(&organization).await?;
    Ok(organization)
}

fn access_token(fixture: &Fixture, seed: &str, at: OffsetDateTime) -> AccessTokenRecord {
    AccessTokenRecord {
        token_hash: hash_token(seed),
        organization_id: fixture.organization.id,
        user_id: Some(fixture.user.id),
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "profile".to_owned()],
        refresh_family_id: None,
        created_at: at,
        expires_at: at + Duration::minutes(15),
        revoked_at: None,
    }
}

fn refresh_token(
    fixture: &Fixture,
    seed: &str,
    family_id: Uuid,
    at: OffsetDateTime,
) -> RefreshToken {
    RefreshToken {
        id: Uuid::new_v4(),
        token_hash: hash_token(seed),
        family_id,
        organization_id: fixture.organization.id,
        user_id: Some(fixture.user.id),
        client_id: fixture.client.id,
        scopes: vec!["openid".to_owned(), "offline_access".to_owned()],
        created_at: at,
        expires_at: at + Duration::days(30),
        rotated_at: None,
        revoked_at: None,
    }
}

fn oidc_client(
    organization_id: Uuid,
    client_id: impl Into<String>,
    name: impl Into<String>,
    public_client: bool,
    allowed_scopes: Vec<String>,
    grant_types: Vec<OidcGrantType>,
    at: OffsetDateTime,
) -> Result<OidcClient, Box<dyn Error>> {
    Ok(OidcClient {
        id: Uuid::new_v4(),
        organization_id,
        client_id: client_id.into(),
        client_secret_hash: (!public_client).then(|| "hashed-secret".to_owned()),
        consent_policy_template_id: None,
        name: name.into(),
        redirect_uris: vec![RedirectUri::parse("http://localhost:3000/callback")?],
        post_logout_redirect_uris: vec![],
        allowed_scopes,
        grant_types,
        public_client,
        require_pkce: true,
        status: OidcClientStatus::Active,
        created_at: at,
    })
}

fn audit_event(
    organization_id: Uuid,
    actor_kind: AuditActorKind,
    actor_id: Option<Uuid>,
    action: impl Into<String>,
    target: impl Into<String>,
    at: OffsetDateTime,
) -> AuditEvent {
    AuditEvent {
        id: Uuid::new_v4(),
        organization_id,
        actor_kind,
        actor_id,
        action: action.into(),
        target: target.into(),
        ip_address: None,
        user_agent: None,
        metadata: json!({}),
        created_at: at,
    }
}

fn email_message(
    organization_id: Uuid,
    recipient_email: impl Into<String>,
    at: OffsetDateTime,
) -> EmailOutboxMessage {
    EmailOutboxMessage {
        id: Uuid::new_v4(),
        organization_id,
        recipient_email: recipient_email.into(),
        subject: "Lifecycle".to_owned(),
        body_text: "Lifecycle email".to_owned(),
        template: "test".to_owned(),
        action_path: None,
        delivery_token_ciphertext: None,
        delivery_token_nonce: None,
        status: "queued".to_owned(),
        attempts: 0,
        last_error: None,
        provider_message_id: None,
        metadata: json!({}),
        created_at: at,
        updated_at: at,
        next_attempt_at: None,
        sent_at: None,
    }
}

fn lifecycle_email_message(
    organization_id: Uuid,
    kind: &str,
    action_url_present: bool,
    sent_at: OffsetDateTime,
) -> EmailOutboxMessage {
    let mut message = email_message(
        organization_id,
        format!("{kind}@example.com"),
        sent_at - Duration::seconds(10),
    );
    message.template = lifecycle_email_template(kind).to_owned();
    message.action_path = action_url_present.then(|| format!("/{kind}"));
    message.status = "sent".to_owned();
    message.provider_message_id = Some(format!("provider-{kind}"));
    message.metadata = json!({ "kind": kind });
    message.updated_at = sent_at;
    message.sent_at = Some(sent_at);
    message
}

fn lifecycle_email_template(kind: &str) -> &str {
    match kind {
        "invitation" => "account_invitation",
        _ => kind,
    }
}
