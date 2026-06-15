use cairn_authn::hash_token;
use cairn_domain::{OrganizationId, UserId};
use time::{Duration, OffsetDateTime};

use super::super::{ApiError, AppState};
use super::network::RequestIdentity;

#[derive(Debug, Clone)]
pub(in crate::http) struct RateLimitKey {
    key: String,
    purpose: &'static str,
}

impl RateLimitKey {
    pub(in crate::http) fn bucket_key(&self) -> &str {
        &self.key
    }
}

pub(in crate::http) async fn enforce_rate_limit(
    state: &AppState,
    keys: &[RateLimitKey],
) -> Result<(), ApiError> {
    let now = OffsetDateTime::now_utc();
    for key in keys {
        if let Some(bucket) = state.database.get_rate_limit_bucket(&key.key).await?
            && bucket.is_blocked(now)
        {
            let blocked_until = bucket.blocked_until.unwrap_or(now + Duration::seconds(1));
            return Err(ApiError::rate_limited(retry_after_seconds(
                blocked_until,
                now,
            )));
        }
    }

    Ok(())
}

fn retry_after_seconds(blocked_until: OffsetDateTime, now: OffsetDateTime) -> i64 {
    (blocked_until - now).whole_seconds().max(1)
}

pub(in crate::http) async fn record_rate_limit_failure(
    state: &AppState,
    keys: &[RateLimitKey],
    window: Duration,
    max_attempts: i64,
    block_for: Duration,
) -> Result<(), ApiError> {
    let now = OffsetDateTime::now_utc();
    for key in keys {
        state
            .database
            .record_rate_limit_failure(&key.key, key.purpose, now, window, max_attempts, block_for)
            .await?;
    }

    Ok(())
}

pub(in crate::http) fn login_pre_credential_rate_limit_keys(
    organization_id: OrganizationId,
    identity: &RequestIdentity,
) -> Vec<RateLimitKey> {
    vec![source_rate_limit_key(
        "login",
        organization_id,
        identity,
        "session.login.ip",
    )]
}

pub(in crate::http) fn login_verified_user_rate_limit_keys(
    organization_id: OrganizationId,
    user_id: UserId,
    identity: &RequestIdentity,
) -> Vec<RateLimitKey> {
    vec![
        RateLimitKey {
            key: format!(
                "login:user:{organization_id}:{}",
                hash_token(&user_id.to_string())
            ),
            purpose: "session.login.user",
        },
        source_rate_limit_key("login", organization_id, identity, "session.login.ip"),
    ]
}

pub(in crate::http) fn reauthentication_rate_limit_keys_for_identity(
    organization_id: OrganizationId,
    user_id: UserId,
    identity: &RequestIdentity,
) -> Vec<RateLimitKey> {
    vec![
        RateLimitKey {
            key: format!(
                "reauth:user:{organization_id}:{}",
                hash_token(&user_id.to_string())
            ),
            purpose: "session.reauthenticate.user",
        },
        RateLimitKey {
            key: format!(
                "reauth:ip:{organization_id}:{}",
                hash_token(&identity.network_identifier())
            ),
            purpose: "session.reauthenticate.ip",
        },
    ]
}

pub(in crate::http) fn bootstrap_rate_limit_keys(
    organization_id: OrganizationId,
    identity: &RequestIdentity,
) -> Vec<RateLimitKey> {
    vec![source_rate_limit_key(
        "bootstrap",
        organization_id,
        identity,
        "bootstrap.ip",
    )]
}

pub(in crate::http) fn account_recovery_rate_limit_keys(
    organization_id: OrganizationId,
    identity: &RequestIdentity,
) -> Vec<RateLimitKey> {
    vec![source_rate_limit_key(
        "account-recovery",
        organization_id,
        identity,
        "account.recovery.ip",
    )]
}

fn source_rate_limit_key(
    prefix: &str,
    organization_id: OrganizationId,
    identity: &RequestIdentity,
    purpose: &'static str,
) -> RateLimitKey {
    RateLimitKey {
        key: format!(
            "{prefix}:ip:{organization_id}:{}",
            hash_token(&identity.network_identifier())
        ),
        purpose,
    }
}

#[cfg(test)]
mod tests {
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    use super::{
        account_recovery_rate_limit_keys, login_pre_credential_rate_limit_keys,
        login_verified_user_rate_limit_keys, reauthentication_rate_limit_keys_for_identity,
        retry_after_seconds,
    };
    use crate::http::request_context::network::RequestIdentity;

    #[test]
    fn retry_after_seconds_uses_positive_delta_seconds() {
        let now = OffsetDateTime::UNIX_EPOCH;

        assert_eq!(retry_after_seconds(now + Duration::seconds(90), now), 90);
        assert_eq!(retry_after_seconds(now, now), 1);
        assert_eq!(retry_after_seconds(now - Duration::seconds(5), now), 1);
    }

    #[test]
    fn login_pre_credential_rate_limit_keys_use_only_source_bucket() {
        let organization_id = Uuid::new_v4();
        let identity = RequestIdentity {
            source_ip: Some("203.0.113.10".parse().unwrap()),
        };

        let keys = login_pre_credential_rate_limit_keys(organization_id, &identity);

        assert_eq!(keys.len(), 1);
        assert!(
            keys[0]
                .key
                .starts_with(&format!("login:ip:{organization_id}:"))
        );
        assert!(!keys[0].key.contains("admin@example.com"));
        assert!(!keys[0].key.contains("203.0.113.10"));
        assert_eq!(keys[0].purpose, "session.login.ip");
    }

    #[test]
    fn login_verified_user_rate_limit_keys_are_scoped_and_hashed() {
        let organization_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let identity = RequestIdentity {
            source_ip: Some("203.0.113.11".parse().unwrap()),
        };

        let keys = login_verified_user_rate_limit_keys(organization_id, user_id, &identity);

        assert_eq!(keys.len(), 2);
        assert!(
            keys[0]
                .key
                .starts_with(&format!("login:user:{organization_id}:"))
        );
        assert!(
            keys[1]
                .key
                .starts_with(&format!("login:ip:{organization_id}:"))
        );
        assert!(!keys[0].key.contains(&user_id.to_string()));
        assert!(!keys[1].key.contains("203.0.113.11"));
        assert_eq!(keys[0].purpose, "session.login.user");
        assert_eq!(keys[1].purpose, "session.login.ip");
    }

    #[test]
    fn reauthentication_rate_limit_keys_are_scoped_and_hashed() {
        let organization_id = Uuid::new_v4();
        let user_id = Uuid::new_v4();
        let identity = RequestIdentity {
            source_ip: Some("203.0.113.20".parse().unwrap()),
        };

        let keys =
            reauthentication_rate_limit_keys_for_identity(organization_id, user_id, &identity);

        assert_eq!(keys.len(), 2);
        assert!(
            keys[0]
                .key
                .starts_with(&format!("reauth:user:{organization_id}:"))
        );
        assert!(
            keys[1]
                .key
                .starts_with(&format!("reauth:ip:{organization_id}:"))
        );
        assert!(!keys[0].key.contains(&user_id.to_string()));
        assert!(!keys[1].key.contains("203.0.113.20"));
        assert_eq!(keys[0].purpose, "session.reauthenticate.user");
        assert_eq!(keys[1].purpose, "session.reauthenticate.ip");
    }

    #[test]
    fn account_recovery_rate_limit_keys_use_only_source_bucket() {
        let organization_id = Uuid::new_v4();
        let identity = RequestIdentity {
            source_ip: Some("198.51.100.4".parse().unwrap()),
        };

        let keys = account_recovery_rate_limit_keys(organization_id, &identity);

        assert_eq!(keys.len(), 1);
        assert!(
            keys[0]
                .key
                .starts_with(&format!("account-recovery:ip:{organization_id}:"))
        );
        assert!(!keys[0].key.contains("admin@example.com"));
        assert!(!keys[0].key.contains("198.51.100.4"));
    }
}
