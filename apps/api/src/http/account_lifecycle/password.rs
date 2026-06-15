use cairn_domain::Environment;
use serde_json::{Value, json};

use super::super::api_response::ApiError;

pub(in crate::http) fn password_recovery_response(
    _environment: Environment,
    _queued_delivery: Option<Value>,
) -> Value {
    json!({ "status": "ok" })
}

pub(in crate::http) fn valid_new_password(password: String) -> Result<String, ApiError> {
    if password.len() < 12 {
        return Err(ApiError::bad_request(
            "password must be at least 12 characters",
        ));
    }

    Ok(password)
}

#[cfg(test)]
mod tests {
    use cairn_domain::Environment;
    use serde_json::json;

    use super::{password_recovery_response, valid_new_password};

    #[test]
    fn password_recovery_response_hides_delivery_in_all_environments() {
        let queued_delivery = json!({
            "status": "queued",
            "preview_url": "http://localhost:5173/reset-password?token=secret"
        });

        assert_eq!(
            password_recovery_response(Environment::Production, Some(queued_delivery.clone())),
            json!({ "status": "ok" })
        );
        assert_eq!(
            password_recovery_response(Environment::Development, Some(queued_delivery.clone())),
            json!({ "status": "ok" })
        );
        assert_eq!(
            password_recovery_response(Environment::Development, None),
            json!({ "status": "ok" })
        );
    }

    #[test]
    fn valid_new_password_enforces_minimum_length() {
        assert!(valid_new_password("short".to_owned()).is_err());
        assert_eq!(
            valid_new_password("correct horse battery staple".to_owned()).unwrap(),
            "correct horse battery staple"
        );
    }
}
