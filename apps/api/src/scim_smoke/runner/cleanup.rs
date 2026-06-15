use reqwest::{Method, StatusCode};

use super::ScimSmokeRun;

impl ScimSmokeRun {
    pub(super) async fn cleanup_after_failure(&self) {
        if let Some(group_id) = self.created_group_id {
            let _ = self
                .request(
                    &self.bearer_token,
                    Method::DELETE,
                    &format!("Groups/{group_id}"),
                    &[],
                    None,
                    StatusCode::NO_CONTENT,
                )
                .await;
        }
        for user_id in &self.created_user_ids {
            let _ = self
                .request(
                    &self.bearer_token,
                    Method::DELETE,
                    &format!("Users/{user_id}"),
                    &[],
                    None,
                    StatusCode::NO_CONTENT,
                )
                .await;
        }
    }
}
