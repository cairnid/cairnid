use super::{
    ScimSmokeCheck, ScimSmokeError, ScimSmokeInputs, ScimSmokeReport,
    helpers::{non_empty_secret, scim_smoke_base_url},
};
use reqwest::{Client, Url};
use std::{env, time::Duration as StdDuration};
use time::OffsetDateTime;
use uuid::Uuid;

mod cleanup;
mod metadata;
mod requests;
mod tokens;

use self::tokens::validate_rotation_tokens;

const SCIM_SMOKE_TIMEOUT: StdDuration = StdDuration::from_secs(20);

pub async fn run_scim_smoke_from_env() -> Result<ScimSmokeReport, ScimSmokeError> {
    let base_url = env::var("CAIRN_SCIM_SMOKE_BASE_URL")
        .or_else(|_| env::var("CAIRN_ISSUER"))
        .map_err(|_| ScimSmokeError::MissingEnv("CAIRN_SCIM_SMOKE_BASE_URL or CAIRN_ISSUER"))?;
    let bearer_token = env::var("CAIRN_SCIM_BEARER_TOKEN")
        .map_err(|_| ScimSmokeError::MissingEnv("CAIRN_SCIM_BEARER_TOKEN"))?;
    let secondary_bearer_token = env::var("CAIRN_SCIM_SECONDARY_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let rejected_bearer_token = env::var("CAIRN_SCIM_REJECTED_BEARER_TOKEN")
        .ok()
        .filter(|value| !value.trim().is_empty());

    run_scim_smoke(ScimSmokeInputs {
        base_url,
        bearer_token,
        secondary_bearer_token,
        rejected_bearer_token,
    })
    .await
}

pub async fn run_scim_smoke(inputs: ScimSmokeInputs) -> Result<ScimSmokeReport, ScimSmokeError> {
    let base_url = scim_smoke_base_url(&inputs.base_url)?;
    let bearer_token = non_empty_secret("CAIRN_SCIM_BEARER_TOKEN", inputs.bearer_token)?;
    let secondary_bearer_token = inputs
        .secondary_bearer_token
        .map(|token| non_empty_secret("CAIRN_SCIM_SECONDARY_BEARER_TOKEN", token))
        .transpose()?;
    let rejected_bearer_token = inputs
        .rejected_bearer_token
        .map(|token| non_empty_secret("CAIRN_SCIM_REJECTED_BEARER_TOKEN", token))
        .transpose()?;
    validate_rotation_tokens(
        &bearer_token,
        &secondary_bearer_token,
        &rejected_bearer_token,
    )?;

    let client = Client::builder()
        .timeout(SCIM_SMOKE_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut smoke = ScimSmokeRun {
        client,
        base_url,
        bearer_token,
        secondary_bearer_token,
        rejected_bearer_token,
        checks: Vec::new(),
        created_user_ids: Vec::new(),
        created_group_id: None,
    };

    let result = smoke.run().await;
    if result.is_err() {
        smoke.cleanup_after_failure().await;
    }
    result
}

pub(super) struct ScimSmokeRun {
    pub(super) client: Client,
    pub(super) base_url: Url,
    pub(super) bearer_token: String,
    pub(super) secondary_bearer_token: Option<String>,
    pub(super) rejected_bearer_token: Option<String>,
    pub(super) checks: Vec<ScimSmokeCheck>,
    pub(super) created_user_ids: Vec<Uuid>,
    pub(super) created_group_id: Option<Uuid>,
}

impl ScimSmokeRun {
    async fn run(&mut self) -> Result<ScimSmokeReport, ScimSmokeError> {
        self.check_secondary_token_if_configured().await?;
        self.check_rejected_token_if_configured().await?;
        self.check_metadata().await?;

        let suffix = Uuid::new_v4().simple().to_string();
        let short_suffix = &suffix[..8];
        let user_one_email = format!("scim-smoke-{suffix}@example.invalid");
        let user_two_email = format!("scim-smoke-{suffix}-2@example.invalid");
        let bulk_user_email = format!("scim-smoke-{suffix}-bulk@example.invalid");
        let user_one_external_id = format!("scim-smoke-user-{suffix}");
        let user_two_external_id = format!("scim-smoke-user-{suffix}-2");
        let bulk_user_external_id = format!("scim-smoke-user-{suffix}-bulk");
        let group_external_id = format!("scim-smoke-group-{suffix}");
        let bulk_group_external_id = format!("scim-smoke-group-{suffix}-bulk");

        let user_one_id = self
            .create_user(
                &user_one_email,
                &user_one_external_id,
                &format!("SCIM Smoke User {short_suffix}"),
            )
            .await?;
        let user_two_id = self
            .create_user(
                &user_two_email,
                &user_two_external_id,
                &format!("SCIM Smoke User {short_suffix} Two"),
            )
            .await?;
        self.check_user_filter(&user_one_email, user_one_id).await?;
        self.check_user_search_request(&user_one_email, user_one_id)
            .await?;
        self.check_user_projection(user_one_id, &user_one_email)
            .await?;
        self.patch_user_display_name(user_one_id, "SCIM Smoke User Patched")
            .await?;
        self.replace_user(
            user_one_id,
            &user_one_email,
            &format!("{user_one_external_id}-replaced"),
            "SCIM Smoke User Replaced",
        )
        .await?;

        let group_id = self
            .create_group(
                &format!("SCIM Smoke Group {short_suffix}"),
                &group_external_id,
                user_one_id,
            )
            .await?;
        self.check_group_filter(&format!("SCIM Smoke Group {short_suffix}"), group_id)
            .await?;
        self.check_group_search_request(&format!("SCIM Smoke Group {short_suffix}"), group_id)
            .await?;
        self.check_group_projection(group_id, user_one_id).await?;
        self.patch_group_members(group_id, user_one_id, user_two_id)
            .await?;
        self.replace_group(
            group_id,
            "SCIM Smoke Group Replaced",
            &format!("{group_external_id}-replaced"),
            user_one_id,
        )
        .await?;
        self.delete_group(group_id).await?;

        let bulk_user_id = self
            .check_bulk_mutations(
                &bulk_user_email,
                &bulk_user_external_id,
                &format!("SCIM Smoke Bulk User {short_suffix}"),
                &format!("SCIM Smoke Bulk Group {short_suffix}"),
                &bulk_group_external_id,
            )
            .await?;

        self.delete_user(user_one_id).await?;
        self.delete_user(user_two_id).await?;
        self.check_user_soft_deleted(user_one_id).await?;
        self.check_user_soft_deleted(user_two_id).await?;
        self.check_user_soft_deleted(bulk_user_id).await?;

        Ok(ScimSmokeReport {
            status: "ok",
            base_url: self.base_url.as_str().trim_end_matches('/').to_owned(),
            completed_at: OffsetDateTime::now_utc(),
            secondary_token_checked: self.secondary_bearer_token.is_some(),
            rejected_token_checked: self.rejected_bearer_token.is_some(),
            created_user_ids: vec![user_one_id, user_two_id, bulk_user_id],
            soft_deleted_user_ids: vec![user_one_id, user_two_id, bulk_user_id],
            deleted_group_id: group_id,
            checks: std::mem::take(&mut self.checks),
        })
    }
}
