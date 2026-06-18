#![forbid(unsafe_code)]

mod admin_operations;
mod api_contract_command;
mod audit_operations;
mod browser_origin_smoke;
mod config;
mod conformance_operations;
mod dependency_policy_operations;
mod email;
mod email_outbox_operations;
mod healthcheck;
mod http;
mod key_encryption_operations;
mod oidc_metadata_smoke;
mod operations_commands;
mod operations_evidence;
mod operations_preflight;
mod restore_operations;
mod scim_commands;
mod scim_profile;
mod scim_smoke;
mod security_header_smoke;
mod signing_key_operations;

use crate::{
    admin_operations::run_admin_command,
    api_contract_command::run_api_contract_command,
    audit_operations::run_audit_command,
    config::ApiConfig,
    conformance_operations::run_conformance_command,
    email_outbox_operations::run_email_outbox_command,
    healthcheck::run_healthcheck,
    http::build_router,
    key_encryption_operations::run_key_encryption_command,
    operations_commands::run_operations_command,
    scim_commands::run_scim_command,
    signing_key_operations::{ensure_startup_signing_key, run_signing_key_command},
};
use cairn_database::Database;
use cairn_domain::Organization;
use std::{env, net::SocketAddr, process::ExitCode};
use tokio::net::TcpListener;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args().skip(1).collect::<Vec<_>>();
    if let Some("api-contract") = args.first().map(String::as_str) {
        return exit_from_result(run_api_contract_command(&args[1..]));
    }

    match args.first().map(String::as_str) {
        Some("healthcheck") => return exit_from_result(run_healthcheck().await),
        Some("signing-key") => {
            return exit_from_result(run_signing_key_command(&args[1..]).await);
        }
        Some("email-outbox") => {
            return exit_from_result(run_email_outbox_command(&args[1..]).await);
        }
        Some("admin") => {
            return exit_from_result(run_admin_command(&args[1..]).await);
        }
        Some("audit") => {
            return exit_from_result(run_audit_command(&args[1..]).await);
        }
        Some("key-encryption") => {
            return exit_from_result(run_key_encryption_command(&args[1..]).await);
        }
        Some("operations") => {
            return exit_from_result(run_operations_command(&args[1..]).await);
        }
        Some("conformance") => {
            return exit_from_result(run_conformance_command(&args[1..]).await);
        }
        Some("scim") => {
            return exit_from_result(run_scim_command(&args[1..]).await);
        }
        _ => {}
    }

    exit_from_result(run().await)
}

fn exit_from_result(result: Result<(), Box<dyn std::error::Error>>) -> ExitCode {
    if let Err(err) = result {
        eprintln!("cairn-api failed: {err}");
        return ExitCode::FAILURE;
    }

    ExitCode::SUCCESS
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = ApiConfig::from_env()?;
    let database = Database::connect(&config.database_url).await?;
    database.migrate().await?;
    ensure_startup_signing_key(&database, &config).await?;

    let organization = match database
        .get_organization_by_slug(&config.default_org_slug)
        .await?
    {
        Some(organization) => organization,
        None => {
            let organization = Organization::new(&config.default_org_slug, "Default Organization")?;
            database.create_organization(&organization).await?;
            organization
        }
    };

    let bind_addr: SocketAddr = config.bind.parse()?;
    let state = http::AppState {
        database,
        organization_id: organization.id,
        config: config.clone(),
    };
    let router = build_router(state);
    let listener = TcpListener::bind(bind_addr).await?;

    tracing::info!(%bind_addr, "starting cairn-api");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
