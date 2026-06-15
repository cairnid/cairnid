mod preflight;
mod result_template;
mod static_config;
mod static_registration;
#[cfg(test)]
mod tests;
mod types;
mod validation;

pub use self::{
    preflight::openid_conformance_operations_preflight_report,
    types::OpenIdConformanceOperationsPreflightReport,
};
use self::{
    result_template::openid_conformance_result_template,
    static_config::openid_conformance_static_config_from_env,
    static_registration::openid_conformance_static_registration_from_env, validation::config_error,
};

pub async fn run_conformance_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("oidcc-static-config") => {
            let suite_config = openid_conformance_static_config_from_env()?;
            println!("{}", serde_json::to_string_pretty(&suite_config)?);
            Ok(())
        }
        Some("oidcc-static-registration") => {
            let report = openid_conformance_static_registration_from_env()?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("oidcc-result-template") => {
            let [_, profile] = args else {
                return Err(config_error(
                    "usage: cairn-api conformance oidcc-result-template <config-op|basic-op>",
                ));
            };
            let report = openid_conformance_result_template(profile)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        _ => Err(config_error(
            "usage: cairn-api conformance <oidcc-static-config|oidcc-static-registration|oidcc-result-template <config-op|basic-op>>",
        )),
    }
}
