use crate::{scim_profile, scim_smoke};
use std::{env, io};

pub(crate) async fn run_scim_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    match args.first().map(String::as_str) {
        Some("smoke") => {
            let report = scim_smoke::run_scim_smoke_from_env().await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("connector-profile") => {
            let [_, profile] = args else {
                return Err(config_error(
                    "usage: cairn-api scim connector-profile <generic|okta|entra>",
                ));
            };
            let issuer = required_env("CAIRN_ISSUER")?;
            let report = scim_profile::scim_connector_profile(profile, &issuer)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        Some("connector-smoke-template") => {
            let [_, profile] = args else {
                return Err(config_error(
                    "usage: cairn-api scim connector-smoke-template <okta|entra>",
                ));
            };
            let issuer = required_env("CAIRN_ISSUER")?;
            let report = scim_profile::scim_connector_smoke_template(profile, &issuer)?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            Ok(())
        }
        _ => Err(config_error(
            "usage: cairn-api scim <smoke|connector-profile <generic|okta|entra>|connector-smoke-template <okta|entra>>",
        )),
    }
}

fn required_env(name: &'static str) -> Result<String, Box<dyn std::error::Error>> {
    required_env_from_lookup(name, env::var)
}

fn required_env_from_lookup<F>(
    name: &'static str,
    lookup: F,
) -> Result<String, Box<dyn std::error::Error>>
where
    F: FnOnce(&'static str) -> Result<String, env::VarError>,
{
    lookup(name)
        .map_err(|_| config_error_owned(format!("missing required environment variable {name}")))
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::{required_env_from_lookup, run_scim_command};
    use std::env;

    #[test]
    fn required_env_from_lookup_reports_missing_variable_name_without_reading_real_env() {
        let error = required_env_from_lookup("CAIRN_ISSUER", |_| Err(env::VarError::NotPresent))
            .expect_err("missing environment variable");

        assert_eq!(
            error.to_string(),
            "missing required environment variable CAIRN_ISSUER"
        );
    }

    #[test]
    fn required_env_from_lookup_preserves_configured_value() {
        let value = required_env_from_lookup("CAIRN_ISSUER", |name| {
            assert_eq!(name, "CAIRN_ISSUER");
            Ok("https://id.example.com".to_owned())
        })
        .expect("configured environment variable");

        assert_eq!(value, "https://id.example.com");
    }

    #[tokio::test]
    async fn scim_command_dispatch_rejects_unknown_subcommand() {
        let error = run_scim_command(&strings(["unknown"]))
            .await
            .expect_err("unknown subcommand");

        assert!(error.to_string().contains("usage: cairn-api scim"));
    }

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_owned).collect()
    }
}
