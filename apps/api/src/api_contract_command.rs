use crate::http::api_contract::api_contract_report;
use std::io;
use time::OffsetDateTime;

#[inline(never)]
pub(crate) fn run_api_contract_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if !args.is_empty() {
        return Err(config_error("usage: cairn-api api-contract"));
    }

    println!("{}", render_api_contract_json(OffsetDateTime::now_utc())?);
    Ok(())
}

#[inline(never)]
fn render_api_contract_json(generated_at: OffsetDateTime) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(&api_contract_report(generated_at))
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::{render_api_contract_json, run_api_contract_command};
    use crate::http::api_contract::{API_CONTRACT_SCHEMA_VERSION, api_contract_routes};
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};

    #[test]
    fn api_contract_command_rejects_arguments() {
        let error = run_api_contract_command(&["unexpected".to_owned()])
            .expect_err("extra argument should fail");

        assert_eq!(error.to_string(), "usage: cairn-api api-contract");
    }

    #[test]
    fn api_contract_command_json_matches_checked_manifest() {
        let rendered =
            render_api_contract_json(test_generated_at()).expect("API contract serializes");
        let json: serde_json::Value =
            serde_json::from_str(&rendered).expect("API contract is valid JSON");

        assert_eq!(json["schema_version"], API_CONTRACT_SCHEMA_VERSION);
        let generated_at = json["generated_at"]
            .as_str()
            .expect("generated_at is serialized");
        OffsetDateTime::parse(generated_at, &Rfc3339).expect("generated_at is RFC3339");

        let routes = json["routes"].as_array().expect("routes array");
        assert!(!routes.is_empty());
        assert_eq!(routes.len(), api_contract_routes().len());

        for (exported, manifest) in routes.iter().zip(api_contract_routes()) {
            assert_eq!(exported["method"], manifest.method.as_str());
            assert_eq!(exported["path"], manifest.path);
            assert_eq!(exported["audience"], manifest.audience.as_str());
            assert_eq!(exported["handler"], manifest.handler);
            assert_eq!(
                exported["request_contract_label"],
                serde_json::to_value(manifest.request_schema.name()).expect("request label json")
            );
            assert_eq!(
                exported["response_contract_label"],
                serde_json::to_value(manifest.response_schema.name()).expect("response label json")
            );
        }
    }

    fn test_generated_at() -> OffsetDateTime {
        OffsetDateTime::parse("2026-06-18T12:00:00Z", &Rfc3339).expect("test timestamp")
    }
}
