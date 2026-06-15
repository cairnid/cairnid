use super::{ConfigError, RequestIdentityConfig};
use std::net::IpAddr;

const TRUSTED_PROXY_IPS_ENV: &str = "CAIRN_TRUSTED_PROXY_IPS";

pub(super) fn request_identity_from_env() -> Result<RequestIdentityConfig, ConfigError> {
    Ok(RequestIdentityConfig {
        trusted_proxy_ips: trusted_proxy_ips_from_value(
            std::env::var(TRUSTED_PROXY_IPS_ENV).ok().as_deref(),
        )?,
    })
}

fn trusted_proxy_ips_from_value(value: Option<&str>) -> Result<Vec<IpAddr>, ConfigError> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let mut trusted_proxy_ips = Vec::new();
    for raw_ip in value.split(',') {
        let raw_ip = raw_ip.trim();
        if raw_ip.is_empty() {
            continue;
        }

        trusted_proxy_ips.push(raw_ip.parse::<IpAddr>().map_err(|_| {
            ConfigError::InvalidIpAddress {
                variable: TRUSTED_PROXY_IPS_ENV,
                value: raw_ip.to_owned(),
            }
        })?);
    }

    Ok(trusted_proxy_ips)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trusted_proxy_ips_default_to_untrusted() {
        assert_eq!(
            trusted_proxy_ips_from_value(None).unwrap(),
            Vec::<IpAddr>::new()
        );
        assert_eq!(
            trusted_proxy_ips_from_value(Some(" , ")).unwrap(),
            Vec::<IpAddr>::new()
        );
    }

    #[test]
    fn trusted_proxy_ips_parse_comma_separated_exact_addresses() {
        let ips = trusted_proxy_ips_from_value(Some("127.0.0.1, ::1")).unwrap();

        assert_eq!(
            ips,
            vec![
                "127.0.0.1".parse::<IpAddr>().unwrap(),
                "::1".parse::<IpAddr>().unwrap()
            ]
        );
    }

    #[test]
    fn trusted_proxy_ips_reject_invalid_addresses() {
        assert!(matches!(
            trusted_proxy_ips_from_value(Some("127.0.0.1, bad-ip")),
            Err(ConfigError::InvalidIpAddress {
                variable: "CAIRN_TRUSTED_PROXY_IPS",
                value
            }) if value == "bad-ip"
        ));
    }
}
