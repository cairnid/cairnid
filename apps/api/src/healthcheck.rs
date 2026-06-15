use crate::config::ApiConfig;
use std::{
    io,
    net::{IpAddr, SocketAddr},
    time::Duration as StdDuration,
};

pub(crate) async fn run_healthcheck() -> Result<(), Box<dyn std::error::Error>> {
    let config = ApiConfig::from_env()?;
    let url = healthcheck_probe_url(&config.bind)?;
    let response = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(StdDuration::from_secs(2))
        .build()?
        .get(url)
        .send()
        .await?;

    if response.status() != reqwest::StatusCode::OK {
        return Err(config_error_owned(format!(
            "healthcheck returned HTTP {}",
            response.status()
        )));
    }

    let payload = response.json::<serde_json::Value>().await?;
    if payload.get("status").and_then(serde_json::Value::as_str) != Some("ok") {
        return Err(config_error("healthcheck response status was not ok"));
    }

    Ok(())
}

fn healthcheck_probe_url(bind: &str) -> Result<reqwest::Url, Box<dyn std::error::Error>> {
    let (host, port) = match bind.parse::<SocketAddr>() {
        Ok(address) => (healthcheck_host_for_ip(address.ip()), address.port()),
        Err(_) => {
            let (host, port) = split_bind_host_port(bind)?;
            (healthcheck_host_for_bind_host(host), port)
        }
    };

    Ok(reqwest::Url::parse(&format!(
        "http://{host}:{port}/healthz"
    ))?)
}

fn healthcheck_host_for_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(address) if address.is_unspecified() => "127.0.0.1".to_owned(),
        IpAddr::V4(address) => address.to_string(),
        IpAddr::V6(address) if address.is_unspecified() => "127.0.0.1".to_owned(),
        IpAddr::V6(address) => format!("[{address}]"),
    }
}

fn split_bind_host_port(bind: &str) -> Result<(&str, u16), Box<dyn std::error::Error>> {
    let trimmed = bind.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return Err(config_error("CAIRN_API_BIND IPv6 host must include a port"));
        };
        return Ok((host, parse_healthcheck_port(port)?));
    }

    let Some((host, port)) = trimmed.rsplit_once(':') else {
        return Err(config_error("CAIRN_API_BIND must include a port"));
    };

    if host.trim().is_empty() {
        return Err(config_error("CAIRN_API_BIND host must not be empty"));
    }

    Ok((host, parse_healthcheck_port(port)?))
}

fn parse_healthcheck_port(port: &str) -> Result<u16, Box<dyn std::error::Error>> {
    port.parse::<u16>()
        .map_err(|_| config_error("CAIRN_API_BIND port must be a valid TCP port"))
}

fn healthcheck_host_for_bind_host(host: &str) -> String {
    match host.trim() {
        "0.0.0.0" | "::" | "[::]" | "*" => "127.0.0.1".to_owned(),
        candidate if candidate.contains(':') => format!("[{candidate}]"),
        candidate => candidate.to_owned(),
    }
}

fn config_error(message: &'static str) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

fn config_error_owned(message: String) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::healthcheck_probe_url;

    #[test]
    fn healthcheck_probe_url_targets_local_http_health_endpoint() {
        assert_eq!(
            healthcheck_probe_url("0.0.0.0:8080").unwrap().as_str(),
            "http://127.0.0.1:8080/healthz"
        );
        assert_eq!(
            healthcheck_probe_url("[::]:8081").unwrap().as_str(),
            "http://127.0.0.1:8081/healthz"
        );
        assert_eq!(
            healthcheck_probe_url("127.0.0.1:8082").unwrap().as_str(),
            "http://127.0.0.1:8082/healthz"
        );
        assert_eq!(
            healthcheck_probe_url("localhost:8083").unwrap().as_str(),
            "http://localhost:8083/healthz"
        );
    }
}
