use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};
use time::{Date, Month, OffsetDateTime, Time, format_description::well_known::Rfc3339};
use zip::ZipArchive;

const TEST_LOG_PREFIX: &str = "test-logs/test-log-";
const TEST_LOG_SUFFIX: &str = ".json";
const FORBIDDEN_LOG_FIELD_KEYS: &[&str] = &[
    "authorization",
    "authorizationheader",
    "bearertoken",
    "clientsecret",
    "cookie",
    "idtoken",
    "password",
    "privatekey",
    "requestheader",
    "requestheaders",
    "secret",
    "sessioncookie",
    "token",
];

pub fn normalize_openid_conformance_export(
    profile: &str,
    export_path: impl AsRef<Path>,
    published_result_url: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let profile = export_profile(profile)?;
    validate_suite_origin("published_result_url", published_result_url)?;

    let package = OidfExportPackage::read(export_path.as_ref())?;
    let plan = parse_plan_index(&package.index_json)?;
    if plan.plan_name != profile.plan_name {
        return Err(error(format!(
            "OIDF export plan name must be {}, got {}",
            profile.plan_name, plan.plan_name
        )));
    }
    if plan.modules.is_empty() {
        return Err(error("OIDF export planInfo.modules must be non-empty"));
    }
    for module in &plan.modules {
        if module.instances.is_empty() {
            return Err(error(format!(
                "OIDF export module {} must include at least one instance",
                module.test_module
            )));
        }
    }

    let expected_instances = plan
        .modules
        .iter()
        .map(|module| {
            (
                module
                    .instances
                    .last()
                    .expect("module instances already checked")
                    .clone(),
                module.test_module.clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut matched_instances = BTreeSet::new();
    let mut saw_warning = false;
    let mut completed_at = None;

    for log in package.test_logs {
        reject_forbidden_log_fields(&log.value, "$")?;
        let export = parse_test_log(log.name, &log.value)?;
        let Some(expected_module) = expected_instances.get(&export.test_id) else {
            return Err(error(format!(
                "OIDF export test log {} does not match any plan module instance",
                export.test_id
            )));
        };
        if expected_module != &export.test_module_name {
            return Err(error(format!(
                "OIDF export test log {} module must be {}, got {}",
                export.test_id, expected_module, export.test_module_name
            )));
        }
        if !matched_instances.insert(export.test_id.clone()) {
            return Err(error(format!(
                "OIDF export has duplicate test log for {}",
                export.test_id
            )));
        }
        if export.result.eq_ignore_ascii_case("WARNING") {
            saw_warning = true;
        }
        completed_at = Some(match completed_at {
            Some(current) if current >= export.exported_at => current,
            _ => export.exported_at,
        });
    }

    for (test_id, module_name) in expected_instances {
        if !matched_instances.contains(&test_id) {
            return Err(error(format!(
                "OIDF export is missing test log for module {module_name} instance {test_id}"
            )));
        }
    }

    let Some(completed_at) = completed_at else {
        return Err(error(
            "OIDF export must include at least one matching test log",
        ));
    };

    Ok(json!({
        "source": "openid-conformance-suite",
        "certification_profile": profile.certification_profile,
        "plan_name": profile.plan_name,
        "status": "FINISHED",
        "result": if saw_warning { "WARNING" } else { "PASSED" },
        "completed_at": completed_at
            .format(&Rfc3339)
            .map_err(|format_error| error(format!("failed to format completed_at: {format_error}")))?,
        "published_result_url": published_result_url
    }))
}

#[derive(Clone, Copy)]
struct ExportProfile {
    certification_profile: &'static str,
    plan_name: &'static str,
}

fn export_profile(profile: &str) -> Result<ExportProfile, Box<dyn std::error::Error>> {
    match profile.trim().to_ascii_lowercase().as_str() {
        "config-op" | "config" | "configuration" | "oidcc-config-certification-test-plan" => {
            Ok(ExportProfile {
                certification_profile: "Config OP",
                plan_name: "oidcc-config-certification-test-plan",
            })
        }
        "basic-op" | "basic" | "oidcc-basic-certification-test-plan" => Ok(ExportProfile {
            certification_profile: "Basic OP",
            plan_name: "oidcc-basic-certification-test-plan",
        }),
        _ => Err(error(
            "OpenID conformance export profile must be config-op or basic-op",
        )),
    }
}

struct OidfExportPackage {
    index_json: Value,
    test_logs: Vec<NamedJson>,
}

struct NamedJson {
    name: String,
    value: Value,
}

impl OidfExportPackage {
    fn read(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        if path.is_dir() {
            Self::read_dir(path)
        } else {
            Self::read_zip(path)
        }
    }

    fn read_dir(root: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let index_path = root
            .join("test-logs")
            .join("index.json")
            .is_file()
            .then(|| root.join("test-logs").join("index.json"))
            .or_else(|| {
                root.join("index.json")
                    .is_file()
                    .then(|| root.join("index.json"))
            })
            .ok_or_else(|| error("OIDF export directory must contain index.json"))?;
        let index_json = read_json_file(&index_path)?;
        let logs_dir = root.join("test-logs");
        if !logs_dir.is_dir() {
            return Err(error("OIDF export directory must contain test-logs"));
        }
        let mut test_logs = Vec::new();
        for entry in fs::read_dir(&logs_dir)? {
            let entry = entry?;
            let path = entry.path();
            let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if file_name.starts_with("test-log-") && file_name.ends_with(TEST_LOG_SUFFIX) {
                test_logs.push(NamedJson {
                    name: format!("test-logs/{file_name}"),
                    value: read_json_file(&path)?,
                });
            }
        }
        if test_logs.is_empty() {
            return Err(error("OIDF export must contain test-logs/test-log-*.json"));
        }
        Ok(Self {
            index_json,
            test_logs,
        })
    }

    fn read_zip(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let file = File::open(path)
            .map_err(|open_error| error(format!("failed to open OIDF ZIP: {open_error}")))?;
        let mut archive = ZipArchive::new(file)
            .map_err(|zip_error| error(format!("failed to read OIDF ZIP: {zip_error}")))?;
        let mut index_json = None;
        let mut test_logs = Vec::new();

        for index in 0..archive.len() {
            let mut member = archive
                .by_index(index)
                .map_err(|zip_error| error(format!("failed to read ZIP entry: {zip_error}")))?;
            if member.is_dir() {
                continue;
            }
            let name = normalize_zip_entry_name(member.name());
            if name == "test-logs/index.json" || name == "index.json" {
                index_json = Some(read_json_from_reader(&mut member, &name)?);
            } else if name.starts_with(TEST_LOG_PREFIX) && name.ends_with(TEST_LOG_SUFFIX) {
                let value = read_json_from_reader(&mut member, &name)?;
                test_logs.push(NamedJson { name, value });
            }
        }

        let Some(index_json) = index_json else {
            return Err(error("OIDF ZIP export must contain index.json"));
        };
        if test_logs.is_empty() {
            return Err(error(
                "OIDF ZIP export must contain test-logs/test-log-*.json",
            ));
        }
        Ok(Self {
            index_json,
            test_logs,
        })
    }
}

struct OidfPlanIndex {
    plan_name: String,
    modules: Vec<OidfPlanModule>,
}

struct OidfPlanModule {
    test_module: String,
    instances: Vec<String>,
}

struct OidfTestLog {
    test_id: String,
    test_module_name: String,
    result: String,
    exported_at: OffsetDateTime,
}

fn parse_plan_index(value: &Value) -> Result<OidfPlanIndex, Box<dyn std::error::Error>> {
    let plan_value = value.get("planInfo").unwrap_or(value);
    let plan_name = string_field(plan_value, &["planName", "plan_name", "name"], "plan name")?;
    let modules = plan_value
        .get("modules")
        .and_then(Value::as_array)
        .ok_or_else(|| error("OIDF export index.json must contain modules"))?
        .iter()
        .enumerate()
        .map(|(index, module)| {
            let test_module = string_field(
                module,
                &["testModule", "test_module", "testModuleName"],
                &format!("modules[{index}].testModule"),
            )?;
            let instances = module
                .get("instances")
                .and_then(Value::as_array)
                .ok_or_else(|| error(format!("modules[{index}].instances must be an array")))?
                .iter()
                .filter_map(Value::as_str)
                .filter(|instance| !instance.trim().is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            Ok(OidfPlanModule {
                test_module,
                instances,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn std::error::Error>>>()?;
    Ok(OidfPlanIndex { plan_name, modules })
}

fn parse_test_log(name: String, value: &Value) -> Result<OidfTestLog, Box<dyn std::error::Error>> {
    let exported_from = string_field(value, &["exportedFrom"], "exportedFrom")?;
    validate_suite_origin("exportedFrom", &exported_from)?;
    let exported_at = suite_timestamp(&string_field(value, &["exportedAt"], "exportedAt")?)?;
    let test_info = value
        .get("testInfo")
        .map(|test_info| test_info.get("testInfo").unwrap_or(test_info))
        .ok_or_else(|| error(format!("{name} must contain testInfo")))?;
    let test_id = string_field(test_info, &["testId", "id"], "testInfo.testId")?;
    let test_module_name = string_field(
        test_info,
        &["testName", "testModuleName"],
        "testInfo.testName",
    )?;
    let status = string_field(test_info, &["status"], "testInfo.status")?;
    let result = string_field(test_info, &["result"], "testInfo.result")?;

    if !status.eq_ignore_ascii_case("FINISHED") {
        return Err(error(format!(
            "OIDF export test {test_id} status must be FINISHED, got {status}"
        )));
    }
    if !(result.eq_ignore_ascii_case("PASSED") || result.eq_ignore_ascii_case("WARNING")) {
        return Err(error(format!(
            "OIDF export test {test_id} result must be PASSED or WARNING, got {result}"
        )));
    }

    Ok(OidfTestLog {
        test_id,
        test_module_name,
        result,
        exported_at,
    })
}

fn validate_suite_origin(label: &str, value: &str) -> Result<(), Box<dyn std::error::Error>> {
    let url = url::Url::parse(value)
        .map_err(|parse_error| error(format!("{label} must be a valid URL: {parse_error}")))?;
    if url.scheme() == "https"
        && url.host_str() == Some("www.certification.openid.net")
        && url.username().is_empty()
        && url.password().is_none()
    {
        Ok(())
    } else {
        Err(error(format!(
            "{label} must be an HTTPS URL on www.certification.openid.net without credentials"
        )))
    }
}

fn reject_forbidden_log_fields(
    value: &Value,
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match value {
        Value::Object(object) => {
            for (key, child) in object {
                let normalized_key = key
                    .chars()
                    .filter(|character| character.is_ascii_alphanumeric())
                    .collect::<String>()
                    .to_ascii_lowercase();
                let child_path = child_path(path, key);
                if FORBIDDEN_LOG_FIELD_KEYS.contains(&normalized_key.as_str()) {
                    return Err(error(format!(
                        "OIDF export test log contains forbidden secret-bearing field at {child_path}"
                    )));
                }
                reject_forbidden_log_fields(child, &child_path)?;
            }
        }
        Value::Array(values) => {
            for (index, child) in values.iter().enumerate() {
                reject_forbidden_log_fields(child, &format!("{path}[{index}]"))?;
            }
        }
        Value::String(text) => {
            if looks_like_raw_credential(text) {
                return Err(error(format!(
                    "OIDF export test log contains forbidden credential-shaped value at {path}"
                )));
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn looks_like_raw_credential(value: &str) -> bool {
    let trimmed = value.trim();
    let lower = trimmed.to_ascii_lowercase();
    lower.starts_with("bearer ")
        || lower.starts_with("basic ")
        || lower.contains("authorization: bearer ")
        || lower.contains("client_secret=")
        || lower.contains("password=")
        || lower.contains("refresh_token=")
        || lower.contains("access_token=")
        || looks_like_compact_jwt(trimmed)
}

fn looks_like_compact_jwt(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|part| part.len() >= 16)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn suite_timestamp(value: &str) -> Result<OffsetDateTime, Box<dyn std::error::Error>> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .or_else(|| parse_openid_suite_export_timestamp(value))
        .ok_or_else(|| error("OIDF export timestamp must be RFC3339 or OpenID suite format"))
}

fn parse_openid_suite_export_timestamp(value: &str) -> Option<OffsetDateTime> {
    let mut parts = value.split(',');
    let month_day = parts.next()?.trim();
    let year = parts.next()?.trim().parse::<i32>().ok()?;
    let time_period = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }

    let mut month_day_parts = month_day.split_whitespace();
    let month = parse_english_month(month_day_parts.next()?)?;
    let day = month_day_parts.next()?.parse::<u8>().ok()?;
    if month_day_parts.next().is_some() {
        return None;
    }

    let mut time_period_parts = time_period.split_whitespace();
    let time = time_period_parts.next()?;
    let period = time_period_parts.next()?.to_ascii_uppercase();
    if time_period_parts.next().is_some() {
        return None;
    }

    let mut time_parts = time.split(':');
    let hour = time_parts.next()?.parse::<u8>().ok()?;
    let minute = time_parts.next()?.parse::<u8>().ok()?;
    let second = time_parts.next()?.parse::<u8>().ok()?;
    if time_parts.next().is_some() || !(1..=12).contains(&hour) {
        return None;
    }
    let hour = match (hour, period.as_str()) {
        (12, "AM") => 0,
        (12, "PM") => 12,
        (hour, "AM") => hour,
        (hour, "PM") => hour + 12,
        _ => return None,
    };

    let date = Date::from_calendar_date(year, month, day).ok()?;
    let time = Time::from_hms(hour, minute, second).ok()?;
    Some(date.with_time(time).assume_utc())
}

fn parse_english_month(value: &str) -> Option<Month> {
    match value.to_ascii_lowercase().as_str() {
        "jan" | "january" => Some(Month::January),
        "feb" | "february" => Some(Month::February),
        "mar" | "march" => Some(Month::March),
        "apr" | "april" => Some(Month::April),
        "may" => Some(Month::May),
        "jun" | "june" => Some(Month::June),
        "jul" | "july" => Some(Month::July),
        "aug" | "august" => Some(Month::August),
        "sep" | "sept" | "september" => Some(Month::September),
        "oct" | "october" => Some(Month::October),
        "nov" | "november" => Some(Month::November),
        "dec" | "december" => Some(Month::December),
        _ => None,
    }
}

fn read_json_file(path: &Path) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(path)
        .map_err(|open_error| error(format!("failed to open {}: {open_error}", path.display())))?;
    read_json_from_reader(file, &path.to_string_lossy())
}

fn read_json_from_reader(
    mut reader: impl Read,
    name: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let mut body = String::new();
    reader
        .read_to_string(&mut body)
        .map_err(|read_error| error(format!("failed to read {name}: {read_error}")))?;
    serde_json::from_str(&body)
        .map_err(|json_error| error(format!("malformed JSON in {name}: {json_error}")))
}

fn string_field(
    value: &Value,
    keys: &[&str],
    label: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    keys.iter()
        .find_map(|key| value.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| error(format!("{label} must be present")))
}

fn normalize_zip_entry_name(name: &str) -> String {
    PathBuf::from(name)
        .components()
        .filter_map(|component| match component {
            std::path::Component::Normal(part) => part.to_str().map(str::to_owned),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn child_path(parent: &str, key: &str) -> String {
    if parent == "$" {
        format!("$.{key}")
    } else {
        format!("{parent}.{key}")
    }
}

fn error(message: impl Into<String>) -> Box<dyn std::error::Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message.into()))
}
