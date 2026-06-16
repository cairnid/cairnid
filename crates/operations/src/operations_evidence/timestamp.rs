use serde_json::Value;
use time::{Date, Duration, Month, OffsetDateTime, Time};

pub(super) const RELEASE_EVIDENCE_CLOCK_SKEW_SECONDS: i64 = 300;

pub(super) fn validate_artifact_root_timestamp_freshness(
    value: &Value,
    now: OffsetDateTime,
    max_age_days: i64,
    checks: &mut Vec<String>,
    failures: &mut Vec<String>,
) {
    let Some((field, timestamp)) = value
        .get("completed_at")
        .and_then(Value::as_str)
        .map(|timestamp| ("completed_at", timestamp))
        .or_else(|| {
            value
                .get("exportedAt")
                .and_then(Value::as_str)
                .map(|timestamp| ("exportedAt", timestamp))
        })
        .or_else(|| {
            value
                .get("generated_at")
                .and_then(Value::as_str)
                .map(|timestamp| ("generated_at", timestamp))
        })
    else {
        return;
    };
    let Some(timestamp) = parse_release_evidence_timestamp(timestamp) else {
        return;
    };

    if now - timestamp > Duration::days(max_age_days) {
        failures.push(format!(
            "{field} is older than {max_age_days} days and must be refreshed"
        ));
    } else if timestamp - now > Duration::seconds(RELEASE_EVIDENCE_CLOCK_SKEW_SECONDS) {
        failures.push(format!(
            "{field} is more than {RELEASE_EVIDENCE_CLOCK_SKEW_SECONDS} seconds in the future"
        ));
    } else {
        checks.push(
            "completion timestamp is within the release evidence freshness window".to_owned(),
        );
    }
}

pub(super) fn parse_release_evidence_timestamp(value: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
        .ok()
        .or_else(|| parse_openid_suite_export_timestamp(value))
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

#[cfg(test)]
mod tests {
    use super::{parse_release_evidence_timestamp, validate_artifact_root_timestamp_freshness};
    use serde_json::json;
    use time::OffsetDateTime;

    #[test]
    fn release_evidence_timestamp_accepts_rfc3339_and_openid_suite_exports() {
        assert_eq!(
            parse_release_evidence_timestamp("2026-06-07T12:00:00Z").expect("RFC3339 timestamp"),
            timestamp("2026-06-07T12:00:00Z")
        );
        assert_eq!(
            parse_release_evidence_timestamp("June 7, 2026, 12:00:00 PM")
                .expect("OpenID suite export timestamp"),
            timestamp("2026-06-07T12:00:00Z")
        );
        assert_eq!(
            parse_release_evidence_timestamp("May 1, 2026, 12:00:00 AM")
                .expect("midnight OpenID suite export timestamp"),
            timestamp("2026-05-01T00:00:00Z")
        );
    }

    #[test]
    fn release_evidence_timestamp_rejects_ambiguous_or_malformed_exports() {
        for value in [
            "2026-06-07 12:00:00",
            "June 7, 2026, 12:00 PM",
            "June 7, 2026, 00:00:00 AM",
            "June 7, 2026, 13:00:00 PM",
            "NotAMonth 7, 2026, 12:00:00 PM",
        ] {
            assert!(
                parse_release_evidence_timestamp(value).is_none(),
                "{value} should be rejected"
            );
        }
    }

    #[test]
    fn root_timestamp_freshness_reports_stale_and_future_values() {
        let now = timestamp("2026-06-07T12:00:00Z");
        let mut checks = Vec::new();
        let mut failures = Vec::new();

        validate_artifact_root_timestamp_freshness(
            &json!({ "completed_at": "2026-05-01T12:00:00Z" }),
            now,
            30,
            &mut checks,
            &mut failures,
        );
        validate_artifact_root_timestamp_freshness(
            &json!({ "generated_at": "2026-06-07T12:10:01Z" }),
            now,
            30,
            &mut checks,
            &mut failures,
        );

        assert!(checks.is_empty());
        assert!(failures.iter().any(|failure| {
            failure.contains("completed_at is older than 30 days and must be refreshed")
        }));
        assert!(failures.iter().any(|failure| {
            failure.contains("generated_at is more than 300 seconds in the future")
        }));
    }

    fn timestamp(value: &str) -> OffsetDateTime {
        OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339)
            .expect("valid test timestamp")
    }
}
