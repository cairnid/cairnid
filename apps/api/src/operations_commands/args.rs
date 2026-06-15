use super::errors::{config_error, config_error_owned};
use crate::operations_evidence::DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS;

pub(super) fn release_evidence_max_age_days(
    args: &[String],
) -> Result<i64, Box<dyn std::error::Error>> {
    match args {
        [] => Ok(DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS),
        [flag, value] if flag == "--max-age-days" => {
            let parsed = value.parse::<i64>().map_err(|_| {
                config_error_owned(format!("invalid --max-age-days value: {value}"))
            })?;
            if !(1..=365).contains(&parsed) {
                return Err(config_error("--max-age-days must be between 1 and 365"));
            }
            Ok(parsed)
        }
        _ => Err(config_error(
            "usage: cairn-api operations <evidence-check|evidence-status> <evidence-dir> [--max-age-days <days>]",
        )),
    }
}

pub(super) fn release_evidence_init_force(
    args: &[String],
) -> Result<bool, Box<dyn std::error::Error>> {
    match args {
        [] => Ok(false),
        [flag] if flag == "--force" => Ok(true),
        _ => Err(config_error(
            "usage: cairn-api operations evidence-init <evidence-dir> [--force]",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{release_evidence_init_force, release_evidence_max_age_days};
    use crate::operations_evidence::DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS;

    #[test]
    fn release_evidence_max_age_days_defaults_and_accepts_valid_override() {
        assert_eq!(
            release_evidence_max_age_days(&[]).expect("default max age"),
            DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS
        );
        assert_eq!(
            release_evidence_max_age_days(&strings(["--max-age-days", "30"]))
                .expect("custom max age"),
            30
        );
        assert_eq!(
            release_evidence_max_age_days(&strings(["--max-age-days", "365"]))
                .expect("upper bound"),
            365
        );
    }

    #[test]
    fn release_evidence_max_age_days_rejects_invalid_or_out_of_range_values() {
        assert!(
            release_evidence_max_age_days(&strings(["--max-age-days", "zero"]))
                .expect_err("non-numeric max age")
                .to_string()
                .contains("invalid --max-age-days")
        );
        assert!(
            release_evidence_max_age_days(&strings(["--max-age-days", "0"]))
                .expect_err("too small")
                .to_string()
                .contains("between 1 and 365")
        );
        assert!(
            release_evidence_max_age_days(&strings(["--max-age-days", "366"]))
                .expect_err("too large")
                .to_string()
                .contains("between 1 and 365")
        );
        assert!(
            release_evidence_max_age_days(&strings(["--unknown", "30"]))
                .expect_err("unknown flag")
                .to_string()
                .contains("evidence-check|evidence-status")
        );
    }

    #[test]
    fn release_evidence_init_force_accepts_only_optional_force_flag() {
        assert!(!release_evidence_init_force(&[]).expect("default force"));
        assert!(release_evidence_init_force(&strings(["--force"])).expect("force flag"));
        assert!(
            release_evidence_init_force(&strings(["--force", "--extra"]))
                .expect_err("extra argument")
                .to_string()
                .contains("evidence-init")
        );
        assert!(
            release_evidence_init_force(&strings(["force"]))
                .expect_err("invalid force flag")
                .to_string()
                .contains("evidence-init")
        );
    }

    fn strings<const N: usize>(values: [&str; N]) -> Vec<String> {
        values.into_iter().map(str::to_owned).collect()
    }
}
