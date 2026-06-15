use super::{
    args::{release_evidence_init_force, release_evidence_max_age_days},
    errors::{config_error, config_error_owned},
};
use crate::operations_evidence::{
    check_release_evidence, init_release_evidence_directory, release_evidence_capture_plan,
    release_evidence_manifest, release_evidence_status_report,
};
use std::{env, path::Path};
use time::OffsetDateTime;

pub(super) fn run_evidence_check_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(evidence_dir) = args.get(1) else {
        return Err(config_error(
            "usage: cairn-api operations evidence-check <evidence-dir> [--max-age-days <days>]",
        ));
    };
    let max_age_days = release_evidence_max_age_days(&args[2..])?;
    let report = check_release_evidence(
        Path::new(evidence_dir),
        OffsetDateTime::now_utc(),
        max_age_days,
    )?;
    let ready = report.failures.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

pub(super) fn run_evidence_status_command(
    args: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(evidence_dir) = args.get(1) else {
        return Err(config_error(
            "usage: cairn-api operations evidence-status <evidence-dir> [--max-age-days <days>]",
        ));
    };
    let max_age_days = release_evidence_max_age_days(&args[2..])?;
    let report = release_evidence_status_report(
        Path::new(evidence_dir),
        OffsetDateTime::now_utc(),
        max_age_days,
    )?;
    let ready = report.failures.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

pub(super) fn run_evidence_manifest_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = release_evidence_manifest(OffsetDateTime::now_utc());
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}

pub(super) fn run_evidence_plan_command() -> Result<(), Box<dyn std::error::Error>> {
    let report = release_evidence_capture_plan(
        OffsetDateTime::now_utc(),
        |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
    );
    let ready = report.missing_environment.is_empty();
    println!("{}", serde_json::to_string_pretty(&report)?);

    if ready {
        Ok(())
    } else {
        Err(config_error_owned(format!(
            "release evidence capture environment is incomplete: {}",
            report.missing_environment.join("; ")
        )))
    }
}

pub(super) fn run_evidence_init_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let Some(evidence_dir) = args.get(1) else {
        return Err(config_error(
            "usage: cairn-api operations evidence-init <evidence-dir> [--force]",
        ));
    };
    let force = release_evidence_init_force(&args[2..])?;
    let report =
        init_release_evidence_directory(Path::new(evidence_dir), OffsetDateTime::now_utc(), force)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    Ok(())
}
