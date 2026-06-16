#![forbid(unsafe_code)]

use cairn_operations::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, check_release_evidence, init_release_evidence_directory,
    release_evidence_capture_plan, release_evidence_manifest, release_evidence_status_report,
};
use clap::{Parser, Subcommand};
use std::{env, error::Error, io, path::PathBuf, process::ExitCode};
use time::OffsetDateTime;

#[derive(Debug, Parser)]
#[command(name = "cairnid", version, about = "CairnID operator CLI", long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    Plan,
    Manifest,
    Init {
        evidence_dir: PathBuf,
        #[arg(long)]
        force: bool,
    },
    Status {
        evidence_dir: PathBuf,
        #[arg(long, default_value_t = DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS)]
        max_age_days: i64,
    },
    Check {
        evidence_dir: PathBuf,
        #[arg(long, default_value_t = DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS)]
        max_age_days: i64,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cairnid failed: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    match cli.command {
        Commands::Evidence { command } => run_evidence(command),
    }
}

fn run_evidence(command: EvidenceCommand) -> Result<(), Box<dyn Error>> {
    match command {
        EvidenceCommand::Plan => run_evidence_plan(),
        EvidenceCommand::Manifest => {
            let report = release_evidence_manifest(OffsetDateTime::now_utc());
            print_report(&report)
        }
        EvidenceCommand::Init {
            evidence_dir,
            force,
        } => {
            let report =
                init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), force)?;
            print_report(&report)
        }
        EvidenceCommand::Status {
            evidence_dir,
            max_age_days,
        } => run_evidence_status(evidence_dir, max_age_days),
        EvidenceCommand::Check {
            evidence_dir,
            max_age_days,
        } => run_evidence_check(evidence_dir, max_age_days),
    }
}

fn run_evidence_plan() -> Result<(), Box<dyn Error>> {
    let report = release_evidence_capture_plan(
        OffsetDateTime::now_utc(),
        |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
    );
    let ready = report.missing_environment.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(user_error(format!(
            "release evidence capture environment is incomplete: {}",
            report.missing_environment.join("; ")
        )))
    }
}

fn run_evidence_status(evidence_dir: PathBuf, max_age_days: i64) -> Result<(), Box<dyn Error>> {
    let report =
        release_evidence_status_report(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)?;
    let ready = report.failures.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(user_error(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

fn run_evidence_check(evidence_dir: PathBuf, max_age_days: i64) -> Result<(), Box<dyn Error>> {
    let report = check_release_evidence(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)?;
    let ready = report.failures.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(user_error(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

fn print_report<T: serde::Serialize>(report: &T) -> Result<(), Box<dyn Error>> {
    println!("{}", serde_json::to_string_pretty(report)?);
    Ok(())
}

fn user_error(message: String) -> Box<dyn Error> {
    Box::new(io::Error::new(io::ErrorKind::InvalidInput, message))
}

#[cfg(test)]
mod tests {
    use super::{Cli, Commands, EvidenceCommand};
    use clap::{CommandFactory, Parser};
    use std::path::PathBuf;

    #[test]
    fn clap_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_evidence_check_with_max_age_override() {
        let cli = Cli::parse_from([
            "cairnid",
            "evidence",
            "check",
            "release-evidence",
            "--max-age-days",
            "45",
        ]);

        let Commands::Evidence { command } = cli.command;
        let EvidenceCommand::Check {
            evidence_dir,
            max_age_days,
        } = command
        else {
            panic!("expected evidence check command");
        };

        assert_eq!(evidence_dir, PathBuf::from("release-evidence"));
        assert_eq!(max_age_days, 45);
    }

    #[test]
    fn parses_evidence_init_force() {
        let cli = Cli::parse_from(["cairnid", "evidence", "init", "release-evidence", "--force"]);

        let Commands::Evidence { command } = cli.command;
        let EvidenceCommand::Init {
            evidence_dir,
            force,
        } = command
        else {
            panic!("expected evidence init command");
        };

        assert_eq!(evidence_dir, PathBuf::from("release-evidence"));
        assert!(force);
    }

    #[test]
    fn rejects_missing_evidence_dir() {
        assert!(Cli::try_parse_from(["cairnid", "evidence", "check"]).is_err());
    }
}
