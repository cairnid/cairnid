#![forbid(unsafe_code)]

use cairn_operations::{
    DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS, ReleaseEvidenceError, check_release_evidence,
    init_release_evidence_directory, release_evidence_capture_plan, release_evidence_manifest,
    release_evidence_status_report,
};
use clap::{Parser, Subcommand};
use std::{env, error::Error, fmt, path::PathBuf, process::ExitCode};
use time::OffsetDateTime;

const EXIT_INTERNAL_ERROR: u8 = 1;
const EXIT_GATE_FAILED: u8 = 3;
const EXIT_OPERATOR_INPUT: u8 = 4;

#[derive(Debug, Parser)]
#[command(name = "cairnid", version, about = "CairnID operator CLI", long_about = None)]
#[command(propagate_version = true)]
#[command(
    after_help = "Examples:\n  cairnid evidence plan\n  cairnid evidence check release-evidence"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    #[command(
        about = "Plan, initialize, inspect, and check release evidence",
        after_help = "Examples:\n  cairnid evidence plan\n  cairnid evidence init release-evidence\n  cairnid evidence check release-evidence --max-age-days 30"
    )]
    Evidence {
        #[command(subcommand)]
        command: EvidenceCommand,
    },
}

#[derive(Debug, Subcommand)]
enum EvidenceCommand {
    #[command(
        about = "Print the release evidence capture plan as JSON",
        after_help = "Examples:\n  cairnid evidence plan"
    )]
    Plan,
    #[command(
        about = "Print the release evidence manifest contract as JSON",
        after_help = "Examples:\n  cairnid evidence manifest"
    )]
    Manifest,
    #[command(
        about = "Create a release evidence scaffold directory",
        after_help = "Examples:\n  cairnid evidence init release-evidence\n  cairnid evidence init release-evidence --force"
    )]
    Init {
        #[arg(
            value_name = "EVIDENCE_DIR",
            help = "Release evidence directory to create"
        )]
        evidence_dir: PathBuf,
        #[arg(long, help = "Replace existing generated scaffold files")]
        force: bool,
    },
    #[command(
        about = "Summarize release evidence readiness as JSON",
        after_help = "Examples:\n  cairnid evidence status release-evidence\n  cairnid evidence status release-evidence --max-age-days 14"
    )]
    Status {
        #[arg(
            value_name = "EVIDENCE_DIR",
            required_unless_present = "evidence_dir_option",
            conflicts_with = "evidence_dir_option",
            help = "Release evidence directory to inspect"
        )]
        evidence_dir: Option<PathBuf>,
        #[arg(
            long = "evidence-dir",
            value_name = "EVIDENCE_DIR",
            help = "Release evidence directory to inspect"
        )]
        evidence_dir_option: Option<PathBuf>,
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
            value_parser = clap::value_parser!(i64).range(1..=365),
            help = "Maximum artifact age in days"
        )]
        max_age_days: i64,
    },
    #[command(
        about = "Validate release evidence artifacts and print the full JSON report",
        after_help = "Examples:\n  cairnid evidence check release-evidence\n  cairnid evidence check release-evidence --max-age-days 7"
    )]
    Check {
        #[arg(
            value_name = "EVIDENCE_DIR",
            required_unless_present = "evidence_dir_option",
            conflicts_with = "evidence_dir_option",
            help = "Release evidence directory to validate"
        )]
        evidence_dir: Option<PathBuf>,
        #[arg(
            long = "evidence-dir",
            value_name = "EVIDENCE_DIR",
            help = "Release evidence directory to validate"
        )]
        evidence_dir_option: Option<PathBuf>,
        #[arg(
            long,
            value_name = "DAYS",
            default_value_t = DEFAULT_RELEASE_EVIDENCE_MAX_AGE_DAYS,
            value_parser = clap::value_parser!(i64).range(1..=365),
            help = "Maximum artifact age in days"
        )]
        max_age_days: i64,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("cairnid failed: {err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
    match cli.command {
        Commands::Evidence { command } => run_evidence(command),
    }
}

fn run_evidence(command: EvidenceCommand) -> Result<(), CliError> {
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
                init_release_evidence_directory(&evidence_dir, OffsetDateTime::now_utc(), force)
                    .map_err(release_evidence_cli_error)?;
            print_report(&report)
        }
        EvidenceCommand::Status {
            evidence_dir,
            evidence_dir_option,
            max_age_days,
        } => run_evidence_status(
            selected_evidence_dir(evidence_dir, evidence_dir_option),
            max_age_days,
        ),
        EvidenceCommand::Check {
            evidence_dir,
            evidence_dir_option,
            max_age_days,
        } => run_evidence_check(
            selected_evidence_dir(evidence_dir, evidence_dir_option),
            max_age_days,
        ),
    }
}

fn selected_evidence_dir(
    evidence_dir: Option<PathBuf>,
    evidence_dir_option: Option<PathBuf>,
) -> PathBuf {
    evidence_dir
        .or(evidence_dir_option)
        .expect("clap requires an evidence directory")
}

fn run_evidence_plan() -> Result<(), CliError> {
    let report = release_evidence_capture_plan(
        OffsetDateTime::now_utc(),
        |name| matches!(env::var(name), Ok(value) if !value.trim().is_empty()),
    );
    let ready = report.missing_environment.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(CliError::gate_failed(format!(
            "release evidence capture environment is incomplete: {}",
            report.missing_environment.join("; ")
        )))
    }
}

fn run_evidence_status(evidence_dir: PathBuf, max_age_days: i64) -> Result<(), CliError> {
    let report =
        release_evidence_status_report(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)
            .map_err(release_evidence_cli_error)?;
    let ready = report.failures.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(CliError::gate_failed(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

fn run_evidence_check(evidence_dir: PathBuf, max_age_days: i64) -> Result<(), CliError> {
    let report = check_release_evidence(&evidence_dir, OffsetDateTime::now_utc(), max_age_days)
        .map_err(release_evidence_cli_error)?;
    let ready = report.failures.is_empty();
    print_report(&report)?;

    if ready {
        Ok(())
    } else {
        Err(CliError::gate_failed(format!(
            "release evidence is incomplete: {}",
            report.failures.join("; ")
        )))
    }
}

fn print_report<T: serde::Serialize>(report: &T) -> Result<(), CliError> {
    println!(
        "{}",
        serde_json::to_string_pretty(report).map_err(CliError::internal)?
    );
    Ok(())
}

fn release_evidence_cli_error(error: ReleaseEvidenceError) -> CliError {
    match error {
        ReleaseEvidenceError::InvalidMaxAge => CliError::operator_input(
            "release evidence max age must be between 1 and 365 days".to_owned(),
        ),
        ReleaseEvidenceError::NotDirectory(_) => {
            CliError::operator_input("release evidence path is not a directory".to_owned())
        }
        ReleaseEvidenceError::ExistingScaffoldFile(_) => CliError::operator_input(
            "release evidence scaffold file already exists; pass --force to replace it".to_owned(),
        ),
        error => CliError::internal(error),
    }
}

#[derive(Debug)]
struct CliError {
    exit_code: u8,
    message: String,
    source: Option<Box<dyn Error>>,
}

impl CliError {
    fn gate_failed(message: String) -> Self {
        Self::new(EXIT_GATE_FAILED, message)
    }

    fn operator_input(message: String) -> Self {
        Self::new(EXIT_OPERATOR_INPUT, message)
    }

    fn internal(error: impl Error + 'static) -> Self {
        Self {
            exit_code: EXIT_INTERNAL_ERROR,
            message: "unexpected internal error".to_owned(),
            source: Some(Box::new(error)),
        }
    }

    fn new(exit_code: u8, message: String) -> Self {
        Self {
            exit_code,
            message,
            source: None,
        }
    }

    fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for CliError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_deref()
    }
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
            evidence_dir_option,
            max_age_days,
        } = command
        else {
            panic!("expected evidence check command");
        };

        assert_eq!(evidence_dir, Some(PathBuf::from("release-evidence")));
        assert_eq!(evidence_dir_option, None);
        assert_eq!(max_age_days, 45);
    }

    #[test]
    fn parses_evidence_status_with_evidence_dir_option() {
        let cli = Cli::parse_from([
            "cairnid",
            "evidence",
            "status",
            "--evidence-dir",
            "release-evidence",
        ]);

        let Commands::Evidence { command } = cli.command;
        let EvidenceCommand::Status {
            evidence_dir,
            evidence_dir_option,
            max_age_days,
        } = command
        else {
            panic!("expected evidence status command");
        };

        assert_eq!(evidence_dir, None);
        assert_eq!(evidence_dir_option, Some(PathBuf::from("release-evidence")));
        assert_eq!(max_age_days, 30);
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

    #[test]
    fn rejects_max_age_days_outside_cli_range() {
        assert!(
            Cli::try_parse_from([
                "cairnid",
                "evidence",
                "check",
                "release-evidence",
                "--max-age-days",
                "0",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "cairnid",
                "evidence",
                "check",
                "release-evidence",
                "--max-age-days",
                "366",
            ])
            .is_err()
        );
    }
}
