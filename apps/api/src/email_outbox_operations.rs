mod command;
mod errors;
mod lifecycle_smoke;
mod provider;
mod report;
mod types;

pub(crate) use self::command::run_email_outbox_command;

#[cfg(test)]
mod tests;
