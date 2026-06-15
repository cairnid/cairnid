use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub(in crate::http) fn scim_timestamp(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| timestamp.unix_timestamp().to_string())
}
