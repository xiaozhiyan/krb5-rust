use chrono::{DateTime, Utc};

pub fn timestamp_to_sfstring(timestamp: DateTime<Utc>) -> String {
    // TODO: check whether to implement the format table
    timestamp.format("%x %X").to_string()
}
