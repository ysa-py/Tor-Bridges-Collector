//! Reproducible ZIP archive construction.

use std::collections::BTreeMap;
use std::io::Write;

use chrono::{DateTime, Datelike, Timelike, Utc};

use crate::error::PublishError;

/// The earliest year representable in a ZIP "DOS" timestamp.
const ZIP_MIN_YEAR: i32 = 1980;
/// The latest year representable in a ZIP "DOS" timestamp.
const ZIP_MAX_YEAR: i32 = 2107;

/// Build a reproducible ZIP archive from `files`.
///
/// Entries are written in `files` iteration order (a `BTreeMap` iterates in
/// ascending key order), every entry uses the same fixed timestamp, and the
/// compression method is DEFLATE. Given identical inputs and timestamp the
/// output bytes are byte-identical across runs and machines.
///
/// A `timestamp` of `None` selects the fixed reproducible epoch
/// (`1980-01-01 00:00:00`), which makes archives independent of wall-clock
/// time.
pub fn deterministic_zip(
    files: &BTreeMap<String, Vec<u8>>,
    timestamp: Option<DateTime<Utc>>,
) -> Result<Vec<u8>, PublishError> {
    let zip_timestamp = to_zip_timestamp(timestamp)?;

    let cursor = std::io::Cursor::new(Vec::new());
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::FileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o644)
        .last_modified_time(zip_timestamp);

    for (path, bytes) in files {
        writer.start_file(path.clone(), options)?;
        writer
            .write_all(bytes)
            .map_err(|source| PublishError::io("write_zip_entry", source))?;
    }

    let cursor = writer.finish()?;
    Ok(cursor.into_inner())
}

/// Convert an optional wall-clock timestamp into a ZIP DOS timestamp, clamping
/// the year to the representable range.
fn to_zip_timestamp(timestamp: Option<DateTime<Utc>>) -> Result<zip::DateTime, PublishError> {
    match timestamp {
        Some(dt) => {
            let year = dt.year().clamp(ZIP_MIN_YEAR, ZIP_MAX_YEAR);
            zip::DateTime::from_date_and_time(
                year as u16,
                dt.month() as u8,
                dt.day() as u8,
                dt.hour() as u8,
                dt.minute() as u8,
                dt.second() as u8,
            )
            .map_err(|()| PublishError::InvalidZipTimestamp {
                reason: "timestamp is outside the ZIP DOS range",
            })
        }
        None => zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 0).map_err(|()| {
            PublishError::InvalidZipTimestamp {
                reason: "fixed epoch is outside the ZIP DOS range",
            }
        }),
    }
}
