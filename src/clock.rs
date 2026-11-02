// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT

use time::OffsetDateTime;

use crate::error::{err, SamlError};
use crate::replay::now_ms;

pub(crate) fn iso_ms(ms: i64) -> String {
    let Ok(dt) = OffsetDateTime::from_unix_timestamp_nanos((ms as i128) * 1_000_000) else {
        return "1970-01-01T00:00:00.000Z".to_string();
    };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        dt.year(),
        u8::from(dt.month()),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.millisecond()
    )
}

pub(crate) fn iso_now() -> String {
    iso_ms(now_ms())
}

pub(crate) fn parse_instant(value: &str, what: &str) -> Result<Option<i64>, SamlError> {
    if value.is_empty() {
        return Ok(None);
    }
    let bytes = value.as_bytes();
    if bytes.len() < 20 || &bytes[10..11] != b"T" || !value.ends_with('Z') {
        return Err(err("validation", format!("{what} is not a UTC dateTime: {value}")));
    }
    let date_ok = bytes.len() >= 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[13] == b':'
        && bytes[16] == b':';
    let frac = if bytes.len() > 20 {
        if bytes[19] != b'.' || !bytes[20..bytes.len() - 1].iter().all(|c| c.is_ascii_digit()) || bytes.len() == 21 {
            return Err(err("validation", format!("{what} is not a UTC dateTime: {value}")));
        }
        true
    } else {
        false
    };
    if !date_ok || !bytes[..4].iter().chain(bytes[5..7].iter()).chain(bytes[8..10].iter())
        .chain(bytes[11..13].iter()).chain(bytes[14..16].iter()).chain(bytes[17..19].iter())
        .all(|c| c.is_ascii_digit())
    {
        return Err(err("validation", format!("{what} is not a UTC dateTime: {value}")));
    }
    let year: i32 = value[0..4].parse().unwrap_or(0);
    let month: u8 = value[5..7].parse().unwrap_or(0);
    let day: u8 = value[8..10].parse().unwrap_or(0);
    let hour: u8 = value[11..13].parse().unwrap_or(0);
    let minute: u8 = value[14..16].parse().unwrap_or(0);
    let second: u8 = value[17..19].parse().unwrap_or(0);
    let mut milli = 0i64;
    if frac {
        let digits = &value[20..value.len() - 1];
        let mut padded = digits.to_string();
        while padded.len() < 3 {
            padded.push('0');
        }
        milli = padded[..3].parse().unwrap_or(0);
    }
    let Some(month) = time::Month::try_from(month).ok() else {
        return Err(err("validation", format!("{what} is not a dateTime: {value}")));
    };
    let Ok(date) = time::Date::from_calendar_date(year, month, day) else {
        return Err(err("validation", format!("{what} is not a dateTime: {value}")));
    };
    let Ok(time_of) = time::Time::from_hms_milli(hour, minute, second, milli as u16) else {
        return Err(err("validation", format!("{what} is not a dateTime: {value}")));
    };
    let dt = date.with_time(time_of).assume_utc();
    Ok(Some(dt.unix_timestamp() * 1000 + i64::from(dt.millisecond())))
}

pub(crate) fn format_valid_to(dt: OffsetDateTime) -> String {
    const MONTHS: [&str; 12] = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let stamp = format!(
        "{} {:02} {:02}:{:02}:{:02} {} GMT",
        MONTHS[usize::from(u8::from(dt.month()) - 1)],
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
        dt.year()
    );
    stamp.replace(" 0", "  ")
}
