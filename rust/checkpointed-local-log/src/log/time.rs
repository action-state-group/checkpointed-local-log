//! Portable millisecond UTC time (docs/backend-contract.md, "Portable
//! encodings" and "Limits").
//!
//! The contract stores every time as ECMAScript `Date.prototype.toISOString()`
//! text and bounds it to the ECMAScript `Date` range. [`Timestamp`] holds any
//! signed millisecond count, so a caller can pass an out-of-range time and the
//! backend reports it as `invalid`; only the portable range formats.

use super::{Error, ErrorCode, MAX_PORTABLE_UNIX_MILLIS, MIN_PORTABLE_UNIX_MILLIS};
use std::fmt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MILLIS_PER_DAY: i64 = 86_400_000;

/// Milliseconds since the Unix epoch, UTC, with no leap seconds: the
/// ECMAScript `Date` time value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(i64);

impl Timestamp {
    /// The earliest portable time, `-271821-04-20T00:00:00.000Z`.
    pub const MIN: Timestamp = Timestamp(MIN_PORTABLE_UNIX_MILLIS);
    /// The latest portable time, `+275760-09-13T00:00:00.000Z`.
    pub const MAX: Timestamp = Timestamp(MAX_PORTABLE_UNIX_MILLIS);

    /// A time `millis` milliseconds after the Unix epoch. Any value is
    /// representable; [`Timestamp::is_portable`] says whether the contract
    /// accepts it.
    pub const fn from_unix_millis(millis: i64) -> Self {
        Self(millis)
    }

    /// Milliseconds since the Unix epoch.
    pub const fn unix_millis(self) -> i64 {
        self.0
    }

    /// Whether the time is inside the ECMAScript `Date` range.
    pub const fn is_portable(self) -> bool {
        self.0 >= MIN_PORTABLE_UNIX_MILLIS && self.0 <= MAX_PORTABLE_UNIX_MILLIS
    }

    /// Truncates `time` to whole milliseconds (toward the past), saturating at
    /// the `i64` range.
    pub fn from_system_time(time: SystemTime) -> Self {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Self(i64::try_from(after.as_millis()).unwrap_or(i64::MAX)),
            Err(before) => {
                let before = before.duration();
                let whole = i64::try_from(before.as_millis()).unwrap_or(i64::MAX);
                let partial = before > Duration::from_millis(whole.unsigned_abs());
                Self(whole.saturating_neg().saturating_sub(i64::from(partial)))
            }
        }
    }

    /// The current time, truncated to milliseconds.
    pub fn now() -> Self {
        Self::from_system_time(SystemTime::now())
    }

    /// The `Date.prototype.toISOString()` form, for example
    /// `2026-09-01T12:00:00.000Z`; years outside 0000..9999 use the signed
    /// six-digit form. A time outside the portable range is `invalid`.
    pub fn to_iso_string(self) -> Result<String, Error> {
        if !self.is_portable() {
            return Err(Error::new(
                ErrorCode::Invalid,
                "time is outside the portable range",
            ));
        }
        Ok(format_unchecked(self.0))
    }

    /// Parses exactly the `Date.prototype.toISOString()` form. Any other
    /// spelling, including a non-canonical year, is `invalid`. A well-formed
    /// six-digit year outside the portable range parses, so the backend can
    /// reject it as a caller value.
    pub fn parse(text: &str) -> Result<Self, Error> {
        parse(text).ok_or_else(|| {
            Error::new(
                ErrorCode::Invalid,
                format!("{text:?} is not a Date.toISOString() time"),
            )
        })
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.to_iso_string() {
            Ok(text) => f.write_str(&text),
            Err(_) => write!(f, "{}ms", self.0),
        }
    }
}

impl FromStr for Timestamp {
    type Err = Error;

    fn from_str(text: &str) -> Result<Self, Error> {
        Self::parse(text)
    }
}

impl From<SystemTime> for Timestamp {
    fn from(time: SystemTime) -> Self {
        Self::from_system_time(time)
    }
}

/// Days since 1970-01-01 of a proleptic Gregorian date (H. Hinnant's
/// `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month_index = (month + 9) % 12;
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// The proleptic Gregorian date of a day count (H. Hinnant's
/// `civil_from_days`).
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let days = days + 719_468;
    let era = days.div_euclid(146_097);
    let day_of_era = days - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn format_unchecked(millis: i64) -> String {
    let days = millis.div_euclid(MILLIS_PER_DAY);
    let of_day = millis.rem_euclid(MILLIS_PER_DAY);
    let (year, month, day) = civil_from_days(days);
    let year = if (0..=9999).contains(&year) {
        format!("{year:04}")
    } else if year < 0 {
        format!("-{:06}", -year)
    } else {
        format!("+{year:06}")
    };
    format!(
        "{year}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        of_day / 3_600_000,
        of_day / 60_000 % 60,
        of_day / 1000 % 60,
        of_day % 1000
    )
}

fn parse(text: &str) -> Option<Timestamp> {
    let bytes = text.as_bytes();
    let (sign, year_digits) = match bytes.first()? {
        b'+' => (1, 6),
        b'-' => (-1, 6),
        _ => (1, 4),
    };
    let year_start = usize::from(year_digits == 6);
    let rest = year_start + year_digits;
    if bytes.len() != rest + 20 {
        return None;
    }
    let number = |start: usize, len: usize| -> Option<i64> {
        let digits = bytes.get(start..start + len)?;
        digits.iter().try_fold(0i64, |acc, &b| {
            b.is_ascii_digit().then(|| acc * 10 + i64::from(b - b'0'))
        })
    };
    for (offset, separator) in [
        (0, b'-'),
        (3, b'-'),
        (6, b'T'),
        (9, b':'),
        (12, b':'),
        (15, b'.'),
        (19, b'Z'),
    ] {
        if bytes[rest + offset] != separator {
            return None;
        }
    }
    let year = sign * number(year_start, year_digits)?;
    let month = number(rest + 1, 2)?;
    let day = number(rest + 4, 2)?;
    let hour = number(rest + 7, 2)?;
    let minute = number(rest + 10, 2)?;
    let second = number(rest + 13, 2)?;
    let milli = number(rest + 16, 3)?;
    if !(1..=12).contains(&month) || day < 1 || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let days = days_from_civil(year, month, day);
    if civil_from_days(days) != (year, month, day) {
        return None;
    }
    let millis = days * MILLIS_PER_DAY + ((hour * 60 + minute) * 60 + second) * 1000 + milli;
    // Round-tripping rejects non-canonical years such as `+002026` or `-000000`.
    (format_unchecked(millis) == text).then_some(Timestamp(millis))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_like_date_to_iso_string() {
        for (millis, text) in [
            (0, "1970-01-01T00:00:00.000Z"),
            (-1, "1969-12-31T23:59:59.999Z"),
            (1_788_264_000_000, "2026-09-01T12:00:00.000Z"),
            (-62_135_596_800_000, "0001-01-01T00:00:00.000Z"),
            (-62_167_219_200_000, "0000-01-01T00:00:00.000Z"),
            (-62_198_755_200_000, "-000001-01-01T00:00:00.000Z"),
            (253_402_300_799_999, "9999-12-31T23:59:59.999Z"),
            (253_402_300_800_000, "+010000-01-01T00:00:00.000Z"),
            (MIN_PORTABLE_UNIX_MILLIS, "-271821-04-20T00:00:00.000Z"),
            (MAX_PORTABLE_UNIX_MILLIS, "+275760-09-13T00:00:00.000Z"),
            (951_782_400_000, "2000-02-29T00:00:00.000Z"),
        ] {
            let time = Timestamp::from_unix_millis(millis);
            assert_eq!(time.to_iso_string().unwrap(), text);
            assert_eq!(Timestamp::parse(text).unwrap(), time, "{text}");
        }
    }

    #[test]
    fn rejects_out_of_range_formatting_but_parses_six_digit_years() {
        let late = Timestamp::from_unix_millis(MAX_PORTABLE_UNIX_MILLIS + 1);
        assert!(!late.is_portable());
        assert_eq!(late.to_iso_string().unwrap_err().code(), ErrorCode::Invalid);
        assert_eq!(
            Timestamp::parse("+275760-09-13T00:00:00.001Z").unwrap(),
            late
        );
        let early = Timestamp::parse("-271821-04-19T23:59:59.999Z").unwrap();
        assert_eq!(early.unix_millis(), MIN_PORTABLE_UNIX_MILLIS - 1);
        assert_eq!(late.to_string(), "8640000000000001ms");
    }

    #[test]
    fn parse_accepts_only_the_canonical_form() {
        for text in [
            "",
            "2026-09-01T12:00:00Z",
            "2026-09-01T12:00:00.000",
            "2026-09-01T12:00:00.000+00:00",
            "2026-9-01T12:00:00.000Z",
            "+002026-09-01T12:00:00.000Z",
            "-000000-01-01T00:00:00.000Z",
            "10000-01-01T00:00:00.000Z",
            "2026-02-30T00:00:00.000Z",
            "2026-13-01T00:00:00.000Z",
            "2026-00-01T00:00:00.000Z",
            "2026-09-01T24:00:00.000Z",
            "2026-09-01T12:60:00.000Z",
            "2026-09-01T12:00:60.000Z",
            "2026-09-01 12:00:00.000Z",
            "2026-09-01T12:00:00.0a0Z",
            "２026-09-01T12:00:00.000Z",
        ] {
            assert!(Timestamp::parse(text).is_err(), "{text:?}");
        }
    }

    #[test]
    fn system_time_truncates_toward_the_past() {
        let after = UNIX_EPOCH + Duration::from_micros(1_500);
        assert_eq!(Timestamp::from(after).unix_millis(), 1);
        let before = UNIX_EPOCH - Duration::from_micros(1_500);
        assert_eq!(Timestamp::from(before).unix_millis(), -2);
        let exact = UNIX_EPOCH - Duration::from_millis(3);
        assert_eq!(Timestamp::from(exact).unix_millis(), -3);
        assert!(Timestamp::now().is_portable());
    }

    #[test]
    fn day_arithmetic_round_trips_across_the_portable_range() {
        let first = MIN_PORTABLE_UNIX_MILLIS / MILLIS_PER_DAY;
        let last = MAX_PORTABLE_UNIX_MILLIS / MILLIS_PER_DAY;
        let mut day = first;
        while day <= last {
            let (year, month, date) = civil_from_days(day);
            assert_eq!(days_from_civil(year, month, date), day);
            day += 997;
        }
    }
}
