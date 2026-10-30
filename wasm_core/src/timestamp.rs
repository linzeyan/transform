//! The Timestamp tool: read one instant typed in any common form, then write it in
//! every form the tool lists.
//!
//! Zones by name (Asia/Taipei) stay with the page, which has the browser's tz
//! database through `Intl`. Input that names no offset therefore comes back as a
//! wall-clock time, and the page places it in the zone the user picked; output takes
//! the offset the page worked out for that instant.

use std::sync::OnceLock;

use chrono::format::{Item, StrftimeItems};
use chrono::{
    DateTime, Datelike, Duration, FixedOffset, NaiveDate, NaiveDateTime, NaiveTime, SecondsFormat,
    TimeZone, Utc,
};
use regex::Regex;
use serde::Serialize;
use wasm_bindgen::prelude::*;

/// What an input was read as.
#[derive(Debug, PartialEq, Serialize)]
pub struct Reading {
    /// The format it matched, shown beside the input so a wrong guess is visible.
    pub label: String,
    /// False when the input named no offset: `seconds` is then the wall-clock time
    /// counted as if it were UTC, for the page to place in its chosen zone.
    pub zoned: bool,
    /// i64 as text: a JS number loses precision past 2^53.
    pub seconds: String,
    pub nanos: u32,
    /// Counted from the current time ("now - 3d"), so the page keeps it ticking.
    pub relative: bool,
}

#[derive(Debug, PartialEq)]
enum When {
    At(DateTime<Utc>),
    Wall(NaiveDateTime),
}

struct Parsed {
    when: When,
    label: String,
    relative: bool,
}

impl Parsed {
    fn at(when: DateTime<Utc>, label: &str) -> Self {
        Parsed {
            when: When::At(when),
            label: label.into(),
            relative: false,
        }
    }

    fn wall(when: NaiveDateTime, label: &str) -> Self {
        Parsed {
            when: When::Wall(when),
            label: label.into(),
            relative: false,
        }
    }
}

type Reader = fn(&str, DateTime<Utc>) -> Option<Parsed>;

/// Every format the menu offers. Auto reads a number as Unix time in the unit its
/// digit count implies, then tries the rest in this order (the shapes barely overlap).
const FORMATS: &[(&str, &str, &str, Reader)] = &[
    ("now", "Relative", "Now ± an amount (now - 3d)", read_now),
    ("unix_s", "Unix", "Unix seconds", |s, _| {
        read_unix(s, Some(Unit::Seconds))
    }),
    ("unix_ms", "Unix", "Unix milliseconds", |s, _| {
        read_unix(s, Some(Unit::Millis))
    }),
    ("unix_us", "Unix", "Unix microseconds", |s, _| {
        read_unix(s, Some(Unit::Micros))
    }),
    ("unix_ns", "Unix", "Unix nanoseconds", |s, _| {
        read_unix(s, Some(Unit::Nanos))
    }),
    ("iso8601", "Text", "ISO 8601 / RFC 3339", read_iso8601),
    ("rfc2822", "Text", "RFC 2822 / HTTP date", read_rfc2822),
    ("sql", "Text", "SQL datetime", read_sql),
    ("clf", "Text", "Access log (CLF)", read_clf),
    ("syslog", "Text", "syslog", read_syslog),
    ("go", "Text", "Go time.String()", read_go),
    ("js", "Text", "JS Date.toString()", read_js),
    ("unix_date", "Text", "Unix date / asctime", read_unix_date),
    ("cjk", "Text", "2026年1月2日", read_cjk),
    ("ymd", "Text", "2026/01/02", read_slashed),
    ("uuid", "ID", "UUID v1, v6, v7", read_uuid),
    ("ulid", "ID", "ULID", read_ulid),
    ("objectid", "ID", "MongoDB ObjectId", read_object_id),
];

#[derive(Serialize)]
struct FormatOption {
    id: &'static str,
    group: &'static str,
    label: &'static str,
}

/// The input format menu: Auto, every format above, then Custom.
#[wasm_bindgen]
pub fn timestamp_formats() -> Result<JsValue, JsValue> {
    let list: Vec<FormatOption> = FORMATS
        .iter()
        .map(|&(id, group, label, _)| FormatOption { id, group, label })
        .collect();
    serde_wasm_bindgen::to_value(&list).map_err(|err| JsValue::from_str(&err.to_string()))
}

/// Reads `input` as `format` (an id from `timestamp_formats`, "auto", or "custom"
/// with a strftime `pattern`).
#[wasm_bindgen]
pub fn read_timestamp(input: &str, format: &str, pattern: &str) -> Result<JsValue, JsValue> {
    read_timestamp_at(input, format, pattern, Utc::now())
        .and_then(|reading| serde_wasm_bindgen::to_value(&reading).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

pub fn read_timestamp_at(
    input: &str,
    format: &str,
    pattern: &str,
    now: DateTime<Utc>,
) -> Result<Reading, String> {
    let text = input.trim();
    if text.is_empty() {
        return Err("Type or paste a time".into());
    }
    let parsed = match format {
        // The fixed-unit Unix entries would take any number as their unit.
        "auto" => read_unix(text, None)
            .or_else(|| {
                FORMATS
                    .iter()
                    .filter(|(_, group, ..)| *group != "Unix")
                    .find_map(|(_, _, _, read)| read(text, now))
            })
            .ok_or_else(|| {
                "Not a format Auto knows: pick one from the menu, or write a pattern with Custom…"
                    .to_string()
            })?,
        "custom" => read_custom(text, pattern)?,
        id => {
            let (_, _, label, read) = FORMATS
                .iter()
                .find(|(known, ..)| *known == id)
                .ok_or_else(|| format!("unknown format {id}"))?;
            read(text, now).ok_or_else(|| format!("Not {label}"))?
        }
    };
    let (instant, zoned) = match parsed.when {
        When::At(at) => (at, true),
        When::Wall(wall) => (wall.and_utc(), false),
    };
    Ok(Reading {
        label: parsed.label,
        zoned,
        seconds: instant.timestamp().to_string(),
        nanos: instant.timestamp_subsec_nanos(),
        relative: parsed.relative,
    })
}

fn regex(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid pattern"))
}

fn read_now(text: &str, now: DateTime<Utc>) -> Option<Parsed> {
    static NOW: OnceLock<Regex> = OnceLock::new();
    // U+2212 too: it is what the tool's own hint shows.
    let caps = regex(
        &NOW,
        r"(?i)^now(?:\s*([+\-−])\s*(\d+)\s*(s|secs?|seconds?|m|mins?|minutes?|h|hrs?|hours?|d|days?|w|weeks?)?)?$",
    )
    .captures(text)?;
    let mut parsed = Parsed::at(now, "Now");
    parsed.relative = true;
    let (Some(sign), Some(amount)) = (caps.get(1), caps.get(2)) else {
        return Some(parsed);
    };
    let amount: i64 = amount.as_str().parse().ok()?;
    let unit = caps.get(3).map_or("s", |m| m.as_str()).to_ascii_lowercase();
    let (step, name) = match unit.chars().next()? {
        'm' => (Duration::try_minutes(amount)?, "minute"),
        'h' => (Duration::try_hours(amount)?, "hour"),
        'd' => (Duration::try_days(amount)?, "day"),
        'w' => (Duration::try_weeks(amount)?, "week"),
        _ => (Duration::try_seconds(amount)?, "second"),
    };
    let later = sign.as_str() == "+";
    let at = if later {
        now.checked_add_signed(step)?
    } else {
        now.checked_sub_signed(step)?
    };
    let plural = if amount == 1 { "" } else { "s" };
    parsed.when = When::At(at);
    parsed.label = format!(
        "Now {} {amount} {name}{plural}",
        if later { "+" } else { "−" }
    );
    Some(parsed)
}

#[derive(Clone, Copy)]
enum Unit {
    Seconds,
    Millis,
    Micros,
    Nanos,
}

impl Unit {
    fn nanos(self) -> i128 {
        match self {
            Unit::Seconds => 1_000_000_000,
            Unit::Millis => 1_000_000,
            Unit::Micros => 1_000,
            Unit::Nanos => 1,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Unit::Seconds => "Unix seconds",
            Unit::Millis => "Unix milliseconds",
            Unit::Micros => "Unix microseconds",
            Unit::Nanos => "Unix nanoseconds",
        }
    }
}

/// Digits are seconds, milliseconds, micro- or nanoseconds by how many there are:
/// up to 11 digits reaches the year 5138 in seconds, 13 is today in milliseconds.
/// A fraction is a fraction of that unit.
fn read_unix(text: &str, unit: Option<Unit>) -> Option<Parsed> {
    static NUMBER: OnceLock<Regex> = OnceLock::new();
    let caps = regex(&NUMBER, r"^([+-]?)(\d+)(?:\.(\d+))?$").captures(text)?;
    let digits = caps.get(2)?.as_str();
    let unit = unit.unwrap_or(match digits.len() {
        0..=11 => Unit::Seconds,
        12..=14 => Unit::Millis,
        15..=17 => Unit::Micros,
        _ => Unit::Nanos,
    });
    let whole: i128 = digits.parse().ok()?;
    let mut total = whole.checked_mul(unit.nanos())?;
    if let Some(fraction) = caps.get(3) {
        // Nanoseconds have no finer part; anything else keeps up to nanosecond precision.
        let places = unit.nanos().ilog10() as usize;
        if places == 0 {
            return None;
        }
        let kept: String = fraction
            .as_str()
            .chars()
            .chain(std::iter::repeat('0'))
            .take(places)
            .collect();
        total += kept.parse::<i128>().ok()?;
    }
    if caps.get(1)?.as_str() == "-" {
        total = -total;
    }
    let seconds = i64::try_from(total.div_euclid(1_000_000_000)).ok()?;
    let nanos = u32::try_from(total.rem_euclid(1_000_000_000)).ok()?;
    Some(Parsed::at(
        Utc.timestamp_opt(seconds, nanos).single()?,
        unit.label(),
    ))
}

fn zoned(text: &str, pattern: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_str(text, pattern)
        .ok()
        .map(|at| at.with_timezone(&Utc))
}

fn wall(text: &str, pattern: &str) -> Option<NaiveDateTime> {
    NaiveDateTime::parse_from_str(text, pattern).ok()
}

fn wall_date(text: &str, pattern: &str) -> Option<NaiveDateTime> {
    NaiveDate::parse_from_str(text, pattern)
        .ok()
        .map(|day| day.and_time(NaiveTime::MIN))
}

/// The variants people actually paste: T or a space, minutes without seconds, any
/// fraction, Z / ±hh / ±hhmm / ±hh:mm, lower case t and z, the basic form without
/// separators, and a date alone.
fn read_iso8601(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    if !text.starts_with(|c: char| c.is_ascii_digit()) {
        return None;
    }
    let text = text.to_ascii_uppercase();
    const ZONED: &[&str] = &[
        "%Y-%m-%dT%H:%M:%S%.f%#z",
        "%Y-%m-%dT%H:%M%#z",
        "%Y%m%dT%H%M%S%.f%#z",
    ];
    if let Some(at) = ZONED.iter().find_map(|p| zoned(&text, p)) {
        return Some(Parsed::at(at, "ISO 8601"));
    }
    const WALL: &[&str] = &["%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M", "%Y%m%dT%H%M%S%.f"];
    if let Some(at) = WALL.iter().find_map(|p| wall(&text, p)) {
        return Some(Parsed::wall(at, "ISO 8601 without offset"));
    }
    wall_date(&text, "%Y-%m-%d").map(|at| Parsed::wall(at, "Date"))
}

/// RFC 2822 and the three date forms HTTP allows (RFC 9110 §5.6.7). HTTP's are
/// GMT by definition.
fn read_rfc2822(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    if let Ok(at) = DateTime::parse_from_rfc2822(text) {
        let label = if text.ends_with("GMT") {
            "HTTP date"
        } else {
            "RFC 2822"
        };
        return Some(Parsed::at(at.with_timezone(&Utc), label));
    }
    wall(text, "%A, %d-%b-%y %H:%M:%S GMT")
        .map(|at| Parsed::at(at.and_utc(), "HTTP date (RFC 850)"))
}

fn read_sql(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    if let Some(at) = zoned(text, "%Y-%m-%d %H:%M:%S%.f %#z") {
        return Some(Parsed::at(at, "SQL datetime with offset"));
    }
    ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M"]
        .iter()
        .find_map(|p| wall(text, p))
        .map(|at| Parsed::wall(at, "SQL datetime"))
}

/// Apache and nginx: `[02/Jan/2026:11:04:05 +0800]`, brackets optional.
fn read_clf(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    let text = text
        .strip_prefix('[')
        .and_then(|t| t.strip_suffix(']'))
        .unwrap_or(text);
    zoned(text, "%d/%b/%Y:%H:%M:%S %z").map(|at| Parsed::at(at, "Access log (CLF)"))
}

/// RFC 3164's `Jan  2 11:04:05` has no year: the most recent one that does not put
/// the line in the future, since logs are read after they are written.
fn read_syslog(text: &str, now: DateTime<Utc>) -> Option<Parsed> {
    let year = now.year();
    let at = wall(&format!("{year} {text}"), "%Y %b %e %H:%M:%S%.f")?;
    let at = if at.and_utc() > now + Duration::days(1) {
        wall(&format!("{} {text}", year - 1), "%Y %b %e %H:%M:%S%.f")?
    } else {
        at
    };
    Some(Parsed::wall(at, "syslog"))
}

/// `2026-01-02 11:04:05.123 +0800 CST m=+0.0001`: the zone name and the monotonic
/// reading are left out, the offset says it all.
fn read_go(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    let text = text.split(" m=").next()?;
    zoned(text, "%Y-%m-%d %H:%M:%S%.f %z %Z").map(|at| Parsed::at(at, "Go time.String()"))
}

/// `Fri Jan 02 2026 11:04:05 GMT+0800 (Taiwan Standard Time)`; the name in brackets
/// is the browser's language, so it is dropped.
fn read_js(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    let text = text.split(" (").next()?;
    zoned(text, "%a %b %d %Y %H:%M:%S GMT%z").map(|at| Parsed::at(at, "JS Date.toString()"))
}

/// `date` and `asctime`. A zone abbreviation means different places (CST is China
/// and Chicago), so only UTC and GMT are taken at their word; anything else is read
/// in the zone the user picked.
fn read_unix_date(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    if let Some(at) = wall(text, "%a %b %e %H:%M:%S %Y") {
        return Some(Parsed::wall(at, "asctime"));
    }
    let at = wall(text, "%a %b %e %H:%M:%S %Z %Y")?;
    let name = text.split_whitespace().nth(4)?;
    Some(if matches!(name, "UTC" | "GMT" | "Z") {
        Parsed::at(at.and_utc(), "Unix date")
    } else {
        Parsed::wall(at, "Unix date (zone name ignored)")
    })
}

fn read_cjk(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    const WALL: &[&str] = &[
        "%Y年%m月%d日 %H:%M:%S",
        "%Y年%m月%d日 %H:%M",
        "%Y年%m月%d日 %H時%M分%S秒",
        "%Y年%m月%d日 %H时%M分%S秒",
        "%Y年%m月%d日 %H時%M分",
        "%Y年%m月%d日 %H时%M分",
    ];
    WALL.iter()
        .find_map(|p| wall(text, p))
        .or_else(|| wall_date(text, "%Y年%m月%d日"))
        .map(|at| Parsed::wall(at, "Chinese date"))
}

fn read_slashed(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    ["%Y/%m/%d %H:%M:%S%.f", "%Y/%m/%d %H:%M"]
        .iter()
        .find_map(|p| wall(text, p))
        .or_else(|| wall_date(text, "%Y/%m/%d"))
        .map(|at| Parsed::wall(at, "Year/month/day"))
}

fn read_uuid(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    let id = ::uuid::Uuid::parse_str(text).ok()?;
    let (seconds, nanos) = id.get_timestamp()?.to_unix();
    let at = Utc
        .timestamp_opt(i64::try_from(seconds).ok()?, nanos)
        .single()?;
    Some(Parsed::at(at, &format!("UUIDv{}", id.get_version_num())))
}

/// The first 10 of 26 Crockford base32 characters are milliseconds since 1970.
fn read_ulid(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    static ULID: OnceLock<Regex> = OnceLock::new();
    if !regex(&ULID, r"^[0-7][0-9A-HJKMNP-TV-Za-hjkmnp-tv-z]{25}$").is_match(text) {
        return None;
    }
    const ALPHABET: &str = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let millis = text[..10].chars().try_fold(0i64, |acc, c| {
        Some(acc * 32 + ALPHABET.find(c.to_ascii_uppercase())? as i64)
    })?;
    Some(Parsed::at(
        Utc.timestamp_millis_opt(millis).single()?,
        "ULID",
    ))
}

/// The first 4 of 12 bytes are seconds since 1970.
fn read_object_id(text: &str, _: DateTime<Utc>) -> Option<Parsed> {
    if text.len() != 24 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let seconds = i64::from_str_radix(&text[..8], 16).ok()?;
    Some(Parsed::at(
        Utc.timestamp_opt(seconds, 0).single()?,
        "ObjectId",
    ))
}

fn read_custom(text: &str, pattern: &str) -> Result<Parsed, String> {
    if pattern.trim().is_empty() {
        return Err("Write the pattern the input follows, like %d-%m-%Y %H:%M".into());
    }
    if let Ok(at) = DateTime::parse_from_str(text, pattern) {
        return Ok(Parsed::at(at.with_timezone(&Utc), pattern));
    }
    if let Ok(at) = NaiveDateTime::parse_from_str(text, pattern) {
        return Ok(Parsed::wall(at, pattern));
    }
    NaiveDate::parse_from_str(text, pattern)
        .map(|day| Parsed::wall(day.and_time(NaiveTime::MIN), pattern))
        .map_err(|err| format!("Doesn't match {pattern}: {err}"))
}

#[derive(Debug, Serialize)]
pub struct Unix {
    pub seconds: String,
    pub milliseconds: String,
    pub microseconds: String,
    pub nanoseconds: String,
}

#[derive(Debug, Serialize)]
pub struct Text {
    pub iso8601: String,
    pub rfc3339: String,
    pub rfc2822: String,
    pub iso9075: String,
    pub sql_datetime: String,
    pub sql_date: String,
}

#[derive(Debug, Serialize)]
pub struct Written {
    pub unix: Unix,
    pub utc: Text,
    /// HTTP dates are always GMT, so only UTC has one.
    pub http: String,
    pub local: Text,
    pub day: String,
    /// One per pattern, in order.
    pub custom: Vec<Custom>,
}

/// The text a pattern gave, or why the pattern is wrong.
#[derive(Debug, PartialEq, Serialize)]
pub struct Custom {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Writes the instant `seconds`.`nanos` in every form, local ones at
/// `offset_seconds` east of UTC, and once per strftime pattern in `patterns`.
#[wasm_bindgen]
pub fn format_timestamp(
    seconds: &str,
    nanos: u32,
    offset_seconds: i32,
    patterns: Vec<String>,
) -> Result<JsValue, JsValue> {
    format_timestamp_internal(seconds, nanos, offset_seconds, &patterns)
        .and_then(|written| serde_wasm_bindgen::to_value(&written).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

pub fn format_timestamp_internal(
    seconds: &str,
    nanos: u32,
    offset_seconds: i32,
    patterns: &[String],
) -> Result<Written, String> {
    let seconds: i64 = seconds.trim().parse().map_err(|_| "invalid seconds")?;
    let at = Utc
        .timestamp_opt(seconds, nanos)
        .single()
        .ok_or("time out of range")?;
    let offset = FixedOffset::east_opt(offset_seconds).ok_or("offset out of range")?;
    let local = at.with_timezone(&offset);
    let whole = i128::from(seconds);
    let nanos = i128::from(nanos);
    let iso_week = local.iso_week();
    Ok(Written {
        unix: Unix {
            seconds: seconds.to_string(),
            milliseconds: (whole * 1_000 + nanos / 1_000_000).to_string(),
            microseconds: (whole * 1_000_000 + nanos / 1_000).to_string(),
            nanoseconds: (whole * 1_000_000_000 + nanos).to_string(),
        },
        utc: text(&at.fixed_offset()),
        http: at.format("%a, %d %b %Y %H:%M:%S GMT").to_string(),
        local: text(&local),
        day: format!(
            "{}, day {} of {}, ISO week {}-W{:02}",
            local.format("%A"),
            local.ordinal(),
            local.year(),
            iso_week.year(),
            iso_week.week()
        ),
        custom: patterns
            .iter()
            .map(|pattern| custom(&local, pattern))
            .collect(),
    })
}

fn text(at: &DateTime<FixedOffset>) -> Text {
    let utc = at.offset().local_minus_utc() == 0;
    Text {
        iso8601: if utc {
            at.format("%Y-%m-%dT%H:%M:%SZ").to_string()
        } else {
            at.format("%Y-%m-%dT%H:%M:%S%:z").to_string()
        },
        rfc3339: at.to_rfc3339_opts(SecondsFormat::Nanos, utc),
        rfc2822: at.to_rfc2822(),
        iso9075: at.format("%Y-%m-%d %H:%M:%S%:z").to_string(),
        sql_datetime: at.format("%Y-%m-%d %H:%M:%S").to_string(),
        sql_date: at.format("%Y-%m-%d").to_string(),
    }
}

/// chrono panics when asked to display a pattern it cannot parse, so it is checked
/// item by item first.
fn custom(at: &DateTime<FixedOffset>, pattern: &str) -> Custom {
    let items: Vec<Item> = StrftimeItems::new(pattern).collect();
    if items.iter().any(|item| matches!(item, Item::Error)) {
        return Custom {
            value: None,
            error: Some("not a valid pattern".into()),
        };
    }
    Custom {
        value: Some(at.format_with_items(items.into_iter()).to_string()),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 1, 5, 12, 0, 0).unwrap()
    }

    fn read(input: &str) -> Reading {
        read_timestamp_at(input, "auto", "", now()).unwrap_or_else(|err| panic!("{input}: {err}"))
    }

    /// (label, zoned, seconds, nanos) — the instant counted as UTC for wall times.
    fn shape(input: &str) -> (String, bool, i64, u32) {
        let r = read(input);
        (r.label, r.zoned, r.seconds.parse().unwrap(), r.nanos)
    }

    // 2026-01-02T03:04:05Z
    const T: i64 = 1_767_323_045;
    // 2026-01-02T11:04:05 as a wall time counted as UTC
    const WALL: i64 = T + 8 * 3600;

    #[test]
    fn unix_unit_follows_the_digit_count() {
        assert_eq!(shape("1767323045"), ("Unix seconds".into(), true, T, 0));
        assert_eq!(
            shape("1767323045123"),
            ("Unix milliseconds".into(), true, T, 123_000_000)
        );
        assert_eq!(
            shape("1767323045123456"),
            ("Unix microseconds".into(), true, T, 123_456_000)
        );
        assert_eq!(
            shape("1767323045123456789"),
            ("Unix nanoseconds".into(), true, T, 123_456_789)
        );
        assert_eq!(shape("0"), ("Unix seconds".into(), true, 0, 0));
        // A fraction is a fraction of the unit the digits imply.
        assert_eq!(
            shape("1767323045.5"),
            ("Unix seconds".into(), true, T, 500_000_000)
        );
        assert_eq!(
            shape("1767323045123.25"),
            ("Unix milliseconds".into(), true, T, 123_250_000)
        );
        // Before 1970: the nanos stay positive and the seconds round down.
        assert_eq!(
            shape("-1.5"),
            ("Unix seconds".into(), true, -2, 500_000_000)
        );
    }

    #[test]
    fn a_chosen_unix_unit_overrides_the_digit_count() {
        // Ten digits in milliseconds is 1970-04-26, which Auto would read as seconds.
        let r = read_timestamp_at("1000000000", "unix_ms", "", now()).unwrap();
        assert_eq!(
            (r.label.as_str(), r.seconds.as_str()),
            ("Unix milliseconds", "1000000")
        );
        assert!(
            read_timestamp_at("2026-01-02", "unix_s", "", now())
                .unwrap_err()
                .contains("Unix seconds")
        );
    }

    #[test]
    fn iso_8601_in_the_forms_people_paste() {
        for input in [
            "2026-01-02T03:04:05Z",
            "2026-01-02t03:04:05z",
            "2026-01-02T11:04:05+08:00",
            "2026-01-02T11:04:05+0800",
            "2026-01-02T11:04:05+08",
            "20260102T030405Z",
        ] {
            assert_eq!(shape(input), ("ISO 8601".into(), true, T, 0), "{input}");
        }
        assert_eq!(
            shape("2026-01-02T03:04:05.123456789Z"),
            ("ISO 8601".into(), true, T, 123_456_789)
        );
        assert_eq!(shape("2026-01-02T03:04Z").2, T - 5);
        assert_eq!(
            shape("2026-01-02T11:04:05"),
            ("ISO 8601 without offset".into(), false, WALL, 0)
        );
        assert_eq!(
            shape("2026-01-02"),
            ("Date".into(), false, T - 3 * 3600 - 4 * 60 - 5, 0)
        );
    }

    #[test]
    fn rfc_2822_and_every_http_date_form() {
        assert_eq!(
            shape("Fri, 02 Jan 2026 11:04:05 +0800"),
            ("RFC 2822".into(), true, T, 0)
        );
        assert_eq!(
            shape("Fri, 02 Jan 2026 03:04:05 GMT"),
            ("HTTP date".into(), true, T, 0)
        );
        assert_eq!(
            shape("Friday, 02-Jan-26 03:04:05 GMT"),
            ("HTTP date (RFC 850)".into(), true, T, 0)
        );
        assert_eq!(
            shape("Fri Jan  2 03:04:05 2026"),
            ("asctime".into(), false, T, 0)
        );
    }

    #[test]
    fn log_and_language_formats() {
        assert_eq!(
            shape("02/Jan/2026:11:04:05 +0800"),
            ("Access log (CLF)".into(), true, T, 0)
        );
        assert_eq!(
            shape("[02/Jan/2026:11:04:05 +0800]"),
            ("Access log (CLF)".into(), true, T, 0)
        );
        assert_eq!(
            shape("2026-01-02 11:04:05.5 +0800 CST m=+0.000012"),
            ("Go time.String()".into(), true, T, 500_000_000)
        );
        assert_eq!(
            shape("Fri Jan 02 2026 11:04:05 GMT+0800 (Taiwan Standard Time)"),
            ("JS Date.toString()".into(), true, T, 0)
        );
        assert_eq!(
            shape("Fri Jan  2 03:04:05 UTC 2026"),
            ("Unix date".into(), true, T, 0)
        );
        assert_eq!(
            shape("Fri Jan  2 11:04:05 CST 2026"),
            ("Unix date (zone name ignored)".into(), false, WALL, 0)
        );
        assert_eq!(
            shape("2026-01-02 11:04:05"),
            ("SQL datetime".into(), false, WALL, 0)
        );
        assert_eq!(
            shape("2026-01-02 11:04:05 +08:00"),
            ("SQL datetime with offset".into(), true, T, 0)
        );
        assert_eq!(
            shape("2026-01-02 11:04:05+08:00"),
            ("SQL datetime with offset".into(), true, T, 0)
        );
    }

    #[test]
    fn syslog_takes_the_latest_year_that_is_not_in_the_future() {
        assert_eq!(shape("Jan  2 11:04:05"), ("syslog".into(), false, WALL, 0));
        // Read on 5 January, a December line is from last year.
        let december = read("Dec 31 23:00:00");
        let expected = Utc
            .with_ymd_and_hms(2025, 12, 31, 23, 0, 0)
            .unwrap()
            .timestamp();
        assert_eq!(december.seconds, expected.to_string());
    }

    #[test]
    fn chinese_and_slashed_dates() {
        assert_eq!(
            shape("2026年1月2日 11:04:05"),
            ("Chinese date".into(), false, WALL, 0)
        );
        assert_eq!(
            shape("2026年01月02日 11時04分05秒"),
            ("Chinese date".into(), false, WALL, 0)
        );
        assert_eq!(shape("2026年1月2日").2, WALL - 11 * 3600 - 4 * 60 - 5);
        assert_eq!(
            shape("2026/01/02 11:04:05"),
            ("Year/month/day".into(), false, WALL, 0)
        );
        assert_eq!(shape("2026/1/2 11:04").2, WALL - 5);
    }

    #[test]
    fn ids_that_carry_their_creation_time() {
        // UUIDv7 / ULID with 1767323045123 ms; ObjectId with T seconds.
        assert_eq!(
            shape("019b7ca9-8d03-7000-8000-000000000000"),
            ("UUIDv7".into(), true, T, 123_000_000)
        );
        assert_eq!(
            shape("01KDYAK3830000000000000000"),
            ("ULID".into(), true, T, 123_000_000)
        );
        assert_eq!(
            shape("01kdyak3830000000000000000"),
            ("ULID".into(), true, T, 123_000_000)
        );
        assert_eq!(
            shape("695735a50000000000000000"),
            ("ObjectId".into(), true, T, 0)
        );
        // A UUID without a time says so instead of guessing.
        assert!(
            read_timestamp_at("8c4d4b4e-3d0a-4f7e-9b52-0c1f6f3a2b10", "auto", "", now()).is_err()
        );
    }

    #[test]
    fn now_and_offsets_from_it_tick() {
        let r = read("now");
        assert_eq!((r.label.as_str(), r.relative), ("Now", true));
        assert_eq!(r.seconds, now().timestamp().to_string());
        let r = read("now - 3d");
        assert_eq!(r.label, "Now − 3 days");
        assert_eq!(r.seconds, (now().timestamp() - 3 * 86_400).to_string());
        assert_eq!(
            read("NOW+1h").seconds,
            (now().timestamp() + 3600).to_string()
        );
        assert_eq!(read("now − 90 minutes").label, "Now − 90 minutes");
    }

    #[test]
    fn custom_patterns_with_and_without_an_offset() {
        let r = read_timestamp_at("02-01-2026 11h04", "custom", "%d-%m-%Y %Hh%M", now()).unwrap();
        assert_eq!((r.zoned, r.seconds), (false, (WALL - 5).to_string()));
        let r = read_timestamp_at(
            "02.01.2026 11:04:05 +0800",
            "custom",
            "%d.%m.%Y %H:%M:%S %z",
            now(),
        )
        .unwrap();
        assert_eq!((r.zoned, r.seconds), (true, T.to_string()));
        let r = read_timestamp_at("02.01.2026", "custom", "%d.%m.%Y", now()).unwrap();
        assert!(!r.zoned);
        let err = read_timestamp_at("2026-01-02", "custom", "%d.%m.%Y", now()).unwrap_err();
        assert!(err.starts_with("Doesn't match %d.%m.%Y"), "{err}");
    }

    #[test]
    fn nonsense_is_an_error_not_a_guess() {
        for input in ["", "   ", "hello", "2026-13-45", "12:34"] {
            assert!(
                read_timestamp_at(input, "auto", "", now()).is_err(),
                "{input}"
            );
        }
    }

    #[test]
    fn writes_every_form_in_utc_and_at_the_given_offset() {
        let w = format_timestamp_internal(&T.to_string(), 123_456_789, 8 * 3600, &[]).unwrap();
        assert_eq!(w.unix.seconds, "1767323045");
        assert_eq!(w.unix.milliseconds, "1767323045123");
        assert_eq!(w.unix.microseconds, "1767323045123456");
        assert_eq!(w.unix.nanoseconds, "1767323045123456789");
        assert_eq!(w.utc.iso8601, "2026-01-02T03:04:05Z");
        assert_eq!(w.utc.rfc3339, "2026-01-02T03:04:05.123456789Z");
        assert_eq!(w.utc.rfc2822, "Fri, 2 Jan 2026 03:04:05 +0000");
        assert_eq!(w.utc.iso9075, "2026-01-02 03:04:05+00:00");
        assert_eq!(w.http, "Fri, 02 Jan 2026 03:04:05 GMT");
        assert_eq!(w.local.iso8601, "2026-01-02T11:04:05+08:00");
        assert_eq!(w.local.rfc3339, "2026-01-02T11:04:05.123456789+08:00");
        assert_eq!(w.local.sql_datetime, "2026-01-02 11:04:05");
        assert_eq!(w.local.sql_date, "2026-01-02");
        assert_eq!(w.day, "Friday, day 2 of 2026, ISO week 2026-W01");
    }

    #[test]
    fn before_1970_keeps_its_fraction() {
        let w = format_timestamp_internal("-2", 500_000_000, 0, &[]).unwrap();
        assert_eq!(w.unix.milliseconds, "-1500");
        assert_eq!(w.utc.rfc3339, "1969-12-31T23:59:58.500000000Z");
    }

    #[test]
    fn a_bad_custom_pattern_fails_alone() {
        let patterns = vec![
            "%Y/%m/%d %H:%M".to_string(),
            "%Q".to_string(),
            "%d.%m.%y".to_string(),
        ];
        let w = format_timestamp_internal(&T.to_string(), 0, 8 * 3600, &patterns).unwrap();
        assert_eq!(w.custom[0].value.as_deref(), Some("2026/01/02 11:04"));
        assert!(w.custom[1].value.is_none() && w.custom[1].error.is_some());
        assert_eq!(w.custom[2].value.as_deref(), Some("02.01.26"));
    }

    #[test]
    fn every_format_in_the_menu_has_a_reader() {
        for (id, ..) in FORMATS {
            let err = read_timestamp_at("?", id, "", now()).unwrap_err();
            assert!(!err.starts_with("unknown format"), "{id}");
        }
    }
}
