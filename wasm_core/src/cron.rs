//! The Cron tool: read a crontab schedule into words, field by field, and list when it
//! runs next.
//!
//! croner decides the run times (L, W, # and the day rules are easy to get wrong), but
//! its own descriptions drop ranges ("23 0-20/2" reads as "every 2 hours") and its
//! errors don't name the field, so the words and the per-field checks are written here.
//! The grammar here is stricter than croner's where croner accepts something it then
//! gets wrong: `L` alone in the weekday field never runs, `LW` is read as `L`, a
//! trailing comma is ignored, and `MON-FRI#2` matches any of those days in week two.
//!
//! Run times are wall-clock times (NaiveDateTime): zones by name stay with the page,
//! which has the browser's tz database through `Intl` (as in the Timestamp tool).

use chrono::{DateTime, NaiveDateTime};
use croner::parser::{CronParser, Seconds};
use serde::Serialize;
use wasm_bindgen::prelude::*;

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Second,
    Minute,
    Hour,
    Day,
    Month,
    Weekday,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Second => "Second",
            Kind::Minute => "Minute",
            Kind::Hour => "Hour",
            Kind::Day => "Day",
            Kind::Month => "Month",
            Kind::Weekday => "Weekday",
        }
    }

    fn unit(self) -> &'static str {
        match self {
            Kind::Second => "second",
            Kind::Minute => "minute",
            Kind::Hour => "hour",
            Kind::Day => "day",
            Kind::Month => "month",
            Kind::Weekday => "day of the week",
        }
    }

    /// What a value may be. 7 is Sunday too, but 0–6 covers every day once.
    fn limits(self) -> (u32, u32) {
        match self {
            Kind::Second | Kind::Minute => (0, 59),
            Kind::Hour => (0, 23),
            Kind::Day => (1, 31),
            Kind::Month => (1, 12),
            Kind::Weekday => (0, 6),
        }
    }

    fn allowed(self) -> &'static str {
        match self {
            Kind::Second | Kind::Minute => "0–59",
            Kind::Hour => "0–23",
            Kind::Day => "1–31",
            Kind::Month => "1–12 or JAN–DEC",
            Kind::Weekday => "0–6 or SUN–SAT",
        }
    }

    fn names(self) -> &'static [&'static str] {
        match self {
            Kind::Month => &MONTHS,
            Kind::Weekday => &WEEKDAYS,
            _ => &[],
        }
    }

    fn value_words(self, value: u32) -> String {
        match self {
            Kind::Day => format!("the {}", ordinal(value)),
            Kind::Month => MONTH_WORDS[value as usize - 1].into(),
            Kind::Weekday => WEEKDAY_WORDS[value as usize % 7].into(),
            _ => value.to_string(),
        }
    }
}

const MONTHS: [&str; 12] = [
    "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
];
const WEEKDAYS: [&str; 7] = ["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"];
const MONTH_WORDS: [&str; 12] = [
    "January",
    "February",
    "March",
    "April",
    "May",
    "June",
    "July",
    "August",
    "September",
    "October",
    "November",
    "December",
];
const WEEKDAY_WORDS: [&str; 7] = [
    "Sunday",
    "Monday",
    "Tuesday",
    "Wednesday",
    "Thursday",
    "Friday",
    "Saturday",
];

const ALIASES: &[(&str, &str)] = &[
    ("@yearly", "0 0 1 1 *"),
    ("@annually", "0 0 1 1 *"),
    ("@monthly", "0 0 1 * *"),
    ("@weekly", "0 0 * * 0"),
    ("@daily", "0 0 * * *"),
    ("@midnight", "0 0 * * *"),
    ("@hourly", "0 * * * *"),
];

#[derive(Clone, Debug, PartialEq)]
enum Item {
    /// `*` or `?`, with a step (1 when there is none).
    All { step: u32 },
    /// `a`, `a-b` or `a-b/n`; a single value has `from == to`.
    Range { from: u32, to: u32, step: u32 },
    /// `L` in the day field.
    LastDay,
    /// `15W`: the weekday nearest that day of the month.
    NearestWeekday(u32),
    /// `5L` or `5#L`: the last Friday of the month.
    LastWeekday(u32),
    /// `1#2`: the second Monday of the month.
    Nth { weekday: u32, nth: u32 },
}

struct Parsed {
    items: Vec<Item>,
    /// `+` before the weekday field: day and weekday must both match (croner's extension).
    and: bool,
}

impl Parsed {
    /// `*` alone: the field leaves the time unrestricted.
    fn any(&self) -> bool {
        self.items == [Item::All { step: 1 }]
    }

    fn single(&self) -> Option<u32> {
        match self.items.as_slice() {
            [Item::Range { from, to, .. }] if from == to => Some(*from),
            _ => None,
        }
    }

    /// Every item is one value: `0,12` but not `0-12`.
    fn singles(&self) -> Option<Vec<u32>> {
        self.items
            .iter()
            .map(|item| match item {
                Item::Range { from, to, .. } if from == to => Some(*from),
                _ => None,
            })
            .collect()
    }
}

/// How the builder can show a field; `Other` is anything it has no control for (L, W, #).
#[derive(Debug, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum Form {
    Every,
    Step { step: u32 },
    Range { from: u32, to: u32, step: u32 },
    Values,
    Other,
}

#[derive(Debug, Serialize)]
pub struct FieldReading {
    pub name: &'static str,
    pub text: String,
    pub allowed: &'static str,
    pub min: u32,
    pub max: u32,
    /// What the field alone means; empty when it has an error.
    pub words: String,
    pub error: Option<String>,
    pub form: Form,
    /// Every value it matches, for the builder's toggles; empty for `Other`.
    pub values: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct CronReading {
    /// The fields joined by single spaces, an alias written out.
    pub expression: String,
    pub alias: Option<String>,
    pub words: String,
    /// Empty for @reboot, which has no schedule.
    pub fields: Vec<FieldReading>,
    /// The first problem, named by field; the fields carry their own.
    pub error: Option<String>,
    /// The minute or hour field starts with `*`. Across daylight-saving changes cronie
    /// and Vixie cron run such jobs again in a repeated hour and skip them in a missing
    /// one, while the others run once, and right after the jump when theirs is skipped.
    pub wildcard: bool,
}

#[wasm_bindgen]
pub fn read_cron(expression: &str) -> Result<JsValue, JsValue> {
    read_cron_internal(expression)
        .and_then(|reading| serde_wasm_bindgen::to_value(&reading).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

/// The next `count` times after the wall-clock time `after` (seconds counted as if it
/// were UTC), as wall-clock seconds in the same frame.
#[wasm_bindgen]
pub fn cron_runs(expression: &str, after: f64, count: u32) -> Result<Vec<f64>, JsValue> {
    let start = DateTime::from_timestamp(after.floor() as i64, 0)
        .ok_or_else(|| JsValue::from_str("Start time out of range"))?
        .naive_utc();
    cron_runs_internal(expression, start, count as usize)
        .map(|runs| {
            runs.iter()
                .map(|run| run.and_utc().timestamp() as f64)
                .collect()
        })
        .map_err(|err| JsValue::from_str(&err))
}

pub fn read_cron_internal(expression: &str) -> Result<CronReading, String> {
    let text = expression.trim();
    if text.is_empty() {
        return Err("Type or paste a cron expression".into());
    }
    let lower = text.to_ascii_lowercase();
    if lower == "@reboot" {
        return Ok(CronReading {
            expression: "@reboot".into(),
            alias: Some("@reboot".into()),
            words: "Once, when cron starts.".into(),
            fields: Vec::new(),
            error: None,
            wildcard: false,
        });
    }
    let (alias, text) = if text.starts_with('@') {
        let expanded = ALIASES
            .iter()
            .find(|(name, _)| *name == lower)
            .map(|(_, expanded)| *expanded)
            .ok_or_else(|| {
                format!(
                    "{text} isn't a cron alias: use @yearly, @monthly, @weekly, @daily, @hourly or @reboot"
                )
            })?;
        (Some(lower), expanded)
    } else {
        (None, text)
    };
    let parts: Vec<&str> = text.split_whitespace().collect();
    let kinds: &[Kind] = match parts.len() {
        5 => &[
            Kind::Minute,
            Kind::Hour,
            Kind::Day,
            Kind::Month,
            Kind::Weekday,
        ],
        6 => &[
            Kind::Second,
            Kind::Minute,
            Kind::Hour,
            Kind::Day,
            Kind::Month,
            Kind::Weekday,
        ],
        n => {
            return Err(format!(
                "A cron expression has 5 fields (minute hour day month weekday), or 6 with seconds first; this has {n}"
            ));
        }
    };
    let parsed: Vec<Result<Parsed, String>> = kinds
        .iter()
        .zip(&parts)
        .map(|(&kind, part)| parse_field(kind, part))
        .collect();

    let mut error = kinds.iter().zip(&parsed).find_map(|(kind, result)| {
        result
            .as_ref()
            .err()
            .map(|e| format!("{}: {e}", kind.name()))
    });
    let mut words = String::new();
    if error.is_none() {
        let fields: Vec<&Parsed> = parsed.iter().filter_map(|p| p.as_ref().ok()).collect();
        let and = day_and_weekday(parts[parts.len() - 3], parts[parts.len() - 1]);
        // croner has the last word: anything it rejects can't run.
        match parser(and).parse(&parts.join(" ")) {
            Ok(_) => words = sentence(&fields, and),
            Err(err) => error = Some(err.to_string()),
        }
    }

    let fields = kinds
        .iter()
        .zip(&parts)
        .zip(parsed)
        .map(|((&kind, part), result)| field_reading(kind, part, result))
        .collect();
    let n = parts.len();
    Ok(CronReading {
        expression: parts.join(" "),
        alias,
        words,
        fields,
        error,
        wildcard: parts[n - 5].starts_with('*') || parts[n - 4].starts_with('*'),
    })
}

pub fn cron_runs_internal(
    expression: &str,
    after: NaiveDateTime,
    count: usize,
) -> Result<Vec<NaiveDateTime>, String> {
    let reading = read_cron_internal(expression)?;
    if let Some(error) = reading.error {
        return Err(error);
    }
    if reading.fields.is_empty() {
        return Ok(Vec::new());
    }
    let parts: Vec<&str> = reading.expression.split(' ').collect();
    let and = day_and_weekday(parts[parts.len() - 3], parts[parts.len() - 1]);
    let cron = parser(and)
        .parse(&reading.expression)
        .map_err(|err| err.to_string())?;
    Ok(cron.iter_after(after).take(count).collect())
}

fn parser(and: bool) -> CronParser {
    CronParser::builder()
        .seconds(Seconds::Optional)
        .dom_and_dow(and)
        .build()
}

/// Vixie cron (and cronie, and crontab.guru) runs on either day when both fields are
/// restricted, but on both when either one starts with `*` (`*/2` included); croner
/// only treats a bare `*` that way, so it is told which.
fn day_and_weekday(day: &str, weekday: &str) -> bool {
    let starred = |field: &str| field.starts_with('*') || field.starts_with('?');
    weekday.starts_with('+') || starred(day) || starred(weekday)
}

fn field_reading(kind: Kind, text: &str, parsed: Result<Parsed, String>) -> FieldReading {
    let (min, max) = kind.limits();
    let base = FieldReading {
        name: kind.name(),
        text: text.into(),
        allowed: kind.allowed(),
        min,
        max,
        words: String::new(),
        error: None,
        form: Form::Other,
        values: Vec::new(),
    };
    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(error) => {
            return FieldReading {
                error: Some(error),
                ..base
            };
        }
    };
    let mut words = field_words(kind, &parsed);
    if kind == Kind::Day && !parsed.any() {
        words.push_str(" of the month");
    }
    let values = expand(kind, &parsed);
    let form = match parsed.items.as_slice() {
        _ if parsed.and => Form::Other,
        [Item::All { step: 1 }] => Form::Every,
        [Item::All { step }] => Form::Step { step: *step },
        [Item::Range { from, to, step }] if from != to => Form::Range {
            from: *from,
            to: *to,
            step: *step,
        },
        items
            if items
                .iter()
                .all(|item| matches!(item, Item::Range { step: 1, .. })) =>
        {
            Form::Values
        }
        _ => Form::Other,
    };
    FieldReading {
        words,
        values: if form == Form::Other {
            Vec::new()
        } else {
            values
        },
        form,
        ..base
    }
}

/// Every value the field matches, for the plain items; the weekday 7 counts as 0.
fn expand(kind: Kind, parsed: &Parsed) -> Vec<u32> {
    let (min, max) = kind.limits();
    let mut values: Vec<u32> = parsed
        .items
        .iter()
        .flat_map(|item| match item {
            Item::All { step } => (min..=max).step_by(*step as usize).collect(),
            Item::Range { from, to, step } => (*from..=*to)
                .step_by(*step as usize)
                .map(|v| if kind == Kind::Weekday { v % 7 } else { v })
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    values.sort_unstable();
    values.dedup();
    values
}

fn parse_field(kind: Kind, text: &str) -> Result<Parsed, String> {
    let (and, body) = match text.strip_prefix('+') {
        Some(rest) if kind == Kind::Weekday => (true, rest),
        Some(_) => return Err("+ only goes before the weekday field".into()),
        None => (false, text),
    };
    let items = body
        .split(',')
        .map(|item| parse_item(kind, item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Parsed { items, and })
}

fn parse_item(kind: Kind, text: &str) -> Result<Item, String> {
    if text.is_empty() {
        return Err("an empty entry between commas".into());
    }
    let upper = text.to_ascii_uppercase();
    let (base, step) = match upper.split_once('/') {
        Some((base, step)) => (base, Some(parse_step(kind, step)?)),
        None => (upper.as_str(), None),
    };
    let day_or_weekday = matches!(kind, Kind::Day | Kind::Weekday);
    if base == "*" || (base == "?" && day_or_weekday) {
        return Ok(Item::All {
            step: step.unwrap_or(1),
        });
    }
    if base == "?" {
        return Err("? only goes in the day and weekday fields".into());
    }
    let special = |item: Item| match step {
        Some(_) => Err(format!("{text} can't take a step")),
        None => Ok(item),
    };
    if kind == Kind::Day {
        if base == "L" {
            return special(Item::LastDay);
        }
        if base == "LW" {
            return Err(
                "LW (the last weekday of the month) isn't supported: use L or 28-31W".into(),
            );
        }
        if let Some(day) = base.strip_suffix('W') {
            return special(Item::NearestWeekday(value(kind, day)?));
        }
    }
    if kind == Kind::Weekday {
        if base == "L" {
            return Err("L in the weekday field needs a day: 5L is the last Friday".into());
        }
        if let Some((day, nth)) = base.split_once('#') {
            let weekday = value(kind, day)? % 7;
            if nth == "L" {
                return special(Item::LastWeekday(weekday));
            }
            let nth: u32 = nth
                .parse()
                .ok()
                .filter(|n| (1..=5).contains(n))
                .ok_or_else(|| format!("{text}: the number after # is a week, 1–5 or L"))?;
            return special(Item::Nth { weekday, nth });
        }
        if let Some(day) = base.strip_suffix('L') {
            return special(Item::LastWeekday(value(kind, day)? % 7));
        }
    }
    if let Some((from, to)) = base.split_once('-') {
        let (from, to) = (value(kind, from)?, value(kind, to)?);
        if from > to {
            return Err(format!(
                "{text} runs backwards: write it as two ranges, or the other way round"
            ));
        }
        return Ok(Item::Range {
            from,
            to,
            step: step.unwrap_or(1),
        });
    }
    let single = value(kind, base)?;
    if let Some(step) = step {
        let (_, max) = kind.limits();
        let max = if kind == Kind::Weekday { 7 } else { max };
        return Err(format!(
            "{text} needs a range to step through: write {single}-{max}/{step} or */{step}"
        ));
    }
    Ok(Item::Range {
        from: single,
        to: single,
        step: 1,
    })
}

fn parse_step(kind: Kind, text: &str) -> Result<u32, String> {
    let (min, max) = kind.limits();
    let step: u32 = text
        .parse()
        .map_err(|_| format!("the step /{text} isn't a whole number"))?;
    if step == 0 || step > max - min + 1 {
        return Err(format!("the step /{text} is outside 1–{}", max - min + 1));
    }
    Ok(step)
}

fn value(kind: Kind, text: &str) -> Result<u32, String> {
    if let Some(index) = kind.names().iter().position(|name| *name == text) {
        return Ok(index as u32 + kind.limits().0);
    }
    let (min, max) = kind.limits();
    // 7 is Sunday in every cron; it is read here and folded into 0 later.
    let max = if kind == Kind::Weekday { 7 } else { max };
    let number: u32 = text.parse().map_err(|_| {
        if text.is_empty() {
            "a range or step is missing a number".to_string()
        } else {
            format!("{text} isn't a value here ({})", kind.allowed())
        }
    })?;
    if !(min..=max).contains(&number) {
        return Err(format!("{number} is outside {}", kind.allowed()));
    }
    Ok(number)
}

// ---- Words ----

fn ordinal(n: u32) -> String {
    let suffix = match (n % 10, n % 100) {
        (_, 11..=13) => "th",
        (1, _) => "st",
        (2, _) => "nd",
        (3, _) => "rd",
        _ => "th",
    };
    format!("{n}{suffix}")
}

/// "a", "a and b", "a, b and c".
fn join(parts: &[String]) -> String {
    match parts {
        [] => String::new(),
        [one] => one.clone(),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

fn clock(hour: u32, minute: u32, second: Option<u32>) -> String {
    match second {
        Some(s) if s != 0 => format!("{hour:02}:{minute:02}:{s:02}"),
        _ => format!("{hour:02}:{minute:02}"),
    }
}

fn item_words(kind: Kind, item: &Item) -> String {
    let unit = kind.unit();
    let bounds = |from: u32, to: u32| match kind {
        Kind::Day | Kind::Month | Kind::Weekday => (kind.value_words(from), kind.value_words(to)),
        _ => (from.to_string(), to.to_string()),
    };
    match item {
        Item::All { step: 1 } => format!("every {unit}"),
        Item::All { step } => format!("every {} {unit}", ordinal(*step)),
        Item::Range { from, to, .. } if from == to => kind.value_words(*from),
        Item::Range { from, to, step: 1 } => {
            let (from, to) = bounds(*from, *to);
            match kind {
                Kind::Month | Kind::Weekday => format!("{from} through {to}"),
                _ => format!("every {unit} from {from} through {to}"),
            }
        }
        Item::Range { from, to, step } => {
            let (from, to) = bounds(*from, *to);
            format!("every {} {unit} from {from} through {to}", ordinal(*step))
        }
        Item::LastDay => "the last day".into(),
        Item::NearestWeekday(day) => format!("the weekday nearest the {}", ordinal(*day)),
        Item::LastWeekday(day) => format!("the last {} of the month", WEEKDAY_WORDS[*day as usize]),
        Item::Nth { weekday, nth } => format!(
            "the {} {} of the month",
            ordinal(*nth),
            WEEKDAY_WORDS[*weekday as usize]
        ),
    }
}

/// The field on its own: single values are gathered where the first one stands, so
/// `0,15,30` reads "minute 0, 15 and 30" rather than repeating the unit.
fn field_words(kind: Kind, parsed: &Parsed) -> String {
    let mut parts: Vec<String> = Vec::new();
    let mut singles: Vec<String> = Vec::new();
    let mut singles_at = None;
    for item in &parsed.items {
        match item {
            Item::Range { from, to, .. } if from == to => {
                singles_at.get_or_insert(parts.len());
                singles.push(match kind {
                    Kind::Day => ordinal(*from),
                    _ => kind.value_words(*from),
                });
            }
            _ => parts.push(item_words(kind, item)),
        }
    }
    if let Some(at) = singles_at {
        let list = join(&singles);
        let group = match kind {
            Kind::Second | Kind::Minute | Kind::Hour => format!("{} {list}", kind.unit()),
            Kind::Day => format!("the {list}"),
            Kind::Month | Kind::Weekday => list,
        };
        parts.insert(at, group);
    }
    join(&parts)
}

fn sentence(fields: &[&Parsed], and: bool) -> String {
    let (second, rest) = match fields.len() {
        6 => (Some(fields[0]), &fields[1..]),
        _ => (None, fields),
    };
    let [minute, hour, day, month, weekday] = rest else {
        unreachable!("five fields after the seconds");
    };
    let mut out = vec![time_words(second, minute, hour)];

    let on_day = || {
        let words = field_words(Kind::Day, day);
        if month.any() {
            format!("on {words} of the month")
        } else {
            format!("on {words}")
        }
    };
    let on_weekday = || format!("on {}", field_words(Kind::Weekday, weekday));
    match (day.any(), weekday.any()) {
        (true, true) => {}
        (false, true) => out.push(on_day()),
        (true, false) => out.push(on_weekday()),
        (false, false) if and => out.push(format!(
            "{} if it falls on {}",
            on_day(),
            field_words(Kind::Weekday, weekday)
        )),
        (false, false) => out.push(format!("{}, or {}", on_day(), on_weekday())),
    }
    if !month.any() {
        out.push(format!("in {}", field_words(Kind::Month, month)));
    }
    format!("{}.", out.join(" "))
}

fn time_words(second: Option<&Parsed>, minute: &Parsed, hour: &Parsed) -> String {
    // A seconds field of 0 says nothing a 5-field expression doesn't.
    let second = second.filter(|s| s.single() != Some(0));
    let second_value = match second {
        None => Some(None),
        Some(s) => s.single().map(Some),
    };
    if let (Some(m), Some(hours), Some(s)) = (minute.single(), hour.singles(), second_value) {
        let times: Vec<String> = hours.iter().map(|&h| clock(h, m, s)).collect();
        return format!("At {}", join(&times));
    }
    let mut chain: Vec<(Kind, &Parsed)> = Vec::new();
    if let Some(s) = second {
        chain.push((Kind::Second, s));
    }
    chain.push((Kind::Minute, minute));
    chain.push((Kind::Hour, hour));
    // "every minute past every hour" says no more than "every minute".
    while chain.len() > 1 && chain.last().is_some_and(|(_, f)| f.any()) {
        chain.pop();
    }
    let words: Vec<String> = chain
        .iter()
        .map(|(kind, field)| field_words(*kind, field))
        .collect();
    format!("At {}", words.join(" past "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Datelike, NaiveDate, Timelike};

    fn words(expression: &str) -> String {
        let reading = read_cron_internal(expression).expect("reads");
        assert_eq!(reading.error, None, "{expression}");
        reading.words
    }

    fn error(expression: &str) -> String {
        match read_cron_internal(expression) {
            Ok(reading) => reading.error.expect("an error"),
            Err(err) => err,
        }
    }

    fn at(y: i32, m: u32, d: u32, h: u32, min: u32) -> NaiveDateTime {
        NaiveDate::from_ymd_opt(y, m, d)
            .unwrap()
            .and_hms_opt(h, min, 0)
            .unwrap()
    }

    #[test]
    fn says_what_a_schedule_means() {
        for (expression, expected) in [
            ("* * * * *", "At every minute."),
            ("5 4 * * *", "At 04:05."),
            ("5 0 * 8 *", "At 00:05 in August."),
            ("15 14 1 * *", "At 14:15 on the 1st of the month."),
            ("0 22 * * 1-5", "At 22:00 on Monday through Friday."),
            // crontab.guru's own example, and where croner drops the range.
            (
                "23 0-20/2 * * *",
                "At minute 23 past every 2nd hour from 0 through 20.",
            ),
            ("5 4 * * sun", "At 04:05 on Sunday."),
            (
                "0 0,12 1 */2 *",
                "At 00:00 and 12:00 on the 1st in every 2nd month.",
            ),
            (
                "0 4 8-14 * *",
                "At 04:00 on every day from the 8th through the 14th of the month.",
            ),
            (
                "0 0 1,15 * 3",
                "At 00:00 on the 1st and 15th of the month, or on Wednesday.",
            ),
            ("*/15 * * * *", "At every 15th minute."),
            (
                "*/15 9-17 * * 1-5",
                "At every 15th minute past every hour from 9 through 17 on Monday through Friday.",
            ),
            ("0 * * * *", "At minute 0."),
            ("0 */6 * * *", "At minute 0 past every 6th hour."),
            ("* 9 * * *", "At every minute past hour 9."),
            (
                "0,30 * * jan-mar *",
                "At minute 0 and 30 in January through March.",
            ),
            (
                "5,7,10-12 * * * *",
                "At minute 5 and 7 and every minute from 10 through 12.",
            ),
            ("0 9 * * 1,3,5", "At 09:00 on Monday, Wednesday and Friday."),
            ("0 0 L * *", "At 00:00 on the last day of the month."),
            ("0 0 * * 5L", "At 00:00 on the last Friday of the month."),
            ("0 0 * * 5#L", "At 00:00 on the last Friday of the month."),
            ("0 0 * * 1#2", "At 00:00 on the 2nd Monday of the month."),
            (
                "0 12 15W * *",
                "At 12:00 on the weekday nearest the 15th of the month.",
            ),
            (
                "0 0 */2 * 1",
                "At 00:00 on every 2nd day of the month if it falls on Monday.",
            ),
            (
                "0 0 1 * +MON",
                "At 00:00 on the 1st of the month if it falls on Monday.",
            ),
            ("0 0 1 1 *", "At 00:00 on the 1st in January."),
            ("0 0 * * 7", "At 00:00 on Sunday."),
            ("30 0 0 * * *", "At 00:00:30."),
            ("0 30 9 * * *", "At 09:30."),
            ("*/10 * * * * *", "At every 10th second."),
            ("30 */5 * * * *", "At second 30 past every 5th minute."),
        ] {
            assert_eq!(words(expression), expected, "{expression}");
        }
    }

    #[test]
    fn wildcard_is_cronies_minute_or_hour_star() {
        for (expression, wildcard) in [
            ("* * * * *", true),
            ("*/15 1 * * *", true),
            ("5 * * * *", true),
            ("0 */2 * * *", true),
            ("30 2 * * *", false),
            ("0,30 1-3 * * *", false),
            // Seconds don't count: cronie has none.
            ("*/10 30 2 * * *", false),
            ("0 * 2 * * *", true),
            ("@hourly", true),
            ("@daily", false),
        ] {
            let reading = read_cron_internal(expression).expect("reads");
            assert_eq!(reading.wildcard, wildcard, "{expression}");
        }
    }

    #[test]
    fn aliases_are_written_out() {
        let reading = read_cron_internal("@weekly").expect("alias");
        assert_eq!(reading.alias.as_deref(), Some("@weekly"));
        assert_eq!(reading.expression, "0 0 * * 0");
        assert_eq!(reading.words, "At 00:00 on Sunday.");
        let reboot = read_cron_internal("@REBOOT").expect("reboot");
        assert!(reboot.fields.is_empty(), "@reboot has no schedule");
        assert!(
            cron_runs_internal("@reboot", at(2026, 1, 1, 0, 0), 5)
                .expect("runs")
                .is_empty()
        );
        assert!(error("@often").contains("isn't a cron alias"));
    }

    #[test]
    fn errors_name_the_field_and_the_fix() {
        for (expression, expected) in [
            ("61 * * * *", "Minute: 61 is outside 0–59"),
            ("* 24 * * *", "Hour: 24 is outside 0–23"),
            ("* * 0 * *", "Day: 0 is outside 1–31"),
            ("* * * 13 *", "Month: 13 is outside 1–12 or JAN–DEC"),
            ("* * * * 8", "Weekday: 8 is outside 0–6 or SUN–SAT"),
            (
                "* * * foo *",
                "Month: FOO isn't a value here (1–12 or JAN–DEC)",
            ),
            (
                "5/15 * * * *",
                "Minute: 5/15 needs a range to step through: write 5-59/15 or */15",
            ),
            ("*/0 * * * *", "Minute: the step /0 is outside 1–60"),
            (
                "* 22-2 * * *",
                "Hour: 22-2 runs backwards: write it as two ranges, or the other way round",
            ),
            ("* * * * 1,", "Weekday: an empty entry between commas"),
            (
                "0 0 * * L",
                "Weekday: L in the weekday field needs a day: 5L is the last Friday",
            ),
            (
                "0 0 LW * *",
                "Day: LW (the last weekday of the month) isn't supported: use L or 28-31W",
            ),
            (
                "0 0 * * 1#6",
                "Weekday: 1#6: the number after # is a week, 1–5 or L",
            ),
            ("0 0 L/2 * *", "Day: L/2 can't take a step"),
            ("+0 0 * * *", "Minute: + only goes before the weekday field"),
        ] {
            assert_eq!(error(expression), expected, "{expression}");
        }
        assert!(error("* * *").starts_with("A cron expression has 5 fields"));
        assert!(error("0 0 0 1 1 * 2030").ends_with("this has 7"));
        assert_eq!(error("  "), "Type or paste a cron expression");
    }

    #[test]
    fn a_bad_field_leaves_the_others_readable() {
        // The builder keeps working on the other fields while one is wrong.
        let reading = read_cron_internal("0 25 * * 1-5").expect("reads");
        assert!(reading.words.is_empty());
        assert!(reading.fields[1].error.is_some());
        assert_eq!(
            reading.fields[4].form,
            Form::Range {
                from: 1,
                to: 5,
                step: 1
            }
        );
        assert_eq!(reading.fields[4].words, "Monday through Friday");
    }

    #[test]
    fn fields_tell_the_builder_their_shape() {
        let reading = read_cron_internal("*/5 9-17/2 1,15,20-22 * MON-FRI").expect("reads");
        let forms: Vec<&Form> = reading.fields.iter().map(|f| &f.form).collect();
        assert_eq!(
            forms,
            [
                &Form::Step { step: 5 },
                &Form::Range {
                    from: 9,
                    to: 17,
                    step: 2
                },
                &Form::Values,
                &Form::Every,
                &Form::Range {
                    from: 1,
                    to: 5,
                    step: 1
                },
            ]
        );
        assert_eq!(reading.fields[2].values, [1, 15, 20, 21, 22]);
        assert_eq!(reading.fields[1].values, [9, 11, 13, 15, 17]);
        // 7 and 0 are both Sunday: one toggle.
        let sundays = read_cron_internal("0 0 * * 0,7").expect("reads");
        assert_eq!(sundays.fields[4].values, [0]);
        let special = read_cron_internal("0 0 L * 5#2").expect("reads");
        assert_eq!(special.fields[2].form, Form::Other);
        assert_eq!(special.fields[4].form, Form::Other);
    }

    #[test]
    fn next_runs_follow_vixie_day_rules() {
        let start = at(2026, 11, 12, 10, 0);
        let days = |expression: &str| -> Vec<(u32, u32)> {
            cron_runs_internal(expression, start, 4)
                .expect("runs")
                .iter()
                .map(|t| (t.month(), t.day()))
                .collect()
        };
        // Both restricted: either day. 2026-11-13 is a Friday.
        assert_eq!(days("0 0 13 * 5"), [(11, 13), (11, 20), (11, 27), (12, 4)]);
        // One starts with *: both must hold, as Vixie cron has it (croner alone runs it
        // on every odd day and every Monday).
        assert_eq!(days("0 0 */2 * 1"), [(11, 23), (12, 7), (12, 21), (1, 11)]);
        assert_eq!(days("0 0 1 * +1"), [(2, 1), (3, 1), (11, 1), (5, 1)]);
        assert_eq!(days("0 0 L * *"), [(11, 30), (12, 31), (1, 31), (2, 28)]);
        assert_eq!(days("0 0 * * 5#L"), [(11, 27), (12, 25), (1, 29), (2, 26)]);
        // Never: there is no 31 February.
        assert!(
            cron_runs_internal("0 0 31 2 *", start, 3)
                .expect("runs")
                .is_empty()
        );
        let seconds = cron_runs_internal("*/20 * * * * *", start, 3).expect("runs");
        assert_eq!(
            seconds.iter().map(|t| t.second()).collect::<Vec<_>>(),
            [20, 40, 0]
        );
    }

    /// An oracle that knows nothing of croner: try every minute and match the fields'
    /// value sets with Vixie's day rule.
    #[test]
    fn next_runs_match_a_minute_by_minute_search() {
        let start = at(2026, 11, 12, 10, 7);
        for expression in [
            "* * * * *",
            "*/7 * * * *",
            "5,10-12 3-5/2 * * *",
            "0 9 * * 1-5",
            "30 18 1,15 * *",
            "0 0 1,15 * 3",
            "0 0 */3 * 2",
            "0 0 * */4 0",
            "15 6 13 * 5",
            "0 12 * feb-apr mon,fri",
            "59 23 31 * *",
            "0 0 29 2 *",
        ] {
            let reading = read_cron_internal(expression).expect("reads");
            let set = |i: usize| reading.fields[i].values.clone();
            let parts: Vec<&str> = expression.split(' ').collect();
            let and = day_and_weekday(parts[2], parts[4]);
            let mut expected = Vec::new();
            let mut t = start + chrono::Duration::minutes(1);
            while expected.len() < 5 && t.year() < 2050 {
                let day = set(2).contains(&t.day());
                let weekday = set(4).contains(&t.weekday().num_days_from_sunday());
                let date = if and { day && weekday } else { day || weekday };
                if !(date && set(3).contains(&t.month())) {
                    // Not a day it runs on: on to the next midnight.
                    t = (t.date() + chrono::Duration::days(1))
                        .and_hms_opt(0, 0, 0)
                        .unwrap();
                    continue;
                }
                if set(0).contains(&t.minute()) && set(1).contains(&t.hour()) {
                    expected.push(t);
                }
                t += chrono::Duration::minutes(1);
            }
            assert_eq!(
                cron_runs_internal(expression, start, 5).expect("runs"),
                expected,
                "{expression}"
            );
        }
    }
}
