// Core Wasm entry: binds Rust helpers (converters, encoders, generators) into JS via wasm_bindgen.
use std::collections::{BTreeMap, HashSet};
use std::convert::TryInto;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

use adler::Adler32;
use argon2::{Algorithm as ArgonAlgorithm, Argon2, Version as ArgonVersion};
use ascii85::{decode as ascii85_decode, encode as ascii85_encode};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use bcrypt::{hash_with_salt as bcrypt_hash_with_salt, verify as bcrypt_verify_fn};
use chrono::{DateTime, NaiveDate, NaiveDateTime, NaiveTime, TimeZone, Utc};
use console_error_panic_hook::set_once as set_panic_hook;
use crc::{CRC_32_ISCSI, CRC_64_ECMA_182, CRC_64_GO_ISO, Crc};
use data_encoding::{BASE32, BASE32_NOPAD, BASE32HEX, BASE32HEX_NOPAD};
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use js_sys::Date;
use md5::Md5;
use num_bigint::BigInt;
use password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use uuid as uuid_crate;
use uuid_crate::{Context, NoContext, Timestamp};
use wasm_bindgen::prelude::*;

mod convert;

/// Wasm entry point that installs a panic hook so Rust panics appear in the browser console.
#[wasm_bindgen(start)]
pub fn wasm_start() {
    set_panic_hook();
}

static NODE_ID: OnceLock<[u8; 6]> = OnceLock::new();
static V1_CONTEXT: OnceLock<Context> = OnceLock::new();
static BASE91_LOOKUP: OnceLock<[i16; 256]> = OnceLock::new();
static TABLE_REGEX: OnceLock<Regex> = OnceLock::new();
static COLUMN_REGEX: OnceLock<Regex> = OnceLock::new();

const BASE91_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

const UNIT_FACTORS: &[(&str, f64)] = &[
    ("bit", 1.0),
    ("byte", 8.0),
    ("kilobit", 1_024.0),
    ("kilobyte", 8_192.0),
    ("megabit", 1_048_576.0),
    ("megabyte", 8_388_608.0),
    ("gigabit", 1_073_741_824.0),
    ("gigabyte", 8_589_934_592.0),
    ("terabit", 1_099_511_627_776.0),
    ("terabyte", 8_796_093_022_208.0),
];

const LOREM_WORDS: &[&str] = &[
    "lorem",
    "ipsum",
    "dolor",
    "sit",
    "amet",
    "consectetur",
    "adipiscing",
    "elit",
    "sed",
    "do",
    "eiusmod",
    "tempor",
    "incididunt",
    "ut",
    "labore",
    "et",
    "dolore",
    "magna",
    "aliqua",
    "ut",
    "enim",
    "ad",
    "minim",
    "veniam",
    "quis",
    "nostrud",
    "exercitation",
    "ullamco",
    "laboris",
    "nisi",
    "ut",
    "aliquip",
    "ex",
    "ea",
    "commodo",
    "consequat",
];

fn node_id() -> &'static [u8; 6] {
    NODE_ID.get_or_init(|| {
        let mut bytes = [0u8; 6];
        fill_random(&mut bytes);
        bytes[0] |= 0x01;
        bytes
    })
}

fn context_v1() -> &'static Context {
    V1_CONTEXT.get_or_init(|| {
        let mut seed_bytes = [0u8; 2];
        fill_random(&mut seed_bytes);
        let seed = u16::from_ne_bytes(seed_bytes);
        Context::new(seed)
    })
}

fn now_millis() -> u64 {
    Date::now() as u64
}

fn unix_timestamp_parts() -> (u64, u32) {
    let millis = now_millis();
    let seconds = millis / 1000;
    let nanos = ((millis % 1000) * 1_000_000) as u32;
    (seconds, nanos)
}

fn timestamp_for_v1() -> Timestamp {
    let (seconds, nanos) = unix_timestamp_parts();
    Timestamp::from_unix(context_v1(), seconds, nanos)
}

fn timestamp_for_v7() -> Timestamp {
    let (seconds, nanos) = unix_timestamp_parts();
    Timestamp::from_unix(NoContext, seconds, nanos)
}

fn uuid_from_bytes(bytes: [u8; 16]) -> String {
    uuid_crate::Uuid::from_bytes(bytes).to_string()
}

fn uuid_v2() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x20;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid_from_bytes(bytes)
}

fn uuid_v8() -> String {
    let mut bytes = [0u8; 16];
    fill_random(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    uuid_from_bytes(bytes)
}

fn random_name() -> [u8; 32] {
    let mut buf = [0u8; 32];
    fill_random(&mut buf);
    buf
}

fn guid_uppercase() -> String {
    uuid_crate::Uuid::new_v4().to_string().to_uppercase()
}

const ULID_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

fn encode_ulid(timestamp_ms: u64, randomness: [u8; 10]) -> String {
    let mut chars = [0u8; 26];
    let mut ts = timestamp_ms & ((1u64 << 48) - 1);
    for idx in (0..10).rev() {
        chars[idx] = ULID_ALPHABET[(ts & 0x1F) as usize];
        ts >>= 5;
    }
    let mut rand_val: u128 = 0;
    for byte in randomness {
        rand_val = (rand_val << 8) | byte as u128;
    }
    for idx in (10..26).rev() {
        chars[idx] = ULID_ALPHABET[(rand_val & 0x1F) as usize];
        rand_val >>= 5;
    }
    String::from_utf8(chars.to_vec()).expect("ULID alphabet is valid ASCII")
}

fn generate_ulid() -> String {
    let timestamp = now_millis();
    let mut randomness = [0u8; 10];
    fill_random(&mut randomness);
    encode_ulid(timestamp, randomness)
}

/// Generates UUID-style identifiers across all supported variants (v1-v8, GUID, ULID).
/// Returns a JS map keyed by the variant name so the UI can render every example side by side.
#[wasm_bindgen]
pub fn generate_uuids() -> JsValue {
    let mut map = BTreeMap::new();

    let ts_v1 = timestamp_for_v1();
    map.insert("v1", uuid_crate::Uuid::new_v1(ts_v1, node_id()).to_string());
    map.insert("v2", uuid_v2());
    let name = random_name();
    map.insert(
        "v3",
        uuid_crate::Uuid::new_v3(&uuid_crate::Uuid::NAMESPACE_DNS, &name).to_string(),
    );
    map.insert("v4", uuid_crate::Uuid::new_v4().to_string());
    let name5 = random_name();
    map.insert(
        "v5",
        uuid_crate::Uuid::new_v5(&uuid_crate::Uuid::NAMESPACE_DNS, &name5).to_string(),
    );
    let ts_v6 = timestamp_for_v1();
    map.insert("v6", uuid_crate::Uuid::new_v6(ts_v6, node_id()).to_string());
    let ts_v7 = timestamp_for_v7();
    map.insert("v7", uuid_crate::Uuid::new_v7(ts_v7).to_string());
    map.insert("v8", uuid_v8());
    map.insert("guid", guid_uppercase());
    map.insert("ulid", generate_ulid());

    serde_wasm_bindgen::to_value(&map).unwrap()
}

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct UserAgentEntry {
    user_agent: &'static str,
    browser_name: &'static str,
    browser_version: &'static str,
    os_name: &'static str,
    os_version: &'static str,
    engine_name: &'static str,
    engine_version: &'static str,
}

static USER_AGENTS: &[UserAgentEntry] = &[
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.136 Safari/537.36",
        browser_name: "chrome",
        browser_version: "142.0.7444.136",
        os_name: "windows",
        os_version: "10",
        engine_name: "Blink",
        engine_version: "142.0.7444.136",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.134 Safari/537.36",
        browser_name: "chrome",
        browser_version: "142.0.7444.134",
        os_name: "macos",
        os_version: "13.6.5",
        engine_name: "Blink",
        engine_version: "142.0.7444.134",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.162 Safari/537.36",
        browser_name: "chrome",
        browser_version: "142.0.7444.162",
        os_name: "linux",
        os_version: "x86_64",
        engine_name: "Blink",
        engine_version: "142.0.7444.162",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15",
        browser_name: "safari",
        browser_version: "26.0",
        os_name: "macos",
        os_version: "14.2",
        engine_name: "WebKit",
        engine_version: "605.1.15",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 18_7_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1",
        browser_name: "safari",
        browser_version: "26.0",
        os_name: "ios",
        os_version: "18.7.2",
        engine_name: "WebKit",
        engine_version: "605.1.15",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:145.0) Gecko/20100101 Firefox/145.0",
        browser_name: "firefox",
        browser_version: "145.0",
        os_name: "windows",
        os_version: "10",
        engine_name: "Gecko",
        engine_version: "145.0",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.2; rv:145.0) Gecko/20100101 Firefox/145.0",
        browser_name: "firefox",
        browser_version: "145.0",
        os_name: "macos",
        os_version: "14.2",
        engine_name: "Gecko",
        engine_version: "145.0",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Linux; Android 16; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.7444.139 Mobile Safari/537.36",
        browser_name: "chrome",
        browser_version: "142.0.7444.139",
        os_name: "android",
        os_version: "16",
        engine_name: "Blink",
        engine_version: "142.0.7444.139",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/142.0.3595.80 Safari/537.36",
        browser_name: "edge",
        browser_version: "142.0.3595.80",
        os_name: "windows",
        os_version: "10",
        engine_name: "Blink",
        engine_version: "142.0.3595.80",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2) AppleWebKit/537.36 (KHTML, like Gecko) Edg/142.0.3595.80 Safari/537.36",
        browser_name: "edge",
        browser_version: "142.0.3595.80",
        os_name: "macos",
        os_version: "14.2",
        engine_name: "Blink",
        engine_version: "142.0.3595.80",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Vivaldi/7.6.3797.63 Chrome/142.0.7444.136 Safari/537.36",
        browser_name: "vivaldi",
        browser_version: "7.6.3797.63",
        os_name: "windows",
        os_version: "10",
        engine_name: "Blink",
        engine_version: "142.0.7444.136",
    },
    UserAgentEntry {
        user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) YaBrowser/25.10.0.2516 Chrome/142.0.7444.136 Safari/537.36",
        browser_name: "yandex",
        browser_version: "25.10.0.2516",
        os_name: "windows",
        os_version: "10",
        engine_name: "Blink",
        engine_version: "142.0.7444.136",
    },
];

/// Returns up to ten fixture user-agent strings filtered by browser and OS names (case-insensitive),
/// e.g., `generate_user_agents("chrome", "macos")` yields the latest Chrome-on-macOS entries.
fn filter_user_agents(browser: &str, os: &str) -> Vec<UserAgentEntry> {
    let browser = browser.trim().to_lowercase();
    let os = os.trim().to_lowercase();

    let mut results = Vec::with_capacity(USER_AGENTS.len());
    for entry in USER_AGENTS.iter() {
        if !browser.is_empty() && entry.browser_name != browser {
            continue;
        }
        if !os.is_empty() && entry.os_name != os {
            continue;
        }
        results.push(entry.clone());
        if results.len() == 10 {
            break;
        }
    }
    results
}

#[wasm_bindgen]
pub fn generate_user_agents(browser: &str, os: &str) -> JsValue {
    serde_wasm_bindgen::to_value(&filter_user_agents(browser, os)).unwrap()
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
/// Generates `count` random strings with per-class minimums (digits/upper/lower/symbols),
/// exclusion lists, and optional leading-zero guard—mirrors the "password / random string" UI.
pub fn random_number_sequences(
    length: u32,
    count: u32,
    allow_leading_zero: bool,
    digits: &str,
    include_lowercase: bool,
    include_uppercase: bool,
    symbols: &str,
    exclude_chars: &str,
    min_digits: u32,
    min_lowercase: u32,
    min_uppercase: u32,
    min_symbols: u32,
) -> Result<JsValue, JsValue> {
    random_sequences_internal(
        length,
        count,
        allow_leading_zero,
        digits,
        include_lowercase,
        include_uppercase,
        symbols,
        exclude_chars,
        min_digits,
        min_lowercase,
        min_uppercase,
        min_symbols,
    )
    .and_then(|list| serde_wasm_bindgen::to_value(&list).map_err(|err| err.to_string()))
    .map_err(|err| JsValue::from_str(&err))
}

#[allow(clippy::too_many_arguments)]
fn random_sequences_internal(
    length: u32,
    count: u32,
    allow_leading_zero: bool,
    digits: &str,
    include_lowercase: bool,
    include_uppercase: bool,
    symbols: &str,
    exclude_chars: &str,
    min_digits: u32,
    min_lowercase: u32,
    min_uppercase: u32,
    min_symbols: u32,
) -> Result<Vec<String>, String> {
    if length == 0 {
        return Err("length must be greater than zero".into());
    }
    if length > 2048 {
        return Err("length must be 2048 or less".into());
    }
    if count == 0 {
        return Err("count must be greater than zero".into());
    }
    if count > 256 {
        return Err("count must be 256 or less".into());
    }
    let total_required =
        min_digits as u64 + min_lowercase as u64 + min_uppercase as u64 + min_symbols as u64;
    if total_required > length as u64 {
        return Err("Minimum character counts exceed requested length".into());
    }

    let exclude = sanitize_exclusions(exclude_chars);
    let mut digits_pool = sanitize_digits(digits);
    digits_pool.retain(|ch| !exclude.contains(ch));
    let mut symbols_vec = sanitize_symbols(symbols);
    symbols_vec.retain(|ch| !exclude.contains(ch));

    let lowercase_pool: Vec<char> = if include_lowercase {
        ('a'..='z').filter(|ch| !exclude.contains(ch)).collect()
    } else {
        Vec::new()
    };
    let uppercase_pool: Vec<char> = if include_uppercase {
        ('A'..='Z').filter(|ch| !exclude.contains(ch)).collect()
    } else {
        Vec::new()
    };

    if min_digits > 0 && digits_pool.is_empty() {
        return Err("No digits available to satisfy minimum requirement".into());
    }
    if min_lowercase > 0 && lowercase_pool.is_empty() {
        return Err("No lowercase letters available to satisfy minimum requirement".into());
    }
    if min_uppercase > 0 && uppercase_pool.is_empty() {
        return Err("No uppercase letters available to satisfy minimum requirement".into());
    }
    if min_symbols > 0 && symbols_vec.is_empty() {
        return Err("No symbols available to satisfy minimum requirement".into());
    }

    let mut general_pool = Vec::new();
    general_pool.extend(&digits_pool);
    general_pool.extend(&lowercase_pool);
    general_pool.extend(&uppercase_pool);
    general_pool.extend(&symbols_vec);
    general_pool.sort_unstable();
    general_pool.dedup();

    if general_pool.is_empty() {
        return Err("No available characters to generate values".into());
    }
    if !allow_leading_zero && general_pool.iter().all(|ch| *ch == '0') {
        return Err("No valid leading character available when zero is disallowed".into());
    }

    let mut results = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let mut chars = Vec::with_capacity(length as usize);
        append_required_chars(&mut chars, &digits_pool, min_digits, "digits")?;
        append_required_chars(
            &mut chars,
            &lowercase_pool,
            min_lowercase,
            "lowercase letters",
        )?;
        append_required_chars(
            &mut chars,
            &uppercase_pool,
            min_uppercase,
            "uppercase letters",
        )?;
        append_required_chars(&mut chars, &symbols_vec, min_symbols, "symbols")?;

        while chars.len() < length as usize {
            let ch = random_char_from_pool(&general_pool)?;
            chars.push(ch);
        }
        shuffle_chars(&mut chars);
        if !allow_leading_zero && !chars.is_empty() && chars[0] == '0' {
            if let Some(idx) = chars.iter().position(|ch| *ch != '0') {
                chars.swap(0, idx);
            } else {
                return Err("No valid leading character available when zero is disallowed".into());
            }
        }
        results.push(chars.into_iter().collect());
    }
    Ok(results)
}

fn sanitize_digits(digits: &str) -> Vec<char> {
    let mut out: Vec<char> = digits.chars().filter(|ch| ch.is_ascii_digit()).collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn sanitize_symbols(symbols: &str) -> Vec<char> {
    let mut out: Vec<char> = symbols
        .chars()
        .filter(|ch| !ch.is_alphanumeric() && !ch.is_whitespace())
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn sanitize_exclusions(input: &str) -> HashSet<char> {
    input.chars().filter(|ch| !ch.is_whitespace()).collect()
}

#[wasm_bindgen]
/// Encodes the given text into multiple bases (Base32/64/85/91, hex) and returns a JS map keyed
/// by the encoding name—handy for previewing many encodings from a single input.
pub fn encode_content(input: &str) -> Result<JsValue, JsValue> {
    let map = encode_content_map(input);
    serde_wasm_bindgen::to_value(&map).map_err(|err| JsValue::from_str(&err.to_string()))
}

fn encode_content_map(input: &str) -> BTreeMap<String, String> {
    let data = input.as_bytes();
    let mut map = BTreeMap::new();
    map.insert("base32_standard".into(), BASE32.encode(data));
    map.insert(
        "base32_standard_no_padding".into(),
        BASE32_NOPAD.encode(data),
    );
    map.insert("base32_hex".into(), BASE32HEX.encode(data));
    map.insert("base32_hex_no_padding".into(), BASE32HEX_NOPAD.encode(data));
    map.insert("base64_standard".into(), STANDARD.encode(data));
    map.insert("base64_raw_standard".into(), STANDARD_NO_PAD.encode(data));
    map.insert("base64_url".into(), URL_SAFE.encode(data));
    map.insert("base64_raw_url".into(), URL_SAFE_NO_PAD.encode(data));
    map.insert("base85_ascii85".into(), ascii85_encode(data));
    map.insert("base91".into(), encode_base91(data));
    map.insert("hex_upper".into(), hex::encode_upper(data));
    map
}

#[wasm_bindgen]
/// Parses MySQL `CREATE TABLE` DDL and emits deterministic sample `INSERT` statements,
/// letting the frontend show plausible rows without connecting to a database.
pub fn generate_insert_statements(
    schema: &str,
    rows: u32,
    overrides: JsValue,
) -> Result<String, JsValue> {
    // Mirrors the "SQL Inserts" generator spec: parse MySQL CREATE TABLE
    // statements, then emit deterministic INSERT samples with lorem ipsum
    // strings, realistic numeric ranges, and optional per-column overrides.
    let override_map: TableOverrideMap = if overrides.is_undefined() || overrides.is_null() {
        BTreeMap::new()
    } else {
        serde_wasm_bindgen::from_value(overrides)
            .map_err(|err| JsValue::from_str(&err.to_string()))?
    };
    generate_insert_statements_internal(schema, rows, override_map)
        .map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
/// Parses MySQL DDL and returns column-level metadata (type, default, enum values, min/max)
/// so the UI can surface validation hints next to each field.
pub fn inspect_schema(schema: &str) -> Result<JsValue, JsValue> {
    let tables = parse_mysql_tables(schema);
    let inspections: Vec<TableInspection> = tables
        .iter()
        .map(|table| TableInspection {
            name: table.name.clone(),
            columns: table
                .columns
                .iter()
                .map(|column| {
                    let limits = column_numeric_limits(column);
                    ColumnInspection {
                        name: column.name.clone(),
                        data_type: column.data_type.clone(),
                        kind: classify_column_kind(column).to_string(),
                        default_value: column_default_display(column),
                        min_value: limits.clone().map(|(min, _)| min),
                        max_value: limits.map(|(_, max)| max),
                        enum_values: if column.enum_values.is_empty() {
                            None
                        } else {
                            Some(column.enum_values.clone())
                        },
                    }
                })
                .collect(),
        })
        .collect();
    serde_wasm_bindgen::to_value(&inspections).map_err(|err| JsValue::from_str(&err.to_string()))
}

fn generate_insert_statements_internal(
    schema: &str,
    rows: u32,
    overrides: TableOverrideMap,
) -> Result<String, String> {
    // We only need a handful of example rows, so bounds-check early to avoid
    // accidentally allocating massive buffers when a user pastes an odd value.
    if rows == 0 {
        return Err("Row count must be greater than zero".into());
    }
    if rows > 100 {
        return Err("Row count must be 100 or less".into());
    }
    let tables = parse_mysql_tables(schema);
    if tables.is_empty() {
        return Err("No CREATE TABLE statements detected".into());
    }
    let mut statements = Vec::new();
    for table in tables {
        if table.columns.is_empty() {
            continue;
        }
        let table_override = overrides.get(&table.name);
        let included_columns: Vec<&ColumnSchema> = table
            .columns
            .iter()
            .filter(|col| {
                !table_override
                    .and_then(|cols| cols.get(&col.name))
                    .map(|cfg| cfg.exclude)
                    .unwrap_or(false)
            })
            .collect();
        if included_columns.is_empty() {
            continue;
        }
        let header = included_columns
            .iter()
            .map(|col| format!("`{}`", col.name))
            .collect::<Vec<_>>()
            .join(", ");
        // Pre-build stringified rows so we can join them with the SQL-friendly
        // layout that mirrors the original Go tool.
        let mut rows_buf = Vec::new();
        for idx in 0..rows as usize {
            let values = included_columns
                .iter()
                .map(|col| {
                    let override_cfg = table_override.and_then(|cols| cols.get(&col.name));
                    sample_value(col, idx, override_cfg)
                })
                .collect::<Vec<_>>()
                .join(", ");
            rows_buf.push(format!("({})", values));
        }
        let statement = format!(
            "INSERT INTO `{}` ({}) VALUES
  {};",
            table.name,
            header,
            rows_buf.join(
                ",
  "
            )
        );
        statements.push(statement);
    }
    if statements.is_empty() {
        return Err("No usable columns found in schema".into());
    }
    Ok(statements.join(
        "

",
    ))
}

#[derive(Debug, Clone)]
struct TableSchema {
    // Canonical table name extracted from the `CREATE TABLE` definition.
    name: String,
    // Raw column list in declaration order. We keep the order so the emitted
    // INSERT statement matches what users expect to see in the UI.
    columns: Vec<ColumnSchema>,
}

#[derive(Debug, Clone)]
struct ColumnSchema {
    name: String,
    data_type: String,
    // Lower-cased type keyword without length modifiers. Helps us map to
    // sampling strategies without needing a full SQL parser.
    base_type: String,
    unsigned: bool,
    length: Option<usize>,
    scale: Option<u32>,
    enum_values: Vec<String>,
    default_value: Option<ColumnDefault>,
}

#[derive(Debug, Clone)]
enum ColumnDefault {
    Null,
    Literal(String),
    Numeric(String),
    CurrentTimestamp,
    UnixTimestamp,
}

#[derive(Debug, Default, Deserialize, Clone)]
struct ColumnOverride {
    min: Option<f64>,
    max: Option<f64>,
    allowed: Option<Vec<f64>>,
    #[serde(default)]
    exclude: bool,
}

type TableOverrideMap = BTreeMap<String, BTreeMap<String, ColumnOverride>>;

#[derive(Serialize)]
struct TableInspection {
    name: String,
    columns: Vec<ColumnInspection>,
}

#[derive(Serialize)]
struct ColumnInspection {
    name: String,
    data_type: String,
    kind: String,
    default_value: Option<String>,
    min_value: Option<String>,
    max_value: Option<String>,
    enum_values: Option<Vec<String>>,
}

fn table_regex() -> &'static Regex {
    TABLE_REGEX.get_or_init(|| {
        Regex::new(r#"(?i)create\s+table\s+(?:if\s+not\s+exists\s+)?[`"\[]?([a-zA-Z0-9_]+)[`"\]]?"#)
            .expect("create table regex")
    })
}

fn column_regex() -> &'static Regex {
    COLUMN_REGEX.get_or_init(|| {
        Regex::new(r#"(?i)^\s*[`"\[]?([a-zA-Z0-9_]+)[`"\]]?\s+([a-zA-Z0-9]+(?:\s*\([^)]*\))?)"#)
            .expect("column regex")
    })
}

fn parse_mysql_tables(schema: &str) -> Vec<TableSchema> {
    // This is intentionally permissive: we only need the column metadata, so
    // a couple of focused regexes are enough and avoid pulling a SQL parser
    // into Wasm.
    let regex = table_regex();
    let mut tables = Vec::new();
    for caps in regex.captures_iter(schema) {
        let matched = caps.get(0).unwrap();
        let name = caps.get(1).map(|m| m.as_str()).unwrap_or("table");
        let after = matched.end();
        let relative_open = schema[after..].find('(');
        let open_idx = match relative_open {
            Some(pos) => after + pos,
            None => continue,
        };
        if let Some(close_idx) = find_matching_paren(schema, open_idx) {
            let body = &schema[open_idx + 1..close_idx];
            let columns = parse_column_definitions(body);
            if !columns.is_empty() {
                tables.push(TableSchema {
                    name: name
                        .trim_matches(|ch| matches!(ch, '`' | '"' | '[' | ']'))
                        .to_string(),
                    columns,
                });
            }
        }
    }
    tables
}

fn parse_column_definitions(body: &str) -> Vec<ColumnSchema> {
    let column_re = column_regex();
    let mut columns = Vec::new();
    for raw in body.lines() {
        if let Some(column) = parse_column_line(raw.trim(), column_re) {
            columns.push(column);
        }
    }
    columns
}

fn parse_column_line(line: &str, column_re: &Regex) -> Option<ColumnSchema> {
    if line.is_empty() {
        return None;
    }
    let trimmed = line.trim_end_matches(',');
    let lowered = trimmed.to_lowercase();
    if lowered.starts_with("primary ")
        || lowered.starts_with("unique ")
        || lowered.starts_with("constraint ")
        || lowered.starts_with("key ")
        || lowered.starts_with("index ")
        || lowered.starts_with("foreign ")
    {
        // Skip secondary indexes—only physical columns get INSERT values.
        return None;
    }
    let caps = column_re.captures(trimmed)?;
    let name = caps
        .get(1)
        .unwrap()
        .as_str()
        .trim_matches(|ch| matches!(ch, '`' | '"' | '[' | ']'))
        .to_string();
    let type_segment = caps.get(2).map(|m| m.as_str()).unwrap_or("");
    let base_type = detect_base_type(type_segment);
    let (length, scale) = parse_length_and_scale(type_segment);
    let enum_values = if base_type == "enum" || base_type == "set" {
        parse_enum_values(type_segment)
    } else {
        Vec::new()
    };
    let default_value = parse_default_clause(trimmed);
    let unsigned = trimmed.to_lowercase().contains(" unsigned");
    Some(ColumnSchema {
        name,
        data_type: type_segment.to_string(),
        base_type,
        unsigned,
        length,
        scale,
        enum_values,
        default_value,
    })
}

fn parse_length_and_scale(data_type: &str) -> (Option<usize>, Option<u32>) {
    if let Some(start) = data_type.find('(') {
        if let Some(end) = data_type[start + 1..].find(')') {
            let inner = &data_type[start + 1..start + 1 + end];
            let mut parts = inner.split(',');
            let len = parts.next().and_then(|v| v.trim().parse::<usize>().ok());
            let scale = parts.next().and_then(|v| v.trim().parse::<u32>().ok());
            return (len, scale);
        }
    }
    (None, None)
}

fn detect_base_type(data_type: &str) -> String {
    data_type
        .split(|ch: char| ch == '(' || ch.is_whitespace())
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

fn parse_default_clause(line: &str) -> Option<ColumnDefault> {
    let lower = line.to_lowercase();
    let needle = " default ";
    let pos = lower.find(needle)?;
    let start = pos + needle.len();
    let remainder = line[start..].trim_start();
    if remainder.is_empty() {
        return None;
    }
    if let Some(stripped) = remainder.strip_prefix('\'') {
        let (literal, _) = parse_quoted_literal(stripped, '\'');
        let value = literal.replace("''", "'");
        return Some(ColumnDefault::Literal(value));
    }
    if let Some(stripped) = remainder.strip_prefix('"') {
        let (literal, _) = parse_quoted_literal(stripped, '"');
        return Some(ColumnDefault::Literal(literal));
    }
    let token = remainder
        .split(|ch: char| ch.is_whitespace() || ch == ',')
        .next()
        .unwrap_or("")
        .trim();
    if token.is_empty() {
        return None;
    }
    match token.to_ascii_lowercase().as_str() {
        "null" => Some(ColumnDefault::Null),
        "current_timestamp" | "current_timestamp()" => Some(ColumnDefault::CurrentTimestamp),
        "unix_timestamp" | "unix_timestamp()" => Some(ColumnDefault::UnixTimestamp),
        _ => {
            if token
                .chars()
                .all(|ch| ch.is_ascii_digit() || ch == '.' || ch == '-')
            {
                Some(ColumnDefault::Numeric(token.to_string()))
            } else {
                Some(ColumnDefault::Literal(
                    token.trim_matches('"').trim_matches('\'').to_string(),
                ))
            }
        }
    }
}

fn parse_quoted_literal(input: &str, quote: char) -> (String, usize) {
    let mut result = String::new();
    let mut chars = input.chars().peekable();
    let mut consumed = 0;
    while let Some(ch) = chars.next() {
        consumed += ch.len_utf8();
        if ch == quote {
            if matches!(chars.peek(), Some(next) if *next == quote) {
                chars.next();
                consumed += quote.len_utf8();
                result.push(quote);
                continue;
            }
            break;
        }
        result.push(ch);
    }
    (result, consumed)
}

fn parse_enum_values(definition: &str) -> Vec<String> {
    let start = definition.find('(');
    let end = definition.rfind(')');
    if let (Some(start), Some(end)) = (start, end) {
        if end <= start {
            return Vec::new();
        }
        let inner = &definition[start + 1..end];
        let mut values = Vec::new();
        let mut current = String::new();
        let mut chars = inner.chars().peekable();
        let mut in_value = false;
        while let Some(ch) = chars.next() {
            match ch {
                '\'' => {
                    if in_value {
                        if matches!(chars.peek(), Some('\'')) {
                            chars.next();
                            current.push('\'');
                        } else {
                            values.push(current.clone());
                            current.clear();
                            in_value = false;
                        }
                    } else {
                        in_value = true;
                    }
                }
                ',' => {
                    if in_value {
                        current.push(ch);
                    }
                }
                _ => {
                    if in_value {
                        current.push(ch);
                    }
                }
            }
        }
        if in_value && !current.is_empty() {
            values.push(current);
        }
        values
    } else {
        Vec::new()
    }
}

fn column_default_display(column: &ColumnSchema) -> Option<String> {
    column.default_value.as_ref().map(render_default)
}

fn column_numeric_limits(column: &ColumnSchema) -> Option<(String, String)> {
    match column.base_type.as_str() {
        base if base.contains("int") || base == "serial" || base == "year" || base == "bit" => {
            let (min, max) = integer_bounds(column)?;
            Some((min.to_string(), max.to_string()))
        }
        base if base == "decimal" || base == "numeric" => {
            let (min, max) = decimal_limits(column);
            Some((
                format_decimal(min, column.scale.unwrap_or(2)),
                format_decimal(max, column.scale.unwrap_or(2)),
            ))
        }
        base if base == "float" || base == "double" || base == "real" => {
            Some(("-1000000".into(), "1000000".into()))
        }
        "bool" | "boolean" => Some(("0".into(), "1".into())),
        _ => None,
    }
}

fn classify_column_kind(column: &ColumnSchema) -> &'static str {
    match column.base_type.as_str() {
        base if base.contains("int") || base == "serial" || base == "year" || base == "bit" => {
            "integer"
        }
        base if base == "decimal" || base == "numeric" => "decimal",
        base if base == "float" || base == "double" || base == "real" => "float",
        "bool" | "boolean" => "boolean",
        "date" | "datetime" | "timestamp" | "time" => "datetime",
        "enum" => "enum",
        "set" => "set",
        base if base.contains("blob") || base.contains("binary") => "binary",
        _ => "string",
    }
}

fn sample_value(
    column: &ColumnSchema,
    row_idx: usize,
    override_cfg: Option<&ColumnOverride>,
) -> String {
    if let Some(prefilled) = column_default_value(column, override_cfg) {
        return prefilled;
    }
    match column.base_type.as_str() {
        base if base.contains("int") || base == "serial" || base == "year" || base == "bit" => {
            sample_integer_value(column, override_cfg)
        }
        base if base == "decimal" || base == "numeric" => {
            sample_decimal_value(column, override_cfg)
        }
        base if base == "float" || base == "double" || base == "real" => {
            sample_float_value(column, override_cfg)
        }
        "bool" | "boolean" => sample_integer_value(column, override_cfg),
        "date" => escape_sql_string(&format!("2025-01-{day:02}", day = row_idx % 28 + 1)),
        "datetime" | "timestamp" => escape_sql_string(&format!(
            "2025-01-{day:02} {hour:02}:{minute:02}:00",
            day = row_idx % 28 + 1,
            hour = (row_idx * 3) % 24,
            minute = (row_idx * 7) % 60
        )),
        "time" => escape_sql_string(&format!(
            "{hour:02}:{minute:02}:{second:02}",
            hour = (row_idx * 3) % 24,
            minute = (row_idx * 7) % 60,
            second = (row_idx * 11) % 60
        )),
        "enum" => {
            if column.enum_values.is_empty() {
                sample_text_value(column)
            } else {
                let idx = random_index(column.enum_values.len());
                escape_sql_string(&column.enum_values[idx])
            }
        }
        "set" => {
            if column.enum_values.is_empty() {
                sample_text_value(column)
            } else {
                let take = ((row_idx % column.enum_values.len()) + 1).min(column.enum_values.len());
                let combined = column
                    .enum_values
                    .iter()
                    .take(take)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(",");
                escape_sql_string(&combined)
            }
        }
        "json" => escape_sql_string(&format!(r#"{{"{}": {}}}"#, column.name, row_idx + 1)),
        base if base.contains("blob") || base.contains("binary") => {
            let first = ((row_idx + 65) % 256) as u8;
            let second = ((row_idx + 97) % 256) as u8;
            format!("X'{:02X}{:02X}'", first, second)
        }
        _ => sample_text_value(column),
    }
}

fn column_default_value(
    column: &ColumnSchema,
    override_cfg: Option<&ColumnOverride>,
) -> Option<String> {
    // User overrides always win; otherwise fall back to SQL defaults when they
    // carry actual information (e.g., CURRENT_TIMESTAMP) so our output matches
    // production schemas more closely.
    if override_cfg.is_some() {
        return None;
    }
    let default = column.default_value.as_ref()?;
    if is_textual_column(column) {
        match default {
            ColumnDefault::Null => return None,
            ColumnDefault::Literal(value) if value.trim().is_empty() => return None,
            _ => {}
        }
    }
    Some(render_default(default))
}

fn is_textual_column(column: &ColumnSchema) -> bool {
    let ty = column.base_type.as_str();
    // Covers MySQL string-ish types that benefit from lorem ipsum content.
    ty.contains("char")
        || ty.contains("text")
        || ty == "json"
        || ty == "uuid"
        || ty == "enum"
        || ty == "set"
}

fn sample_integer_value(column: &ColumnSchema, override_cfg: Option<&ColumnOverride>) -> String {
    let (mut min, mut max) = integer_bounds(column).unwrap_or((0, 1));
    if let Some(override_cfg) = override_cfg {
        if let Some(value) = override_cfg.min {
            min = value.floor() as i128;
        }
        if let Some(value) = override_cfg.max {
            max = value.floor() as i128;
        }
        if let Some(list) = override_cfg.allowed.as_ref() {
            if !list.is_empty() {
                let idx = random_index(list.len());
                let value = list[idx].round() as i128;
                return value.to_string();
            }
        }
    }
    if max < min {
        std::mem::swap(&mut min, &mut max);
    }
    random_integer_in_range(min, max).to_string()
}

fn sample_decimal_value(column: &ColumnSchema, override_cfg: Option<&ColumnOverride>) -> String {
    let (mut min, mut max) = decimal_limits(column);
    if let Some(override_cfg) = override_cfg {
        if let Some(value) = override_cfg.min {
            min = value;
        }
        if let Some(value) = override_cfg.max {
            max = value;
        }
        if let Some(list) = override_cfg.allowed.as_ref() {
            if !list.is_empty() {
                let idx = random_index(list.len());
                return format_decimal(list[idx], column.scale.unwrap_or(2));
            }
        }
    }
    if max < min {
        std::mem::swap(&mut min, &mut max);
    }
    let value = random_decimal_value(min, max);
    format_decimal(value, column.scale.unwrap_or(2))
}

fn sample_float_value(column: &ColumnSchema, override_cfg: Option<&ColumnOverride>) -> String {
    let (mut min, mut max) = (-1_000_000.0, 1_000_000.0);
    let precision = column.scale.unwrap_or(4).min(10);
    if let Some(override_cfg) = override_cfg {
        if let Some(value) = override_cfg.min {
            min = value;
        }
        if let Some(value) = override_cfg.max {
            max = value;
        }
        if let Some(list) = override_cfg.allowed.as_ref() {
            if !list.is_empty() {
                let idx = random_index(list.len());
                return format!("{:.*}", precision as usize, list[idx]);
            }
        }
    }
    if max < min {
        std::mem::swap(&mut min, &mut max);
    }
    let value = random_decimal_value(min, max);
    format!("{:.*}", precision as usize, value)
}

fn integer_bounds(column: &ColumnSchema) -> Option<(i128, i128)> {
    let unsigned = column.unsigned;
    match column.base_type.as_str() {
        "tinyint" => Some(if unsigned { (0, 255) } else { (-128, 127) }),
        "smallint" => Some(if unsigned {
            (0, 65_535)
        } else {
            (-32_768, 32_767)
        }),
        "mediumint" => Some(if unsigned {
            (0, 16_777_215)
        } else {
            (-8_388_608, 8_388_607)
        }),
        "int" | "integer" => Some(if unsigned {
            (0, 4_294_967_295)
        } else {
            (-2_147_483_648, 2_147_483_647)
        }),
        "bigint" => Some(if unsigned {
            (0, 18_446_744_073_709_551_615)
        } else {
            (-9_223_372_036_854_775_808, 9_223_372_036_854_775_807)
        }),
        "year" => Some((1901, 2155)),
        "bit" | "bool" | "boolean" => Some((0, 1)),
        _ => None,
    }
}

fn decimal_limits(column: &ColumnSchema) -> (f64, f64) {
    if let Some(precision) = column.length {
        let scale = column.scale.unwrap_or(0) as i32;
        let integer_digits = precision.saturating_sub(column.scale.unwrap_or(0) as usize);
        let max_integer = 10f64.powi(integer_digits as i32) - 1.0;
        let fractional = if scale > 0 {
            1.0 - 10f64.powi(-scale)
        } else {
            0.0
        };
        let max = max_integer + fractional;
        return (-max, max);
    }
    (-1_000_000.0, 1_000_000.0)
}

fn format_decimal(value: f64, scale: u32) -> String {
    if scale == 0 {
        format!("{:.0}", value)
    } else {
        format!("{:.*}", scale as usize, value)
    }
}

fn random_integer_in_range(min: i128, max: i128) -> i128 {
    if min >= max {
        return min;
    }
    let span = (max - min + 1) as u128;
    let threshold = u128::MAX - (u128::MAX % span);
    loop {
        let mut buf = [0u8; 16];
        fill_random(&mut buf);
        let sample = u128::from_le_bytes(buf);
        if sample < threshold {
            return min + (sample % span) as i128;
        }
    }
}

fn random_decimal_value(min: f64, max: f64) -> f64 {
    if min >= max {
        return min;
    }
    let mut buf = [0u8; 8];
    fill_random(&mut buf);
    let sample = u64::from_le_bytes(buf);
    let unit = (sample as f64) / (u64::MAX as f64);
    min + (max - min) * unit
}

fn render_default(default: &ColumnDefault) -> String {
    match default {
        ColumnDefault::Null => "NULL".into(),
        ColumnDefault::Literal(value) => escape_sql_string(value),
        ColumnDefault::Numeric(value) => value.clone(),
        ColumnDefault::CurrentTimestamp => escape_sql_string(&now_timestamp_string()),
        ColumnDefault::UnixTimestamp => unix_timestamp_value(),
    }
}

fn now_timestamp_string() -> String {
    let date = Date::new_0();
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        date.get_utc_full_year(),
        date.get_utc_month() + 1,
        date.get_utc_date(),
        date.get_utc_hours(),
        date.get_utc_minutes(),
        date.get_utc_seconds()
    )
}

fn unix_timestamp_value() -> String {
    let seconds = (Date::now() / 1000.0).floor() as i64;
    seconds.to_string()
}

fn sample_text_value(column: &ColumnSchema) -> String {
    let max_len = column.length.unwrap_or(32).clamp(1, 256);
    let mut value = lorem_text(max_len);
    if value.len() > max_len {
        value.truncate(max_len);
    }
    escape_sql_string(&value)
}

fn lorem_text(max_len: usize) -> String {
    if max_len == 0 {
        return String::new();
    }
    // We use a deterministic-ish lorem word bag so results are readable yet
    // still look random when rendered in the UI.
    let mut out = String::new();
    while out.len() < max_len {
        if !out.is_empty() {
            out.push(' ');
        }
        let idx = random_index(LOREM_WORDS.len());
        out.push_str(LOREM_WORDS[idx]);
    }
    out
}

fn escape_sql_string(value: &str) -> String {
    let escaped = value.replace('\'', "''");
    format!("'{}'", escaped)
}

#[derive(Serialize, Debug)]
struct TotpResponse {
    code: String,
    period: u32,
    remaining: u32,
    algorithm: String,
    timestamp_seconds: String,
}

#[wasm_bindgen]
/// Computes a TOTP value following RFC 6238 for the supplied Base32 secret and parameters.
/// Example: `totp_token("JBSWY3DPEHPK3PXP", "SHA256", 30, 6)` returns a code plus metadata.
pub fn totp_token(
    secret: &str,
    algorithm: &str,
    period: u32,
    digits: u32,
) -> Result<JsValue, JsValue> {
    // Implements RFC 6238 (TOTP). The frontend exposes SHA1/SHA256/SHA512 per
    // the requirement list, so we keep the API narrow and deterministic.
    totp_token_internal(secret, algorithm, period, digits)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

/// Computes a TOTP code for a Base32 secret.
///
/// Whitespace in the input is ignored, so both `6BDRT7ATRRCZV5ISFLOHAHQLYF4ZORG7`
/// and `6BDR T7AT RRCZ V5IS FLOH AHQL YF4Z ORG7` map to the same key. The
/// `algorithm` parameter accepts `SHA1`, `SHA256` (preferred), or `SHA512`. Both
/// the `period` (seconds) and number of digits follow the UI inputs.
fn totp_token_internal(
    secret: &str,
    algorithm: &str,
    period: u32,
    digits: u32,
) -> Result<TotpResponse, String> {
    let trimmed = secret.trim();
    if trimmed.is_empty() {
        return Err("secret cannot be empty".into());
    }
    if !(1..=300).contains(&period) {
        return Err("period must be between 1 and 300".into());
    }
    if !(4..=10).contains(&digits) {
        return Err("digits must be between 4 and 10".into());
    }
    let key = decode_totp_secret(trimmed)?;
    if key.is_empty() {
        return Err("secret cannot be empty".into());
    }
    let seconds = (Date::now() / 1000.0).floor() as u64;
    let period64 = period as u64;
    let counter = seconds / period64;
    let mut remaining = period64 - (seconds % period64);
    if remaining == 0 {
        remaining = period64;
    }
    let algorithm_normalized = algorithm.trim().to_ascii_lowercase();
    let digest = match algorithm_normalized.as_str() {
        "sha1" => hmac_digest::<Hmac<Sha1>>(&key, counter)?,
        "sha256" => hmac_digest::<Hmac<Sha256>>(&key, counter)?,
        "sha512" => hmac_digest::<Hmac<Sha512>>(&key, counter)?,
        _ => return Err("unsupported algorithm".into()),
    };
    let truncated = dynamic_truncate(&digest);
    let modulus = 10u64.pow(digits);
    let otp_value = truncated as u64 % modulus;
    let code = format!("{:0width$}", otp_value, width = digits as usize);
    Ok(TotpResponse {
        code,
        period,
        remaining: remaining as u32,
        algorithm: algorithm_normalized.to_uppercase(),
        timestamp_seconds: seconds.to_string(),
    })
}

fn decode_totp_secret(secret: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = secret
        .chars()
        .filter(|ch| !ch.is_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if cleaned.is_empty() {
        return Err("secret cannot be empty".into());
    }
    BASE32
        .decode(cleaned.as_bytes())
        .map_err(|err| err.to_string())
}

fn hmac_digest<M>(key: &[u8], counter: u64) -> Result<Vec<u8>, String>
where
    M: Mac + KeyInit,
{
    let mut mac = <M as KeyInit>::new_from_slice(key).map_err(|_| "invalid secret".to_string())?;
    mac.update(&counter.to_be_bytes());
    Ok(mac.finalize().into_bytes().to_vec())
}

fn dynamic_truncate(payload: &[u8]) -> u32 {
    if payload.len() < 4 {
        return 0;
    }
    let offset = (payload[payload.len() - 1] & 0xf) as usize;
    if offset + 4 > payload.len() {
        return 0;
    }
    let slice = &payload[offset..offset + 4];
    ((slice[0] as u32 & 0x7f) << 24)
        | ((slice[1] as u32) << 16)
        | ((slice[2] as u32) << 8)
        | slice[3] as u32
}

#[wasm_bindgen]
/// Decodes a text payload using the specified format (Base32/64/85/91 or hex) and returns UTF-8 text.
/// On failure the error message matches the variant, making it easier to surface in the UI.
pub fn decode_content(kind: &str, input: &str) -> Result<String, JsValue> {
    decode_content_internal(kind, input)
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
        .map_err(|err| JsValue::from_str(&err))
}

fn decode_content_internal(kind: &str, input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    match kind {
        "base32_standard" => BASE32
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base32_standard_no_padding" => BASE32_NOPAD
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base32_hex" => BASE32HEX
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base32_hex_no_padding" => BASE32HEX_NOPAD
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base64_standard" => STANDARD
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base64_raw_standard" => STANDARD_NO_PAD
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base64_url" => URL_SAFE
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base64_raw_url" => URL_SAFE_NO_PAD
            .decode(trimmed.as_bytes())
            .map_err(|err| err.to_string()),
        "base85_ascii85" => ascii85_decode(trimmed).map_err(|err| err.to_string()),
        "base91" => decode_base91(trimmed),
        "hex_upper" => hex::decode(trimmed).map_err(|err| err.to_string()),
        other => Err(format!("unsupported decode type {}", other)),
    }
}

#[wasm_bindgen]
/// Hashes input bytes with common digests (MD5, SHA1/2/3, CRC32/64, FNV, Adler) and
/// returns a JS map keyed by algorithm name so callers can render many digests at once.
pub fn hash_content(input: &str) -> Result<JsValue, JsValue> {
    let map = hash_content_map(input.as_bytes());
    serde_wasm_bindgen::to_value(&map).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
/// Computes HMAC digests (SHA1/2/3 families) for the provided key+message and
/// returns them as a JS map, keeping the UI preview in sync with the plain-hash output.
pub fn hash_content_hmac(input: &str, key: &str) -> Result<JsValue, JsValue> {
    let map = hash_hmac_map(input.as_bytes(), key.as_bytes());
    serde_wasm_bindgen::to_value(&map).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
/// Produces a bcrypt hash with an optional pre-specified salt; errors if the cost is outside 4-31.
/// Example: providing your own 22-char bcrypt-base64 salt keeps results reproducible in tests.
pub fn bcrypt_hash(password: &str, cost: u32, salt_b64: Option<String>) -> Result<String, JsValue> {
    if !(4..=31).contains(&cost) {
        return Err(JsValue::from_str("cost must be between 4 and 31"));
    }
    let salt_bytes = match salt_b64 {
        Some(s) if !s.trim().is_empty() => decode_bcrypt_salt(&s)
            .map_err(|err| JsValue::from_str(&format!("invalid bcrypt salt: {}", err)))?,
        _ => {
            let mut buf = [0u8; 16];
            fill_random(&mut buf);
            buf
        }
    };
    bcrypt_hash_with_salt(password, cost, salt_bytes)
        .map(|parts| parts.format_for_version(bcrypt::Version::TwoB))
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
/// Verifies a plaintext password against a bcrypt hash, returning `true` on success without panics.
pub fn bcrypt_verify(password: &str, hash: &str) -> Result<bool, JsValue> {
    bcrypt_verify_fn(password, hash).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
/// Hashes a password with Argon2 (i/d/id) using caller-supplied parameters; generates a random salt
/// when one is not provided and returns the encoded PHC string ready for verification elsewhere.
pub fn argon2_hash(
    password: &str,
    salt_b64: Option<String>,
    time_cost: u32,
    memory_kib: u32,
    parallelism: u32,
    hash_len: u32,
    variant: &str,
) -> Result<String, JsValue> {
    let salt_bytes = match salt_b64 {
        Some(val) => decode_b64(&val).map_err(|err| JsValue::from_str(&err))?,
        None => random_bytes(16),
    };
    let salt =
        SaltString::encode_b64(&salt_bytes).map_err(|err| JsValue::from_str(&err.to_string()))?;

    let algorithm = match variant.to_lowercase().as_str() {
        "argon2i" => ArgonAlgorithm::Argon2i,
        "argon2d" => ArgonAlgorithm::Argon2d,
        _ => ArgonAlgorithm::Argon2id,
    };

    let params = argon2::Params::new(memory_kib, time_cost, parallelism, Some(hash_len as usize))
        .map_err(|err| JsValue::from_str(&err.to_string()))?;

    let argon2 = Argon2::new(algorithm, ArgonVersion::V0x13, params);
    argon2
        .hash_password(password.as_bytes(), &salt)
        .map(|ph| ph.to_string())
        .map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
/// Verifies a password against an Argon2 PHC string, returning `false` for mismatches
/// and bubbling up malformed encodings as JavaScript errors for clearer UI messaging.
pub fn argon2_verify(password: &str, encoded: &str) -> Result<bool, JsValue> {
    let hash = PasswordHash::new(encoded).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let algorithm = match hash.algorithm.as_str() {
        "argon2i" => ArgonAlgorithm::Argon2i,
        "argon2d" => ArgonAlgorithm::Argon2d,
        _ => ArgonAlgorithm::Argon2id,
    };
    let params =
        argon2::Params::try_from(&hash).map_err(|err| JsValue::from_str(&err.to_string()))?;
    let argon2 = Argon2::new(algorithm, ArgonVersion::V0x13, params);
    argon2
        .verify_password(password.as_bytes(), &hash)
        .map(|_| true)
        .or_else(|err| match err {
            password_hash::Error::Password => Ok(false),
            other => Err(JsValue::from_str(&other.to_string())),
        })
}

#[wasm_bindgen]
/// Converts between structured-text formats (JSON, YAML, TOML, XML, etc.) using the shared
/// `convert` helpers so the web UI can provide format-to-format transforms in one call.
pub fn transform_format(from: &str, to: &str, input: &str) -> Result<String, JsValue> {
    convert::convert_formats(from, to, input).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
/// Formats or minifies structured content (JSON, XML, YAML, TOML) while preserving semantics,
/// mirroring the "Prettify / Minify" buttons in the UI.
pub fn format_content_text(format: &str, input: &str, minify: bool) -> Result<String, JsValue> {
    convert::format_content(format, input, minify).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
/// Converts Markdown to HTML using the same rules as the web playground so previews
/// look identical between Rust tests and the browser.
pub fn markdown_to_html_text(input: &str) -> Result<String, JsValue> {
    convert::markdown::markdown_to_html(input).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
/// Converts HTML snippets back into Markdown, enabling round-trip formatting checks in tests/UI.
pub fn html_to_markdown_text(input: &str) -> Result<String, JsValue> {
    convert::markdown::html_to_markdown(input).map_err(|err| JsValue::from_str(&err))
}

fn hash_content_map(data: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    map.insert("md5".into(), hex::encode(Md5::digest(data)));
    map.insert("sha1".into(), hex::encode(Sha1::digest(data)));
    map.insert("sha224".into(), hex::encode(Sha224::digest(data)));
    map.insert("sha256".into(), hex::encode(Sha256::digest(data)));
    map.insert("sha384".into(), hex::encode(Sha384::digest(data)));
    map.insert("sha512".into(), hex::encode(Sha512::digest(data)));
    map.insert("sha512_224".into(), hex::encode(Sha512_224::digest(data)));
    map.insert("sha512_256".into(), hex::encode(Sha512_256::digest(data)));
    map.insert("sha3_224".into(), hex::encode(Sha3_224::digest(data)));
    map.insert("sha3_256".into(), hex::encode(Sha3_256::digest(data)));
    map.insert("sha3_384".into(), hex::encode(Sha3_384::digest(data)));
    map.insert("sha3_512".into(), hex::encode(Sha3_512::digest(data)));

    let crc32_value = crc32fast::hash(data);
    map.insert("crc32_ieee".into(), format!("{:08x}", crc32_value));
    let crc32_castagnoli = Crc::<u32>::new(&CRC_32_ISCSI);
    map.insert(
        "crc32_castagnoli".into(),
        format!("{:08x}", crc32_castagnoli.checksum(data)),
    );
    let crc64_iso = Crc::<u64>::new(&CRC_64_GO_ISO);
    map.insert(
        "crc64_iso".into(),
        format!("{:016x}", crc64_iso.checksum(data)),
    );
    let crc64_ecma = Crc::<u64>::new(&CRC_64_ECMA_182);
    map.insert(
        "crc64_ecma".into(),
        format!("{:016x}", crc64_ecma.checksum(data)),
    );

    let mut adler = Adler32::new();
    adler.write_slice(data);
    map.insert("adler32".into(), format!("{:08x}", adler.checksum()));

    map.insert("fnv32".into(), format!("{:08x}", fnv1_32(data)));
    map.insert("fnv32a".into(), format!("{:08x}", fnv1a_32(data)));
    map.insert("fnv64".into(), format!("{:016x}", fnv1_64(data)));
    map.insert("fnv64a".into(), format!("{:016x}", fnv1a_64(data)));
    map.insert("fnv128".into(), format!("{:032x}", fnv1_128(data)));
    map.insert("fnv128a".into(), format!("{:032x}", fnv1a_128(data)));

    map
}

fn hash_hmac_map(data: &[u8], key: &[u8]) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();

    map.insert("sha1".into(), hmac_hex_generic::<Hmac<Sha1>>(key, data));
    map.insert("sha224".into(), hmac_hex_generic::<Hmac<Sha224>>(key, data));
    map.insert("sha256".into(), hmac_hex_generic::<Hmac<Sha256>>(key, data));
    map.insert("sha384".into(), hmac_hex_generic::<Hmac<Sha384>>(key, data));
    map.insert("sha512".into(), hmac_hex_generic::<Hmac<Sha512>>(key, data));
    map.insert(
        "sha3_224".into(),
        hmac_hex_generic::<Hmac<Sha3_224>>(key, data),
    );
    map.insert(
        "sha3_256".into(),
        hmac_hex_generic::<Hmac<Sha3_256>>(key, data),
    );
    map.insert(
        "sha3_384".into(),
        hmac_hex_generic::<Hmac<Sha3_384>>(key, data),
    );
    map.insert(
        "sha3_512".into(),
        hmac_hex_generic::<Hmac<Sha3_512>>(key, data),
    );

    map
}

fn hmac_hex_generic<M>(key: &[u8], data: &[u8]) -> String
where
    M: Mac + KeyInit,
{
    let mut mac: M = <M as KeyInit>::new_from_slice(key)
        .unwrap_or_else(|_| <M as KeyInit>::new_from_slice(b"").unwrap());
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

#[derive(Serialize, Default)]
struct NumberBases {
    binary: String,
    octal: String,
    decimal: String,
    hex: String,
}

#[wasm_bindgen]
/// Parses a number expressed in binary/octal/decimal/hex and returns all four representations,
/// making it easy for the UI to cross-display values (e.g., `0x10` → `"16"` and `"10000"`).
pub fn convert_number_base(base: &str, value: &str) -> Result<JsValue, JsValue> {
    convert_number_base_internal(base, value)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn convert_number_base_internal(base: &str, value: &str) -> Result<NumberBases, String> {
    let num = parse_number_by_base(base, value)?;
    Ok(NumberBases {
        binary: format_bigint(&num, 2, false),
        octal: format_bigint(&num, 8, false),
        decimal: format_bigint(&num, 10, false),
        hex: format_bigint(&num, 16, true),
    })
}

fn parse_number_by_base(base: &str, value: &str) -> Result<BigInt, String> {
    let cleaned = value.trim().replace('_', "");
    if cleaned.is_empty() {
        return Err("value is empty".into());
    }
    let mut slice = cleaned.as_str();
    let mut negative = false;
    if let Some(rest) = slice.strip_prefix('-') {
        negative = true;
        slice = rest;
    } else if let Some(rest) = slice.strip_prefix('+') {
        slice = rest;
    }
    if slice.is_empty() {
        return Err("value is empty".into());
    }
    let radix = match base {
        "binary" => {
            if let Some(rest) = slice
                .strip_prefix("0b")
                .or_else(|| slice.strip_prefix("0B"))
            {
                slice = rest;
            }
            2
        }
        "octal" => {
            if let Some(rest) = slice
                .strip_prefix("0o")
                .or_else(|| slice.strip_prefix("0O"))
            {
                slice = rest;
            }
            8
        }
        "decimal" => 10,
        "hex" => {
            if let Some(rest) = slice
                .strip_prefix("0x")
                .or_else(|| slice.strip_prefix("0X"))
            {
                slice = rest;
            }
            16
        }
        _ => return Err(format!("unsupported base {}", base)),
    };
    if slice.is_empty() {
        return Err("value is empty".into());
    }
    let mut num = BigInt::parse_bytes(slice.as_bytes(), radix)
        .ok_or_else(|| format!("invalid {} value", base))?;
    if negative {
        num = -num;
    }
    Ok(num)
}

fn format_bigint(value: &BigInt, radix: u32, uppercase: bool) -> String {
    let mut out = value.to_str_radix(radix);
    if uppercase {
        out = out.to_uppercase();
    }
    out
}

// === Converter helpers ===
//
// Each converter mirrors a specific section of the original Go tool. The goal is
// to keep the data model deterministic so the web UI can show live previews for
// every format the specification calls out (JSON↔TOON, timestamp, units, etc.).

#[wasm_bindgen]
/// Converts a numeric value between bit/byte units (bit, byte, kilo/mega/giga/tera in both)
/// returning a JS map so the UI can show every unit side-by-side.
pub fn convert_units(unit: &str, value: &str) -> Result<JsValue, JsValue> {
    convert_units_internal(unit, value)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn convert_units_internal(unit: &str, value: &str) -> Result<BTreeMap<String, String>, String> {
    // Every value is normalized to bits so we can convert between bit/byte and
    // their binary multiples (definitions borrowed from the spec discussion).
    let factor = find_unit_factor(unit).ok_or_else(|| format!("unsupported unit: {}", unit))?;
    let parsed = parse_unit_value(value)?;
    let total_bits = parsed * factor;
    let mut results = BTreeMap::new();
    for (name, unit_factor) in UNIT_FACTORS.iter() {
        let converted = total_bits / unit_factor;
        results.insert((*name).to_string(), format_unit_value(converted));
    }
    Ok(results)
}

fn find_unit_factor(unit: &str) -> Option<f64> {
    let trimmed = unit.trim();
    UNIT_FACTORS
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(trimmed))
        .map(|(_, factor)| *factor)
}

fn parse_unit_value(value: &str) -> Result<f64, String> {
    let cleaned = value.trim().replace('_', "");
    if cleaned.is_empty() {
        return Err("value is empty".into());
    }
    cleaned
        .parse::<f64>()
        .map_err(|_| "invalid numeric value".into())
}

fn format_unit_value(value: f64) -> String {
    if value == 0.0 {
        return "0".into();
    }
    if !value.is_finite() {
        return value.to_string();
    }
    let mut formatted = format!("{:.12}", value);
    if let Some(dot_pos) = formatted.find('.') {
        let mut idx = formatted.len();
        while idx > dot_pos && formatted.as_bytes()[idx - 1] == b'0' {
            idx -= 1;
        }
        if idx > dot_pos && formatted.as_bytes()[idx - 1] == b'.' {
            idx -= 1;
        }
        formatted.truncate(idx);
    }
    if formatted == "-0" {
        formatted = "0".into();
    }
    formatted
}

#[wasm_bindgen]
/// Normalizes timestamps supplied as epoch seconds/millis/micros/nanos or textual dates
/// into a map of common formats (ISO8601, RFC2822, SQL datetime/date, multiple epoch precisions).
pub fn convert_timestamp(source: &str, value: &str) -> Result<JsValue, JsValue> {
    convert_timestamp_internal(source, value)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn convert_timestamp_internal(
    source: &str,
    value: &str,
) -> Result<BTreeMap<String, String>, String> {
    // Normalize any supported representation (RFC3339, SQL datetime, or the
    // different epoch precisions) into a UTC DateTime so we can fan out into
    // all of the formats surfaced in the UI/spec.
    let dt = parse_timestamp_from_source(source, value)?;
    let mut map = BTreeMap::new();
    map.insert("iso8601".into(), dt.to_rfc3339());
    map.insert("rfc2822".into(), dt.to_rfc2822());
    map.insert(
        "sql_datetime".into(),
        dt.format("%Y-%m-%d %H:%M:%S").to_string(),
    );
    map.insert("sql_date".into(), dt.format("%Y-%m-%d").to_string());
    map.insert("timestamp_seconds".into(), dt.timestamp().to_string());
    map.insert(
        "timestamp_milliseconds".into(),
        timestamp_value(&dt, TimestampUnit::Milliseconds),
    );
    map.insert(
        "timestamp_microseconds".into(),
        timestamp_value(&dt, TimestampUnit::Microseconds),
    );
    map.insert(
        "timestamp_nanoseconds".into(),
        timestamp_value(&dt, TimestampUnit::Nanoseconds),
    );
    Ok(map)
}

fn timestamp_value(dt: &DateTime<Utc>, unit: TimestampUnit) -> String {
    let base = i128::from(dt.timestamp());
    let nanos = i128::from(dt.timestamp_subsec_nanos());
    let value = match unit {
        TimestampUnit::Seconds => base,
        TimestampUnit::Milliseconds => base * 1_000 + nanos / 1_000_000,
        TimestampUnit::Microseconds => base * 1_000_000 + nanos / 1_000,
        TimestampUnit::Nanoseconds => base * 1_000_000_000 + nanos,
    };
    value.to_string()
}

fn parse_timestamp_from_source(source: &str, value: &str) -> Result<DateTime<Utc>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("input is empty".into());
    }
    let key = source.trim().to_ascii_lowercase();
    match key.as_str() {
        "timestamp_seconds" => parse_numeric_timestamp(trimmed, TimestampUnit::Seconds),
        "timestamp_milliseconds" => parse_numeric_timestamp(trimmed, TimestampUnit::Milliseconds),
        "timestamp_microseconds" => parse_numeric_timestamp(trimmed, TimestampUnit::Microseconds),
        "timestamp_nanoseconds" => parse_numeric_timestamp(trimmed, TimestampUnit::Nanoseconds),
        "sql_datetime" => parse_sql_datetime(trimmed),
        "sql_date" => parse_sql_date(trimmed),
        "rfc2822" => parse_textual_timestamp(trimmed),
        _ => parse_textual_timestamp(trimmed),
    }
}

fn parse_numeric_timestamp(value: &str, unit: TimestampUnit) -> Result<DateTime<Utc>, String> {
    let parsed = value
        .trim()
        .parse::<i128>()
        .map_err(|_| "invalid numeric value".to_string())?;
    let factor = unit.factor();
    let mut seconds = parsed / factor;
    let mut remainder = parsed % factor;
    if remainder < 0 {
        remainder += factor;
        seconds -= 1;
    }
    let nanos = remainder * unit.nanos_per_unit();
    let secs_i64: i64 = seconds
        .try_into()
        .map_err(|_| "timestamp out of range".to_string())?;
    let nanos_u32: u32 = nanos
        .try_into()
        .map_err(|_| "timestamp out of range".to_string())?;
    Utc.timestamp_opt(secs_i64, nanos_u32)
        .single()
        .ok_or_else(|| "timestamp out of range".to_string())
}

fn parse_textual_timestamp(value: &str) -> Result<DateTime<Utc>, String> {
    // Accept multiple canonical textual formats because the spec documents
    // RFC3339, RFC2822, and ISO 8601 partials (SQL date/datetime).
    if let Ok(dt) = DateTime::parse_from_rfc3339(value) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(naive) = NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S") {
        return Utc
            .from_local_datetime(&naive)
            .single()
            .ok_or_else(|| "invalid datetime".to_string());
    }
    if let Ok(naive_date) = NaiveDate::parse_from_str(value, "%Y-%m-%d") {
        let naive_dt =
            naive_date.and_time(NaiveTime::from_hms_opt(0, 0, 0).expect("valid midnight"));
        return Utc
            .from_local_datetime(&naive_dt)
            .single()
            .ok_or_else(|| "invalid datetime".to_string());
    }
    Err("unable to parse timestamp".into())
}

fn parse_sql_datetime(value: &str) -> Result<DateTime<Utc>, String> {
    // The UI allows pasting arbitrary SQL DATETIME strings; reject early so we
    // can surface validation errors near the input box.
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("input is empty".into());
    }
    let naive = NaiveDateTime::parse_from_str(trimmed, "%Y-%m-%d %H:%M:%S")
        .map_err(|_| "invalid SQL datetime".to_string())?;
    Utc.from_local_datetime(&naive)
        .single()
        .ok_or_else(|| "invalid datetime".to_string())
}

fn parse_sql_date(value: &str) -> Result<DateTime<Utc>, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("input is empty".into());
    }
    let naive_date = NaiveDate::parse_from_str(trimmed, "%Y-%m-%d")
        .map_err(|_| "invalid SQL date".to_string())?;
    let naive_dt = naive_date.and_time(NaiveTime::from_hms_opt(0, 0, 0).expect("valid midnight"));
    Utc.from_local_datetime(&naive_dt)
        .single()
        .ok_or_else(|| "invalid datetime".to_string())
}

enum TimestampUnit {
    Seconds,
    Milliseconds,
    Microseconds,
    Nanoseconds,
}

impl TimestampUnit {
    fn factor(&self) -> i128 {
        match self {
            TimestampUnit::Seconds => 1,
            TimestampUnit::Milliseconds => 1_000,
            TimestampUnit::Microseconds => 1_000_000,
            TimestampUnit::Nanoseconds => 1_000_000_000,
        }
    }

    fn nanos_per_unit(&self) -> i128 {
        match self {
            TimestampUnit::Seconds => 1_000_000_000,
            TimestampUnit::Milliseconds => 1_000_000,
            TimestampUnit::Microseconds => 1_000,
            TimestampUnit::Nanoseconds => 1,
        }
    }
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct IpInfoResult {
    #[serde(rename = "type")]
    kind: Option<String>,
    version: Option<String>,
    input: String,
    cidr: Option<String>,
    mask: Option<String>,
    mask_binary: Option<String>,
    range_start: Option<String>,
    range_end: Option<String>,
    total: Option<String>,
    standard: Option<String>,
    network: Option<String>,
    broadcast: Option<String>,
    three_part: Option<String>,
    two_part: Option<String>,
    integer: Option<String>,
    expanded: Option<String>,
    compressed: Option<String>,
    binary: Option<String>,
    host_bits: Option<String>,
    ipv6_mapped: Option<String>,
}

#[wasm_bindgen]
/// Inspects IPv4/IPv6 strings, CIDR blocks, or IPv4 ranges and returns a rich
/// breakdown (network, broadcast, total hosts, binary masks) for display in the UI.
pub fn ipv4_info(input: &str) -> Result<JsValue, JsValue> {
    ip_info_internal(input)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn ip_info_internal(input: &str) -> Result<IpInfoResult, String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err("input is empty".into());
    }
    if looks_like_range(trimmed) {
        return ipv4_range(trimmed);
    }
    if trimmed.contains('/') {
        return ip_with_prefix(trimmed);
    }
    if let Some(ip) = parse_ipv4(trimmed) {
        return Ok(ipv4_single(ip, trimmed));
    }
    if let Some(ip) = parse_ipv6(trimmed) {
        return Ok(ipv6_single(ip, trimmed));
    }
    Err("invalid IP input".into())
}

fn ip_with_prefix(input: &str) -> Result<IpInfoResult, String> {
    let mut parts = input.splitn(2, '/');
    let left = parts.next().unwrap_or("").trim();
    let right = parts.next().unwrap_or("").trim();
    if right.is_empty() {
        return Err("invalid prefix length".into());
    }
    if let Some(ip) = parse_ipv4(left) {
        return ipv4_with_prefix(ip, right, input);
    }
    if let Some(ip) = parse_ipv6(left) {
        return ipv6_with_prefix(ip, right, input);
    }
    Err(format!("invalid IP address: {}", left))
}

fn ipv4_single(ip: Ipv4Addr, original: &str) -> IpInfoResult {
    let octets = ip.octets();
    let three_part = format!(
        "{}.{}.{}",
        octets[0],
        octets[1],
        (((octets[2] as u16) << 8) | octets[3] as u16)
    );
    let two_part = format!(
        "{}.{}",
        octets[0],
        (((octets[1] as u32) << 16) | ((octets[2] as u32) << 8) | octets[3] as u32)
    );
    let mask_value = u32::MAX;
    IpInfoResult {
        kind: Some("single".into()),
        version: Some("IPv4".into()),
        input: original.to_string(),
        cidr: Some(format!("{}/32", ip)),
        mask: Some(Ipv4Addr::from(mask_value).to_string()),
        mask_binary: Some(format_binary(mask_value as u128, 32)),
        network: Some(ip.to_string()),
        broadcast: Some(ip.to_string()),
        range_start: Some(ip.to_string()),
        range_end: Some(ip.to_string()),
        total: Some("1".into()),
        standard: Some(ip.to_string()),
        three_part: Some(three_part),
        two_part: Some(two_part),
        integer: Some(u32::from(ip).to_string()),
        binary: Some(format_binary(u32::from(ip) as u128, 32)),
        host_bits: Some("0".into()),
        ipv6_mapped: Some(ipv4_mapped_ipv6(ip)),
        ..Default::default()
    }
}

fn ipv6_single(ip: Ipv6Addr, original: &str) -> IpInfoResult {
    IpInfoResult {
        kind: Some("single".into()),
        version: Some("IPv6".into()),
        input: original.to_string(),
        cidr: Some(format!("{}/128", ip)),
        mask: Some(Ipv6Addr::from(u128::MAX).to_string()),
        mask_binary: Some(format_binary(u128::MAX, 128)),
        range_start: Some(ip.to_string()),
        range_end: Some(ip.to_string()),
        total: Some("1".into()),
        standard: Some(ip.to_string()),
        compressed: Some(ip.to_string()),
        expanded: Some(format_ipv6_expanded(ip)),
        binary: Some(format_binary(ipv6_to_u128(ip), 128)),
        host_bits: Some("0".into()),
        ..Default::default()
    }
}

fn ipv4_with_prefix(ip: Ipv4Addr, right: &str, original: &str) -> Result<IpInfoResult, String> {
    let (prefix, mask_value, mask_string) = if right.contains('.') {
        let mask_ip = parse_ipv4(right).ok_or_else(|| format!("invalid subnet mask: {}", right))?;
        let mask_value = u32::from(mask_ip);
        let prefix = mask_to_prefix(mask_value)?;
        (prefix, mask_value, mask_ip.to_string())
    } else {
        let prefix: u8 = right
            .parse()
            .map_err(|_| format!("invalid prefix length: {}", right))?;
        if prefix > 32 {
            return Err(format!("invalid prefix length: {}", right));
        }
        let mask_value = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix as u32)
        };
        (prefix, mask_value, Ipv4Addr::from(mask_value).to_string())
    };
    let ip_value = u32::from(ip);
    let network = ip_value & mask_value;
    let broadcast = network | (!mask_value);
    let host_bits = 32 - prefix as u32;
    let total = if host_bits >= 32 {
        1u128 << 32
    } else {
        1u128 << host_bits
    };
    let three_part = format!(
        "{}.{}.{}",
        ip.octets()[0],
        ip.octets()[1],
        (((ip.octets()[2] as u16) << 8) | ip.octets()[3] as u16)
    );
    let two_part = format!(
        "{}.{}",
        ip.octets()[0],
        (((ip.octets()[1] as u32) << 16) | ((ip.octets()[2] as u32) << 8) | ip.octets()[3] as u32)
    );
    Ok(IpInfoResult {
        kind: Some("network".into()),
        version: Some("IPv4".into()),
        input: original.trim().to_string(),
        cidr: Some(format!("{}/{}", Ipv4Addr::from(network), prefix)),
        mask: Some(mask_string),
        mask_binary: Some(format_binary(mask_value as u128, 32)),
        range_start: Some(Ipv4Addr::from(network).to_string()),
        range_end: Some(Ipv4Addr::from(broadcast).to_string()),
        total: Some(total.to_string()),
        standard: Some(ip.to_string()),
        network: Some(Ipv4Addr::from(network).to_string()),
        broadcast: Some(Ipv4Addr::from(broadcast).to_string()),
        three_part: Some(three_part),
        two_part: Some(two_part),
        integer: Some(ip_value.to_string()),
        binary: Some(format_binary(ip_value as u128, 32)),
        host_bits: Some(host_bits.to_string()),
        ipv6_mapped: Some(ipv4_mapped_ipv6(ip)),
        ..Default::default()
    })
}

fn ipv6_with_prefix(ip: Ipv6Addr, right: &str, original: &str) -> Result<IpInfoResult, String> {
    let prefix: u8 = right
        .parse()
        .map_err(|_| format!("invalid prefix length: {}", right))?;
    if prefix > 128 {
        return Err(format!("invalid prefix length: {}", right));
    }
    let mask_value = if prefix == 0 {
        0
    } else {
        (!0u128) << (128 - prefix as u32)
    };
    let ip_value = ipv6_to_u128(ip);
    let network = ip_value & mask_value;
    let broadcast = network | (!mask_value);
    let host_bits = 128 - prefix as u32;
    let mut total = BigInt::from(1u8);
    total <<= host_bits;
    Ok(IpInfoResult {
        kind: Some("network".into()),
        version: Some("IPv6".into()),
        input: original.trim().to_string(),
        cidr: Some(format!("{}/{}", Ipv6Addr::from(network), prefix)),
        mask: Some(Ipv6Addr::from(mask_value).to_string()),
        mask_binary: Some(format_binary(mask_value, 128)),
        range_start: Some(Ipv6Addr::from(network).to_string()),
        range_end: Some(Ipv6Addr::from(broadcast).to_string()),
        total: Some(total.to_string()),
        standard: Some(ip.to_string()),
        compressed: Some(ip.to_string()),
        expanded: Some(format_ipv6_expanded(ip)),
        binary: Some(format_binary(ip_value, 128)),
        network: Some(Ipv6Addr::from(network).to_string()),
        broadcast: Some(Ipv6Addr::from(broadcast).to_string()),
        host_bits: Some(host_bits.to_string()),
        ..Default::default()
    })
}

fn ipv4_range(input: &str) -> Result<IpInfoResult, String> {
    let normalized = normalize_range_input(input);
    let pieces: Vec<&str> = normalized.split('-').collect();
    if pieces.len() != 2 {
        return Err("range must be in start-end format".into());
    }
    let start_ip = parse_ipv4(pieces[0]).ok_or_else(|| "invalid IPv4 range".to_string())?;
    let end_ip = parse_ipv4(pieces[1]).ok_or_else(|| "invalid IPv4 range".to_string())?;
    let start = u32::from(start_ip);
    let end = u32::from(end_ip);
    if start > end {
        return Err("start IP must be less than or equal to end IP".into());
    }
    let total = (end - start) as u64 + 1;
    let cidrs = ip_range_to_cidrs(start, end);
    Ok(IpInfoResult {
        kind: Some("range".into()),
        version: Some("IPv4".into()),
        input: input.trim().to_string(),
        cidr: if cidrs.is_empty() {
            None
        } else {
            Some(cidrs.join(", "))
        },
        mask: None,
        range_start: Some(start_ip.to_string()),
        range_end: Some(end_ip.to_string()),
        total: Some(total.to_string()),
        standard: None,
        three_part: None,
        two_part: None,
        integer: None,
        ..Default::default()
    })
}

fn parse_ipv4(value: &str) -> Option<Ipv4Addr> {
    let trimmed = value.trim();
    Ipv4Addr::from_str(trimmed)
        .ok()
        .or_else(|| parse_ipv4_extended(trimmed))
}

fn parse_ipv4_extended(value: &str) -> Option<Ipv4Addr> {
    if value.is_empty() {
        return None;
    }
    if value.contains('.') {
        let parts: Vec<&str> = value.split('.').collect();
        if parts.len() > 4 {
            return None;
        }
        let mut nums = Vec::with_capacity(parts.len());
        for part in parts.iter() {
            nums.push(parse_ipv4_number(part.trim())?);
        }
        let val = match nums.len() {
            1 => nums[0],
            2 => {
                if nums[0] > 0xFF || nums[1] > 0xFFFFFF {
                    return None;
                }
                (nums[0] << 24) | nums[1]
            }
            3 => {
                if nums[0] > 0xFF || nums[1] > 0xFF || nums[2] > 0xFFFF {
                    return None;
                }
                (nums[0] << 24) | (nums[1] << 16) | nums[2]
            }
            4 => {
                if nums.iter().any(|n| *n > 0xFF) {
                    return None;
                }
                (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
            }
            _ => return None,
        };
        return Some(Ipv4Addr::from(val));
    }
    let num = parse_ipv4_number(value)?;
    Some(Ipv4Addr::from(num))
}

fn parse_ipv4_number(part: &str) -> Option<u32> {
    let trimmed = part.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        u32::from_str_radix(rest, 16).ok()
    } else {
        trimmed.parse::<u32>().ok()
    }
}

fn parse_ipv6(value: &str) -> Option<Ipv6Addr> {
    Ipv6Addr::from_str(value.trim()).ok()
}

fn looks_like_range(input: &str) -> bool {
    let normalized = input.replace(' ', "");
    normalized.contains('-') || normalized.contains("->")
}

fn normalize_range_input(input: &str) -> String {
    input
        .replace(' ', "")
        .replace("->", "-")
        .replace(&['—', '–'][..], "-")
}

fn mask_to_prefix(mask: u32) -> Result<u8, String> {
    let mut seen_zero = false;
    let mut prefix = 0u8;
    for bit in (0..32).rev() {
        let bit_set = (mask >> bit) & 1;
        if bit_set == 1 {
            if seen_zero {
                return Err("invalid subnet mask".into());
            }
            prefix += 1;
        } else {
            seen_zero = true;
        }
    }
    Ok(prefix)
}

fn ip_range_to_cidrs(mut start: u32, end: u32) -> Vec<String> {
    let mut cidrs = Vec::new();
    while start <= end {
        let mut max_size = start & (!start + 1);
        if max_size == 0 {
            max_size = 1 << 31;
        }
        let remaining = end - start + 1;
        let mut size = max_size;
        while size > remaining {
            size >>= 1;
        }
        let prefix = 32 - size.trailing_zeros();
        cidrs.push(format!("{}/{}", Ipv4Addr::from(start), prefix));
        start = start.wrapping_add(size);
        if start == 0 {
            break;
        }
    }
    cidrs
}

fn ipv6_to_u128(addr: Ipv6Addr) -> u128 {
    u128::from(addr)
}

fn format_ipv6_expanded(addr: Ipv6Addr) -> String {
    let segments = addr.segments();
    format!(
        "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
        segments[0],
        segments[1],
        segments[2],
        segments[3],
        segments[4],
        segments[5],
        segments[6],
        segments[7]
    )
}

fn ipv4_mapped_ipv6(ip: Ipv4Addr) -> String {
    let octets = ip.octets();
    let seg6 = ((octets[0] as u16) << 8) | octets[1] as u16;
    let seg7 = ((octets[2] as u16) << 8) | octets[3] as u16;
    format!("0000:0000:0000:0000:0000:ffff:{:04x}:{:04x}", seg6, seg7)
}

fn format_binary(value: u128, bits: usize) -> String {
    let raw = format!("{:0width$b}", value, width = bits);
    let mut out = String::with_capacity(raw.len() + raw.len() / 4);
    for (idx, ch) in raw.chars().enumerate() {
        if idx > 0 && idx % 4 == 0 {
            out.push(' ');
        }
        out.push(ch);
    }
    out
}

#[derive(Serialize, Default)]
#[serde(rename_all = "camelCase")]
struct JwtDecodeResult {
    header: Option<String>,
    payload: Option<String>,
    signature: Option<String>,
    algorithm: Option<String>,
}

#[wasm_bindgen]
/// Percent-encodes a string for URL query contexts while keeping spaces as `+`
/// to match the browser form-encoding convention.
pub fn url_encode(input: &str) -> String {
    urlencoding::encode(input).replace("%20", "+")
}

#[wasm_bindgen]
/// Decodes URL-encoded strings, treating `+` as space to align with form submissions.
pub fn url_decode(input: &str) -> Result<String, JsValue> {
    let normalized = input.replace('+', " ");
    urlencoding::decode(&normalized)
        .map(|cow| cow.into_owned())
        .map_err(|_| JsValue::from_str("invalid URL encoding"))
}

#[wasm_bindgen]
/// Builds an HMAC-signed JWT from a JSON payload and secret, defaulting to HS256 when
/// the algorithm input is empty; returns the compact token string.
pub fn jwt_encode(payload_input: &str, secret: &str, algorithm: &str) -> Result<String, JsValue> {
    jwt_encode_internal(payload_input, secret, algorithm).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
/// Decodes a JWT without verifying the signature, returning pretty-printed header/payload
/// text plus the algorithm and raw signature segment for inspection.
pub fn jwt_decode(token: &str) -> Result<JsValue, JsValue> {
    jwt_decode_internal(token)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn jwt_encode_internal(
    payload_input: &str,
    secret: &str,
    algorithm: &str,
) -> Result<String, String> {
    if secret.trim().is_empty() {
        return Err("secret is required".into());
    }
    let algo = if algorithm.trim().is_empty() {
        "HS256"
    } else {
        algorithm
    };
    let payload_value: Value = serde_json::from_str(payload_input)
        .map_err(|_| "payload must be valid JSON".to_string())?;
    let payload_bytes = serde_json::to_vec(&payload_value).map_err(|err| err.to_string())?;
    let header = serde_json::json!({
        "typ": "JWT",
        "alg": algo,
    });
    let header_bytes = serde_json::to_vec(&header).map_err(|err| err.to_string())?;
    let header_encoded = URL_SAFE_NO_PAD.encode(header_bytes);
    let payload_encoded = URL_SAFE_NO_PAD.encode(payload_bytes);
    let signing_input = format!("{}.{}", header_encoded, payload_encoded);
    let signature = sign_jwt(&signing_input, secret, algo)?;
    Ok(format!(
        "{}.{}.{}",
        header_encoded, payload_encoded, signature
    ))
}

fn jwt_decode_internal(token: &str) -> Result<JwtDecodeResult, String> {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return Err("token is empty".into());
    }
    let segments: Vec<&str> = trimmed.split('.').collect();
    if segments.len() < 2 {
        return Err("invalid JWT token".into());
    }
    let header_bytes =
        decode_base64_segment(segments[0]).map_err(|err| format!("invalid header: {}", err))?;
    let payload_bytes =
        decode_base64_segment(segments[1]).map_err(|err| format!("invalid payload: {}", err))?;
    let header_pretty =
        pretty_json_bytes(&header_bytes).map_err(|err| format!("invalid header JSON: {}", err))?;
    let payload_pretty = pretty_json_bytes(&payload_bytes)
        .map_err(|err| format!("invalid payload JSON: {}", err))?;
    let signature = segments
        .get(2)
        .and_then(|sig| (!sig.is_empty()).then(|| (*sig).to_string()));
    let algorithm = serde_json::from_slice::<Value>(&header_bytes)
        .ok()
        .and_then(|value| match value {
            Value::Object(map) => map
                .get("alg")
                .and_then(|alg| alg.as_str())
                .map(|alg| alg.to_string()),
            _ => None,
        });
    Ok(JwtDecodeResult {
        header: Some(header_pretty),
        payload: Some(payload_pretty),
        signature,
        algorithm,
    })
}

fn pretty_json_bytes(data: &[u8]) -> Result<String, String> {
    let value: Value = serde_json::from_slice(data).map_err(|err| err.to_string())?;
    serde_json::to_string_pretty(&value).map_err(|err| err.to_string())
}

fn decode_base64_segment(segment: &str) -> Result<Vec<u8>, String> {
    let mut normalized = segment.trim().to_string();
    if normalized.is_empty() {
        return Err("segment is empty".into());
    }
    let rem = normalized.len() % 4;
    if rem != 0 {
        normalized.extend(std::iter::repeat_n('=', 4 - rem));
    }
    URL_SAFE
        .decode(normalized.as_bytes())
        .map_err(|err| err.to_string())
}

fn sign_jwt(signing_input: &str, secret: &str, algorithm: &str) -> Result<String, String> {
    let key = secret.as_bytes();
    let signature = match algorithm {
        "HS256" | "" => {
            let mut mac =
                <Hmac<Sha256> as KeyInit>::new_from_slice(key).map_err(|err| err.to_string())?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac =
                <Hmac<Sha384> as KeyInit>::new_from_slice(key).map_err(|err| err.to_string())?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac =
                <Hmac<Sha512> as KeyInit>::new_from_slice(key).map_err(|err| err.to_string())?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        other => return Err(format!("unsupported algorithm {}", other)),
    };
    Ok(URL_SAFE_NO_PAD.encode(signature))
}

fn encode_base91(data: &[u8]) -> String {
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    for &byte in data {
        value |= (byte as u32) << bits;
        bits += 8;
        while bits > 13 {
            let mut encoded = value & 8191;
            if encoded > 88 {
                value >>= 13;
                bits -= 13;
            } else {
                encoded = value & 16383;
                value >>= 14;
                bits -= 14;
            }
            out.push(BASE91_ALPHABET[(encoded % 91) as usize]);
            out.push(BASE91_ALPHABET[(encoded / 91) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE91_ALPHABET[(value % 91) as usize]);
        if bits > 7 || value > 90 {
            out.push(BASE91_ALPHABET[(value / 91) as usize]);
        }
    }
    String::from_utf8(out).unwrap_or_default()
}

fn decode_base91(input: &str) -> Result<Vec<u8>, String> {
    let table = base91_lookup();
    let mut value = 0u32;
    let mut bits = 0u32;
    let mut pair = -1i32;
    let mut out = Vec::new();
    for byte in input.bytes() {
        let idx = table[byte as usize];
        if idx == -1 {
            return Err(format!("invalid base91 character '{}'", byte as char));
        }
        if pair == -1 {
            pair = idx as i32;
        } else {
            let combined = pair + (idx as i32) * 91;
            value |= (combined as u32) << bits;
            if (combined & 8191) > 88 {
                bits += 13;
            } else {
                bits += 14;
            }
            while bits >= 8 {
                out.push((value & 255) as u8);
                value >>= 8;
                bits -= 8;
            }
            pair = -1;
        }
    }
    if pair != -1 {
        value |= (pair as u32) << bits;
        out.push((value & 255) as u8);
    }
    Ok(out)
}

fn base91_lookup() -> &'static [i16; 256] {
    BASE91_LOOKUP.get_or_init(|| {
        let mut table = [-1i16; 256];
        for (idx, byte) in BASE91_ALPHABET.iter().enumerate() {
            table[*byte as usize] = idx as i16;
        }
        table
    })
}

fn fnv1_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for &byte in data {
        hash = hash.wrapping_mul(0x0100_0193);
        hash ^= u32::from(byte);
    }
    hash
}

fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811C9DC5;
    for &byte in data {
        hash ^= u32::from(byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn fnv1_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash = hash.wrapping_mul(0x1000_0000_01b3);
        hash ^= u64::from(byte);
    }
    hash
}

fn fnv1a_64(data: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &byte in data {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn fnv1_128(data: &[u8]) -> u128 {
    let mut hash: u128 = 0x6c62272e07bb014262b821756295c58d;
    let prime: u128 = 0x0000000000000000000000000000013b;
    for &byte in data {
        hash = hash.wrapping_mul(prime);
        hash ^= u128::from(byte);
    }
    hash
}

fn fnv1a_128(data: &[u8]) -> u128 {
    let mut hash: u128 = 0x6c62272e07bb014262b821756295c58d;
    let prime: u128 = 0x0000000000000000000000000000013b;
    for &byte in data {
        hash ^= u128::from(byte);
        hash = hash.wrapping_mul(prime);
    }
    hash
}

fn append_required_chars(
    buffer: &mut Vec<char>,
    pool: &[char],
    count: u32,
    label: &str,
) -> Result<(), String> {
    // Used by the random string generator to guarantee minimum counts for each
    // selected character family (digits/upper/lower/symbols).
    if count == 0 {
        return Ok(());
    }
    if pool.is_empty() {
        return Err(format!(
            "No {} available to satisfy minimum requirement",
            label
        ));
    }
    for _ in 0..count {
        let ch = random_char_from_pool(pool)?;
        buffer.push(ch);
    }
    Ok(())
}

fn random_char_from_pool(pool: &[char]) -> Result<char, String> {
    if pool.is_empty() {
        return Err("Character pool is empty".into());
    }
    Ok(pool[random_index(pool.len())])
}

fn shuffle_chars(chars: &mut [char]) {
    // Fisher-Yates shuffle so each password candidate looks random even if the
    // caller requested minimum counts for specific sets.
    if chars.len() < 2 {
        return;
    }
    for idx in (1..chars.len()).rev() {
        let swap_idx = random_index(idx + 1);
        chars.swap(idx, swap_idx);
    }
}
fn fill_random(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("randomness available");
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    fill_random(&mut buf);
    buf
}

fn decode_b64(input: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|err| err.to_string())
}

fn decode_bcrypt_salt(input: &str) -> Result<[u8; 16], String> {
    const ALPHABET: &[u8] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    if input.len() != 22 {
        return Err(format!(
            "22 chars required for bcrypt-base64 salt, got {}",
            input.len()
        ));
    }
    let mut decode_map = [u8::MAX; 256];
    for (i, ch) in ALPHABET.iter().enumerate() {
        decode_map[*ch as usize] = i as u8;
    }
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;
    let mut out = Vec::with_capacity(16);
    for byte in input.bytes() {
        let val = decode_map[byte as usize];
        if val == u8::MAX {
            return Err(format!("invalid character '{}'", byte as char));
        }
        buffer = (buffer << 6) | val as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xFF) as u8);
        }
    }
    if out.len() != 16 {
        return Err(format!("decoded salt must be 16 bytes, got {}", out.len()));
    }
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&out);
    Ok(salt)
}

fn random_index(max: usize) -> usize {
    assert!(max > 0, "pool cannot be empty");
    let bound = max as u64;
    let threshold = u64::MAX - (u64::MAX % bound);
    loop {
        let mut buf = [0u8; 8];
        fill_random(&mut buf);
        let sample = u64::from_le_bytes(buf);
        if sample < threshold {
            return (sample % bound) as usize;
        }
    }
}

fn find_matching_paren(src: &str, open_idx: usize) -> Option<usize> {
    let mut depth = 0i32;
    for (idx, byte) in src.as_bytes().iter().enumerate().skip(open_idx) {
        match *byte {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(idx);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod lib_tests;
