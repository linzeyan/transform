use std::collections::{BTreeMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use std::sync::OnceLock;

use adler::Adler32;
use ascii85::{decode as ascii85_decode, encode as ascii85_encode};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use console_error_panic_hook::set_once as set_panic_hook;
use crc::{Crc, CRC_32_ISCSI, CRC_64_ECMA_182, CRC_64_GO_ISO};
use data_encoding::{BASE32, BASE32HEX, BASE32HEX_NOPAD, BASE32_NOPAD};
use hmac::{Hmac, Mac};
use js_sys::Date;
use md5::Md5;
use num_bigint::BigInt;
use serde::Serialize;
use serde_json::Value;
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use uuid as uuid_crate;
use uuid_crate::{Context, NoContext, Timestamp};
use wasm_bindgen::prelude::*;

mod convert;

#[wasm_bindgen(start)]
pub fn wasm_start() {
    set_panic_hook();
}

static NODE_ID: OnceLock<[u8; 6]> = OnceLock::new();
static V1_CONTEXT: OnceLock<Context> = OnceLock::new();
static BASE91_LOOKUP: OnceLock<[i16; 256]> = OnceLock::new();

const BASE91_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~\"";

const UNIT_FACTORS: &[(&str, f64)] = &[
    ("bit", 1.0),
    ("byte", 8.0),
    ("kilobit", 1_000.0),
    ("kilobyte", 8_000.0),
    ("megabit", 1_000_000.0),
    ("megabyte", 8_000_000.0),
    ("gigabit", 1_000_000_000.0),
    ("gigabyte", 8_000_000_000.0),
    ("terabit", 1_000_000_000_000.0),
    ("terabyte", 8_000_000_000_000.0),
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

#[wasm_bindgen]
pub fn generate_user_agents(browser: &str, os: &str) -> JsValue {
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
    serde_wasm_bindgen::to_value(&results).unwrap()
}

#[wasm_bindgen]
#[allow(clippy::too_many_arguments)]
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
pub fn hash_content(input: &str) -> Result<JsValue, JsValue> {
    let map = hash_content_map(input.as_bytes());
    serde_wasm_bindgen::to_value(&map).map_err(|err| JsValue::from_str(&err.to_string()))
}

#[wasm_bindgen]
pub fn transform_format(from: &str, to: &str, input: &str) -> Result<String, JsValue> {
    convert::convert_formats(from, to, input).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
pub fn format_content_text(format: &str, input: &str, minify: bool) -> Result<String, JsValue> {
    convert::format_content(format, input, minify).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
pub fn markdown_to_html_text(input: &str) -> Result<String, JsValue> {
    convert::markdown::markdown_to_html(input).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
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

#[derive(Serialize, Default)]
struct NumberBases {
    binary: String,
    octal: String,
    decimal: String,
    hex: String,
}

#[wasm_bindgen]
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

#[wasm_bindgen]
pub fn convert_units(unit: &str, value: &str) -> Result<JsValue, JsValue> {
    convert_units_internal(unit, value)
        .and_then(|res| serde_wasm_bindgen::to_value(&res).map_err(|err| err.to_string()))
        .map_err(|err| JsValue::from_str(&err))
}

fn convert_units_internal(unit: &str, value: &str) -> Result<BTreeMap<String, String>, String> {
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
}

#[wasm_bindgen]
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
pub fn url_encode(input: &str) -> String {
    urlencoding::encode(input).replace("%20", "+")
}

#[wasm_bindgen]
pub fn url_decode(input: &str) -> Result<String, JsValue> {
    let normalized = input.replace('+', " ");
    urlencoding::decode(&normalized)
        .map(|cow| cow.into_owned())
        .map_err(|_| JsValue::from_str("invalid URL encoding"))
}

#[wasm_bindgen]
pub fn jwt_encode(payload_input: &str, secret: &str, algorithm: &str) -> Result<String, JsValue> {
    jwt_encode_internal(payload_input, secret, algorithm).map_err(|err| JsValue::from_str(&err))
}

#[wasm_bindgen]
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
            let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|err| err.to_string())?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS384" => {
            let mut mac = Hmac::<Sha384>::new_from_slice(key).map_err(|err| err.to_string())?;
            mac.update(signing_input.as_bytes());
            mac.finalize().into_bytes().to_vec()
        }
        "HS512" => {
            let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|err| err.to_string())?;
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
    if chars.len() < 2 {
        return;
    }
    for idx in (1..chars.len()).rev() {
        let swap_idx = random_index(idx + 1);
        chars.swap(idx, swap_idx);
    }
}
fn fill_random(buf: &mut [u8]) {
    getrandom::fill(buf).expect("randomness available");
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
