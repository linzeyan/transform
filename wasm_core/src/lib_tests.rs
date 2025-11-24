use super::*;
use base64::Engine;
use bcrypt::BASE_64;
use chrono::{TimeZone, Utc};
use data_encoding::{BASE32, BASE32HEX};

fn assert_has_category(input: &str, predicate: impl Fn(char) -> bool, label: &str) {
    assert!(input.chars().any(predicate), "expected {label} in {input}");
}

#[test]
fn bcrypt_hash_and_verify_with_fixed_salt() {
    // 16 zero bytes encoded into bcrypt-base64 (22 chars) keeps the output deterministic.
    let salt = BASE_64.encode([0u8; 16]);
    let hash = bcrypt_hash("apple111", 10, Some(salt)).expect("hash ok");
    assert!(hash.starts_with("$2b$10$"));
    assert!(bcrypt_verify("apple111", &hash).unwrap());
    assert!(!bcrypt_verify("wrong", &hash).unwrap());
}

#[test]
fn decode_bcrypt_salt_valid() {
    let salt = BASE_64.encode([0u8; 16]);
    let decoded = decode_bcrypt_salt(&salt).expect("decode ok");
    assert_eq!(decoded, [0u8; 16]);
}

#[test]
fn decode_bcrypt_salt_invalid_length() {
    let err = decode_bcrypt_salt("short").unwrap_err();
    assert!(err.contains("22 chars"), "msg: {err}");
}

#[test]
fn decode_bcrypt_salt_invalid_char() {
    let mut salt = BASE_64.encode([0u8; 16]);
    salt.replace_range(0..1, "!");
    let err = decode_bcrypt_salt(&salt).unwrap_err();
    assert!(err.contains("invalid character"));
}

#[test]
fn argon2_hash_and_verify_with_fixed_salt() {
    let salt = base64::engine::general_purpose::STANDARD.encode([1u8; 16]);
    let hash = argon2_hash("apple111", Some(salt), 2, 4096, 1, 16, "argon2id").expect("hash ok");
    assert!(hash.starts_with("$argon2id$"));
    assert!(argon2_verify("apple111", &hash).unwrap());
    assert!(!argon2_verify("wrong", &hash).unwrap());
}

#[test]
fn encode_content_map_includes_common_encodings() {
    let map = encode_content_map("hi");
    assert_eq!(map.get("base32_standard").unwrap(), &BASE32.encode(b"hi"));
    assert_eq!(map.get("base32_hex").unwrap(), &BASE32HEX.encode(b"hi"));
    assert_eq!(map.get("hex_upper").unwrap(), &hex::encode_upper("hi"));
    assert!(map.contains_key("base91"));
}

#[test]
fn decode_content_internal_round_trips_base64() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("rust");
    let decoded =
        decode_content_internal("base64_standard", &encoded).expect("should decode base64");
    assert_eq!(decoded, b"rust");
}

#[test]
fn decode_content_internal_rejects_unknown_kind() {
    let err = decode_content_internal("unknown", "abc").unwrap_err();
    assert!(err.contains("unsupported"));
}

#[test]
fn random_sequences_internal_respects_counts() {
    let outputs = random_sequences_internal(8, 2, true, "12", true, true, "@#", "", 2, 1, 1, 1)
        .expect("sequences generated");
    for candidate in outputs {
        assert_eq!(candidate.len(), 8);
        assert_has_category(&candidate, |c| c.is_ascii_digit(), "digit");
        assert_has_category(&candidate, |c| c.is_ascii_lowercase(), "lowercase");
        assert_has_category(&candidate, |c| c.is_ascii_uppercase(), "uppercase");
        assert_has_category(&candidate, |c| !c.is_alphanumeric(), "symbol");
    }
}

#[test]
fn random_sequences_internal_rejects_empty_pool() {
    let err =
        random_sequences_internal(4, 1, true, "", false, false, "", "", 0, 0, 0, 0).unwrap_err();
    assert!(err.contains("No available characters"));
}

#[test]
fn sanitize_helpers_clean_inputs() {
    assert_eq!(sanitize_digits("1a2a3"), vec!['1', '2', '3']);
    assert_eq!(sanitize_symbols("a!@#"), vec!['!', '#', '@']);
    let exclusions = sanitize_exclusions(" a b 1 ");
    assert!(exclusions.contains(&'a'));
    assert!(exclusions.contains(&'b'));
    assert!(exclusions.contains(&'1'));
}

#[test]
fn parse_column_line_extracts_metadata() {
    let column = parse_column_line(
        "`price` DECIMAL(6,2) unsigned DEFAULT 1.25,",
        column_regex(),
    )
    .expect("column parsed");
    assert_eq!(column.name, "price");
    assert_eq!(column.base_type, "decimal");
    assert_eq!(column.length, Some(6));
    assert_eq!(column.scale, Some(2));
    assert!(column.unsigned);
    match column.default_value {
        Some(ColumnDefault::Numeric(val)) => assert_eq!(val, "1.25"),
        other => panic!("unexpected default: {other:?}"),
    }
}

#[test]
fn parse_enum_values_handles_escaped_quotes() {
    let values = parse_enum_values("enum('a','b''b','c')");
    assert_eq!(values, vec!["a", "b'b", "c"]);
}

#[test]
fn generate_insert_statements_internal_builds_rows() {
    let schema = "CREATE TABLE users (
  id INT PRIMARY KEY,
  name VARCHAR(10)
);";
    let output = generate_insert_statements_internal(schema, 2, BTreeMap::new()).unwrap();
    assert!(output.contains("INSERT INTO `users`"));
    assert!(output.contains("`id`"));
    assert!(output.contains("`name`"));
}

#[test]
fn convert_timestamp_internal_from_sql_datetime() {
    let map = convert_timestamp_internal("sql_datetime", "2025-01-02 03:04:05").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");
    assert_eq!(map.get("iso8601").unwrap(), &expected_dt.to_rfc3339());
    assert_eq!(
        map.get("timestamp_seconds").unwrap(),
        &expected_dt.timestamp().to_string()
    );
}

#[test]
fn convert_units_internal_converts_bytes() {
    let map = convert_units_internal("byte", "1024").unwrap();
    assert_eq!(map.get("byte").unwrap(), "1024");
    assert_eq!(map.get("bit").unwrap(), "8192");
    assert_eq!(map.get("kilobit").unwrap(), "8");
}

#[test]
fn convert_number_base_internal_hex() {
    let bases = convert_number_base_internal("hex", "0x10").unwrap();
    assert_eq!(bases.decimal, "16");
    assert_eq!(bases.binary, "10000");
    assert_eq!(bases.octal, "20");
}

#[test]
fn parse_number_by_base_handles_negative_binary() {
    let num = parse_number_by_base("binary", "-0b1010").unwrap();
    assert_eq!(format_bigint(&num, 10, false), "-10");
}

#[test]
fn ip_info_internal_single_ipv4() {
    let info = ip_info_internal("192.168.1.1").unwrap();
    assert_eq!(info.kind.unwrap(), "single");
    assert_eq!(info.version.unwrap(), "IPv4");
    assert_eq!(info.cidr.unwrap(), "192.168.1.1/32");
    assert_eq!(info.total.unwrap(), "1");
}

#[test]
fn ipv4_range_parses_total_hosts() {
    let info = ip_info_internal("192.168.0.1-192.168.0.3").unwrap();
    assert_eq!(info.kind.unwrap(), "range");
    assert_eq!(info.total.unwrap(), "3");
}

#[test]
fn mask_to_prefix_validates_masks() {
    assert_eq!(mask_to_prefix(0xFFFF_FF00).unwrap(), 24);
    assert!(mask_to_prefix(0xFF00_FF00).is_err());
}

#[test]
fn encode_decode_base91_roundtrip() {
    let encoded = encode_base91(b"hello");
    let decoded = decode_base91(&encoded).expect("roundtrip succeeds");
    assert_eq!(decoded, b"hello");
}

#[test]
fn jwt_encode_decode_roundtrip() {
    let token =
        jwt_encode_internal("{\"sub\":\"demo\"}", "topsecret", "HS256").expect("token encoded");
    let decoded = jwt_decode_internal(&token).expect("token decoded");
    assert!(decoded.payload.unwrap().contains("\"sub\": \"demo\""));
    assert_eq!(decoded.algorithm.unwrap(), "HS256");
}

#[test]
fn url_encode_decode_handles_spaces() {
    let encoded = url_encode("a b+c");
    let decoded = url_decode(&encoded).unwrap();
    assert_eq!(decoded, "a b+c");
}

#[test]
fn fnv_hashes_match_reference() {
    assert_eq!(fnv1_32(b"fnv"), 0x418f_6079);
    assert_eq!(fnv1a_32(b"fnv"), 0xb2f5_cb99);
    assert_eq!(fnv1_64(b"fnv"), 0x33e5_1b18_6ba1_3779);
    assert_eq!(fnv1a_64(b"fnv"), 0x7280_7b18_fedc_1a99);
    assert_eq!(fnv1_128(b"fnv"), 0x158c_3dea_7d8b_5822_836d_bc78_c6a7_b2a9);
    assert_eq!(fnv1a_128(b"fnv"), 0x158c_3dea_7d8b_5822_836d_bc79_768e_89e9);
}

#[test]
fn find_matching_paren_locates_closing_index() {
    let src = "fn(a(b)c)d";
    assert_eq!(find_matching_paren(src, 2), Some(8));
}
