use super::*;
use crate::cert;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD; // Base64 encoder used by QR tests.
use bcrypt::BASE_64;
use chrono::{TimeZone, Timelike, Utc};
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
fn encode_content_bytes_matches_text_map() {
    // File bytes should reuse the same encoding helpers used for text input.
    let text_map = encode_content_map("file!");
    let bytes_map = encode_content_map_bytes("file!".as_bytes());
    assert_eq!(text_map, bytes_map);
}

#[test]
fn decode_content_internal_round_trips_base64() {
    let encoded = base64::engine::general_purpose::STANDARD.encode("rust");
    let decoded =
        decode_content_internal("base64_standard", &encoded).expect("should decode base64");
    assert_eq!(decoded, b"rust");
}

#[test]
fn decode_content_bytes_preserves_binary_output() {
    // Decode bytes should return raw data, not a lossy UTF-8 string.
    let encoded = base64::engine::general_purpose::STANDARD.encode([0u8, 255u8, 2u8, 3u8]);
    let decoded = decode_content_bytes("base64_standard", &encoded).expect("binary decode");
    assert_eq!(decoded, vec![0u8, 255u8, 2u8, 3u8]);
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
fn random_numeric_range_internal_generates_within_bounds() {
    let outputs = random_numeric_range_internal(3, "10", "25", 3).expect("range ok");
    assert_eq!(outputs.len(), 3);
    for val in outputs {
        let parsed: i32 = val.parse().expect("digit string");
        assert!((10..=25).contains(&parsed));
        assert!(!val.starts_with('0'));
        assert!(val.len() <= 3);
    }
}

#[test]
fn random_numeric_range_internal_rejects_length_overflow() {
    let err = random_numeric_range_internal(1, "1", "1000", 3).unwrap_err();
    assert!(err.contains("length"), "unexpected err: {err}");
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

    // Test ISO 8601 format (basic format without nanoseconds)
    assert_eq!(map.get("iso8601").unwrap(), "2025-01-02T03:04:05Z");

    // Test RFC 3339 format (with nanoseconds)
    assert!(map.get("rfc3339").unwrap().contains("2025-01-02T03:04:05."));
    assert!(map.get("rfc3339").unwrap().ends_with("Z"));

    // Test RFC 2822 format
    assert_eq!(map.get("rfc2822").unwrap(), &expected_dt.to_rfc2822());

    // Test ISO 9075 format (SQL timestamp with timezone)
    assert_eq!(map.get("iso9075").unwrap(), "2025-01-02 03:04:05+00:00");

    // Test RFC 7231 format (HTTP date format)
    assert_eq!(map.get("rfc7231").unwrap(), "Thu, 02 Jan 2025 03:04:05 GMT");

    // Test SQL formats
    assert_eq!(map.get("sql_datetime").unwrap(), "2025-01-02 03:04:05");
    assert_eq!(map.get("sql_date").unwrap(), "2025-01-02");

    // Test Unix timestamp formats
    assert_eq!(
        map.get("timestamp_seconds").unwrap(),
        &expected_dt.timestamp().to_string()
    );

    // Test browser timezone formats exist
    assert!(map.contains_key("browser_iso8601"));
    assert!(map.contains_key("browser_rfc3339"));
    assert!(map.contains_key("browser_rfc2822"));
    assert!(map.contains_key("browser_iso9075"));
    assert!(map.contains_key("browser_rfc7231"));
    assert!(map.contains_key("browser_sql_datetime"));
    assert!(map.contains_key("browser_sql_date"));
}

#[test]
fn convert_timestamp_internal_from_iso8601() {
    let map = convert_timestamp_internal("iso8601", "2025-01-02T03:04:05Z").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");

    assert_eq!(map.get("iso8601").unwrap(), "2025-01-02T03:04:05Z");
    assert_eq!(
        map.get("rfc3339").unwrap(),
        &expected_dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    );
    assert_eq!(map.get("rfc2822").unwrap(), &expected_dt.to_rfc2822());
    assert_eq!(map.get("iso9075").unwrap(), "2025-01-02 03:04:05+00:00");
    assert_eq!(map.get("rfc7231").unwrap(), "Thu, 02 Jan 2025 03:04:05 GMT");
}

#[test]
fn convert_timestamp_internal_from_rfc3339() {
    let map = convert_timestamp_internal("rfc3339", "2025-01-02T03:04:05.123456789Z").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .unwrap()
        .with_nanosecond(123_456_789)
        .unwrap();

    assert_eq!(map.get("iso8601").unwrap(), "2025-01-02T03:04:05Z");
    assert_eq!(
        map.get("rfc3339").unwrap(),
        &expected_dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    );
    assert_eq!(map.get("rfc2822").unwrap(), &expected_dt.to_rfc2822());
}

#[test]
fn convert_timestamp_internal_from_iso9075() {
    let map = convert_timestamp_internal("iso9075", "2025-01-02 03:04:05+00:00").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");

    assert_eq!(map.get("iso8601").unwrap(), "2025-01-02T03:04:05Z");
    assert_eq!(
        map.get("rfc3339").unwrap(),
        &expected_dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    );
    assert_eq!(map.get("iso9075").unwrap(), "2025-01-02 03:04:05+00:00");
}

#[test]
fn convert_timestamp_internal_from_rfc7231() {
    let map = convert_timestamp_internal("rfc7231", "Thu, 02 Jan 2025 03:04:05 GMT").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");

    assert_eq!(map.get("iso8601").unwrap(), "2025-01-02T03:04:05Z");
    assert_eq!(
        map.get("rfc3339").unwrap(),
        &expected_dt.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
    );
    assert_eq!(map.get("rfc7231").unwrap(), "Thu, 02 Jan 2025 03:04:05 GMT");
}

#[test]
fn parse_iso9075_timestamp_with_timezone() {
    let dt = parse_iso9075_timestamp("2025-01-02 03:04:05+00:00").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");
    assert_eq!(dt, expected_dt);
}

#[test]
fn parse_iso9075_timestamp_without_timezone() {
    let dt = parse_iso9075_timestamp("2025-01-02 03:04:05").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");
    assert_eq!(dt, expected_dt);
}

#[test]
fn parse_rfc7231_timestamp_gmt() {
    let dt = parse_rfc7231_timestamp("Thu, 02 Jan 2025 03:04:05 GMT").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");
    assert_eq!(dt, expected_dt);
}

#[test]
fn parse_iso8601_timestamp_basic() {
    let dt = parse_iso8601_timestamp("2025-01-02T03:04:05Z").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .single()
        .expect("valid timestamp");
    assert_eq!(dt, expected_dt);
}

#[test]
fn parse_rfc3339_timestamp_with_nanos() {
    let dt = parse_rfc3339_timestamp("2025-01-02T03:04:05.123456789Z").unwrap();
    let expected_dt = Utc
        .with_ymd_and_hms(2025, 1, 2, 3, 4, 5)
        .unwrap()
        .with_nanosecond(123_456_789)
        .unwrap();
    assert_eq!(dt, expected_dt);
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
fn convert_number_base_internal_decimal_100() {
    let bases = convert_number_base_internal("decimal", "100").unwrap();
    assert_eq!(bases.binary, "1100100");
    assert_eq!(bases.octal, "144");
    assert_eq!(bases.decimal, "100");
    assert_eq!(bases.hex, "64");
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

#[test]
fn generate_user_agents_filters_and_limits_results() {
    let all = filter_user_agents("", "");
    assert!(
        all.len() <= 10,
        "expected at most 10 results, got {}",
        all.len()
    );

    let filtered = filter_user_agents("ChRoMe", "MACOS");
    assert!(!filtered.is_empty(), "expected filtered results");
    for ua in filtered {
        assert_eq!(ua.browser_name, "chrome");
        assert_eq!(ua.os_name, "macos");
    }
}

#[test]
fn hash_content_map_produces_known_digests() {
    let map = hash_content_map(b"abc");
    assert_eq!(
        map.get("md5"),
        Some(&"900150983cd24fb0d6963f7d28e17f72".into())
    );
    assert_eq!(
        map.get("sha1"),
        Some(&"a9993e364706816aba3e25717850c26c9cd0d89d".into())
    );
    assert_eq!(map.get("crc32_ieee"), Some(&"352441c2".into()));
}

#[test]
fn hash_content_hmac_matches_reference() {
    let map = hash_hmac_map(b"message", b"secret");
    assert_eq!(
        map.get("sha256"),
        Some(&"8b5f48702995c1598c573db1e21866a9b825d4a794d169d7060a03605796360b".into())
    );
    assert_eq!(
        map.get("sha1"),
        Some(&"0caf649feee4953d87bf903ac1176c45e028df16".into())
    );
}

#[test]
fn hash_content_bytes_matches_text_hashes() {
    // Hashing raw bytes should match the exact digests produced for text input.
    let file_map = hash_content_map(b"abc");
    let text_map = hash_content_map("abc".as_bytes());
    assert_eq!(file_map, text_map);
}

#[test]
fn hash_content_hmac_bytes_matches_text() {
    let file_map = hash_hmac_map(b"payload", b"topsecret");
    let text_map = hash_hmac_map("payload".as_bytes(), b"topsecret");
    assert_eq!(file_map.get("sha256"), text_map.get("sha256"));
    assert_eq!(file_map.get("sha1"), text_map.get("sha1"));
}

#[test]
fn encrypt_bytes_internal_aes_roundtrip() {
    let key_bytes = [0x11u8; 32];
    let nonce_bytes = [0x22u8; 12];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
    let plaintext = b"secret memo";
    let output = encrypt_bytes_internal(
        "aes-256-gcm",
        plaintext,
        Some(key_b64.clone()),
        Some(nonce_b64.clone()),
    )
    .expect("encrypt ok");
    assert_eq!(output.algorithm, "aes-256-gcm");
    assert_eq!(output.key_b64, key_b64);
    assert_eq!(output.nonce_b64, nonce_b64);

    let decrypted =
        decrypt_bytes_internal("aes-256-gcm", &output.ciphertext_b64, &key_b64, &nonce_b64)
            .expect("decrypt ok");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn encrypt_bytes_internal_chacha_roundtrip() {
    let key_bytes = [0xABu8; 32];
    let nonce_bytes = [0xCDu8; 12];
    let key_b64 = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(nonce_bytes);
    let plaintext = b"file-bytes";
    let output = encrypt_bytes_internal(
        "chacha20-poly1305",
        plaintext,
        Some(key_b64.clone()),
        Some(nonce_b64.clone()),
    )
    .expect("encrypt ok");
    let decrypted = decrypt_bytes_internal(
        "chacha20-poly1305",
        &output.ciphertext_b64,
        &key_b64,
        &nonce_b64,
    )
    .expect("decrypt ok");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn xchacha_nonce_length_is_validated() {
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0x33u8; 32]);
    let short_nonce = base64::engine::general_purpose::STANDARD.encode([0x44u8; 12]);
    let err = encrypt_bytes_internal(
        "xchacha20-poly1305",
        b"plaintext",
        Some(key_b64),
        Some(short_nonce),
    )
    .unwrap_err();
    assert!(
        err.contains("24 bytes"),
        "expected nonce length error, got {err}"
    );
}

#[test]
fn decrypt_bytes_internal_rejects_empty_key() {
    let err = decrypt_bytes_internal("aes-256-gcm", "Zm9v", "", "").unwrap_err();
    assert!(err.contains("key is required"), "msg: {err}");
}

#[test]
fn convert_timestamp_internal_parses_epoch_millis() {
    let map = convert_timestamp_internal("timestamp_milliseconds", "1735689600000").unwrap();
    assert_eq!(map.get("sql_date").unwrap(), "2025-01-01");
    assert_eq!(map.get("timestamp_seconds").unwrap(), "1735689600");
}

#[test]
fn convert_timestamp_internal_accepts_rfc2822() {
    let map = convert_timestamp_internal("rfc2822", "Wed, 02 Oct 2002 13:00:00 GMT").unwrap();
    assert_eq!(map.get("sql_date").unwrap(), "2002-10-02");
    assert_eq!(map.get("timestamp_seconds").unwrap(), "1033563600");
}

#[test]
fn ipv4_info_parses_cidr_and_calculates_hosts() {
    let info = ip_info_internal("10.0.0.1/30").unwrap();
    assert_eq!(info.kind.unwrap(), "network");
    assert_eq!(info.range_start.unwrap(), "10.0.0.0");
    assert_eq!(info.range_end.unwrap(), "10.0.0.3");
    assert_eq!(info.total.unwrap(), "4");
}

#[test]
fn ipv6_with_prefix_sets_host_bits() {
    let info = ip_info_internal("2001:db8::1/64").unwrap();
    assert_eq!(info.version.unwrap(), "IPv6");
    assert_eq!(info.host_bits.unwrap(), "64");
    assert_eq!(info.range_start.unwrap(), "2001:db8::");
}

#[test]
fn random_sequences_internal_rejects_excessive_minimums() {
    let err =
        random_sequences_internal(3, 1, true, "123", false, false, "", "", 2, 2, 0, 0).unwrap_err();
    assert!(err.contains("Minimum character counts exceed requested length"));
}

#[test]
fn random_sequences_internal_disallows_leading_zero_only_pool() {
    let err =
        random_sequences_internal(2, 1, false, "0", false, false, "", "", 0, 0, 0, 0).unwrap_err();
    assert!(err.contains("No valid leading character available"));
}

#[test]
fn random_sequences_internal_requires_digits_when_requested() {
    let err =
        random_sequences_internal(4, 1, true, "", false, false, "", "", 1, 0, 0, 0).unwrap_err();
    assert!(err.contains("No digits available to satisfy minimum requirement"));
}

#[test]
fn totp_token_internal_validates_inputs() {
    let err = totp_token_internal("", "SHA256", 30, 6).unwrap_err();
    assert!(err.contains("secret cannot be empty"));

    let err = totp_token_internal("JBSWY3DPEHPK3PXP", "SHA256", 0, 6).unwrap_err();
    assert!(err.contains("period must be between 1 and 300"));

    let err = totp_token_internal("JBSWY3DPEHPK3PXP", "SHA256", 30, 3).unwrap_err();
    assert!(err.contains("digits must be between 4 and 10"));
}

#[test]
fn qr_code_internal_produces_png_with_otpauth() {
    // Ensure the QR helper preserves the otpauth URI and PNG signature.
    let qr = generate_qr_code_internal(
        "otp",
        "png",
        QrRequest {
            otp_account: Some("demo".into()),
            otp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            otp_issuer: Some("Transform".into()),
            otp_algorithm: Some("SHA1".into()),
            otp_period: Some(30),
            otp_digits: Some(6),
            ..Default::default()
        },
    )
    .expect("qr generated");

    assert_eq!(qr.format, "png");
    assert_eq!(qr.mime, "image/png");
    assert_eq!(qr.width, QR_CODE_SIZE);
    assert_eq!(qr.height, QR_CODE_SIZE);
    assert!(qr.payload.starts_with("otpauth://totp/Transform:demo"));
    assert!(qr.data_url.starts_with("data:image/png;base64,"));

    let bytes = B64_STD
        .decode(qr.data_base64.as_bytes())
        .expect("decode png");
    assert!(
        bytes.starts_with(b"\x89PNG\r\n\x1a\n"),
        "png header must be present"
    );
}

#[test]
fn qr_code_internal_escapes_wifi_payload() {
    // WiFi QR codes must escape separators so they remain parseable on scan.
    let qr = generate_qr_code_internal(
        "wifi",
        "svg",
        QrRequest {
            wifi_type: Some("WPA".into()),
            wifi_pass: Some("p@ss;word".into()),
            wifi_ssid: Some("Cafe;Net".into()),
            ..Default::default()
        },
    )
    .expect("wifi qr");

    assert_eq!(qr.format, "svg");
    assert_eq!(qr.mime, "image/svg+xml");
    assert!(qr.payload.contains("Cafe\\;Net"));
    assert!(qr.payload.contains("p@ss\\;word"));
    assert!(qr.data_url.starts_with("data:image/svg+xml;base64,"));

    let svg_bytes = B64_STD
        .decode(qr.data_base64.as_bytes())
        .expect("decode svg");
    let svg_text = String::from_utf8(svg_bytes).expect("utf8 svg");
    assert!(svg_text.contains("<svg"), "SVG payload should render");
}

#[test]
fn qr_code_internal_outputs_webp_signature() {
    // WebP output should include the RIFF/WEBP signature bytes for download validation.
    let qr = generate_qr_code_internal(
        "custom",
        "webp",
        QrRequest {
            custom_string: Some("hello webp".into()),
            ..Default::default()
        },
    )
    .expect("webp qr");

    assert_eq!(qr.format, "webp");
    assert_eq!(qr.mime, "image/webp");
    let bytes = B64_STD
        .decode(qr.data_base64.as_bytes())
        .expect("decode webp");
    assert!(bytes.starts_with(b"RIFF"));
    assert!(bytes.len() > 12 && &bytes[8..12] == b"WEBP");
}

#[test]
fn inspect_certificates_parses_chain_and_links_issuer() {
    const CHAIN: &str = include_str!("../tests/fixtures/test_chain.pem");
    let summaries = cert::inspect_certificates_internal(CHAIN).expect("chain parsed");
    assert_eq!(summaries.len(), 2, "expected leaf + root");

    let leaf = &summaries[0];
    assert_eq!(
        leaf.subject_common_name.as_deref(),
        Some("transform.test"),
        "leaf CN should match request"
    );
    assert_eq!(
        leaf.issuer_common_name.as_deref(),
        Some("Transform Root CA"),
        "leaf issuer should be root CN"
    );
    assert!(
        leaf.subject_alt_names
            .iter()
            .any(|val| val.contains("transform.test")),
        "SAN should include DNS names"
    );
    assert_eq!(
        leaf.issuer_position,
        Some(2),
        "authority key id should map to root position"
    );
    assert!(
        !leaf.fingerprints.sha256.is_empty(),
        "fingerprints should be present"
    );
}

#[test]
fn convert_timestamp_internal_now_returns_current_time() {
    let map = convert_timestamp_internal("now", "").unwrap();

    // Check that all expected keys are present
    assert!(map.contains_key("iso8601"));
    assert!(map.contains_key("rfc3339"));
    assert!(map.contains_key("rfc2822"));
    assert!(map.contains_key("iso9075"));
    assert!(map.contains_key("rfc7231"));
    assert!(map.contains_key("sql_datetime"));
    assert!(map.contains_key("sql_date"));
    assert!(map.contains_key("timestamp_seconds"));
    assert!(map.contains_key("timestamp_milliseconds"));
    assert!(map.contains_key("timestamp_microseconds"));
    assert!(map.contains_key("timestamp_nanoseconds"));

    // Verify year is recent (>= 2024)
    let iso = map.get("iso8601").unwrap();
    assert!(iso.starts_with("202") || iso.starts_with("203")); // Covers 2020-2039

    // Verify RFC 3339 contains nanoseconds (dot followed by digits)
    let rfc3339 = map.get("rfc3339").unwrap();
    assert!(rfc3339.contains('.'));
    // Ensure it ends with Z
    assert!(rfc3339.ends_with('Z'));
}
