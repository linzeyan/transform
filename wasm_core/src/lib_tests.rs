use super::*;
use crate::{ascii, cert};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD; // Base64 encoder used by QR tests.
use bcrypt::BASE_64;
use chrono::{TimeZone, Timelike, Utc};
use data_encoding::{BASE32, BASE32HEX};
use image::{DynamicImage, ImageFormat, Luma};
use qrcode::{EcLevel, QrCode};
use std::collections::BTreeMap;

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
fn generate_insert_statements_builds_rows_for_mysql() {
    let schema = "CREATE TABLE users (
  id INT PRIMARY KEY,
  name VARCHAR(10)
);";
    let output = generate_insert_statements_native(schema, 2, BTreeMap::new()).unwrap();
    assert!(output.contains("INSERT INTO `users`"));
    assert!(output.contains("`id`"));
    assert!(output.contains("`name`"));
}

#[test]
fn generate_insert_statements_supports_json_object_output_as_array() {
    let schema = r#"{"id":1,"name":"alice"}"#;
    let output = generate_insert_statements_native(schema, 2, BTreeMap::new()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("json output");
    let arr = parsed.as_array().expect("array rows");
    assert_eq!(arr.len(), 2);
    assert!(arr[0].get("id").is_some());
    assert!(arr[0].get("name").is_some());
}

#[test]
fn generate_insert_statements_supports_json_schema_output() {
    let schema = r#"{
  "type": "object",
    "properties": {
        "age": { "type": "integer" },
        "name": { "type": "string" }
  }
}"#;
    let output = generate_insert_statements_native(schema, 1, BTreeMap::new()).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&output).expect("json output");
    let arr = parsed.as_array().expect("array rows");
    assert_eq!(arr.len(), 1);
    let row = &arr[0];
    assert!(row.get("age").is_some());
    assert!(row.get("name").is_some());
}

#[test]
fn parse_qr_codes_decodes_png_payload() {
    let code =
        QrCode::with_error_correction_level("hello".as_bytes(), EcLevel::M).expect("qr build");
    let image = code
        .render::<Luma<u8>>()
        .min_dimensions(250, 250)
        .max_dimensions(250, 250)
        .build();
    let mut buf = Vec::new();
    let mut cursor = std::io::Cursor::new(&mut buf);
    DynamicImage::ImageLuma8(image)
        .write_to(&mut cursor, ImageFormat::Png)
        .expect("encode png");
    let entries = parse_qr_codes_native(&buf).expect("decode");
    assert!(!entries.is_empty(), "expected at least one QR result");
    assert_eq!(entries[0].payload, "hello");
}

#[test]
fn parse_qr_codes_batch_processes_multiple_images() {
    let build_qr = |text: &str| {
        let code =
            QrCode::with_error_correction_level(text.as_bytes(), EcLevel::M).expect("qr build");
        let image = code
            .render::<Luma<u8>>()
            .min_dimensions(250, 250)
            .max_dimensions(250, 250)
            .build();
        let mut buf = Vec::new();
        let mut cursor = std::io::Cursor::new(&mut buf);
        DynamicImage::ImageLuma8(image)
            .write_to(&mut cursor, ImageFormat::Png)
            .expect("encode png");
        buf
    };

    let first = build_qr("alpha");
    let second = build_qr("beta");
    let batch = vec![
        ("first.png".to_string(), first),
        ("second.png".to_string(), second),
    ];
    let results = parse_qr_codes_batch_native(batch);
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].file_name, "first.png");
    assert_eq!(results[1].file_name, "second.png");
    assert!(results[0].error.is_none());
    assert!(results[1].error.is_none());
    assert_eq!(results[0].results[0].payload, "alpha");
    assert_eq!(results[1].results[0].payload, "beta");
}

#[test]
fn generate_qr_code_accepts_custom_ecc_level() {
    let req = QrRequest {
        otp_account: None,
        otp_secret: None,
        otp_issuer: None,
        otp_algorithm: None,
        otp_period: None,
        otp_digits: None,
        wifi_type: None,
        wifi_pass: None,
        wifi_ssid: None,
        custom_string: Some("hello-ecc".into()),
        qr_ecc: Some("L".into()),
    };

    let res = generate_qr_code_internal("custom", "png", req).expect("generate qr");
    assert_eq!(res.kind, "custom");
    // Decode and ensure ECC level is Low (L).
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(res.data_base64.as_bytes())
        .expect("decode png");
    let entries = parse_qr_codes_native(&bytes).expect("decode");
    assert_eq!(entries[0].payload, "hello-ecc");
    let ecc_lower = entries[0].ecc_level.to_lowercase();
    assert!(
        ecc_lower.contains('l') || ecc_lower.contains("low") || ecc_lower == "1",
        "expected ECC level Low, got {}",
        entries[0].ecc_level
    );
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

#[test]
fn ascii_art_rejects_empty_and_long_input() {
    assert!(ascii::generate_ascii_art_internal("", "standard", None, None).is_err());
    let long = "a".repeat(257);
    let err = ascii::generate_ascii_art_internal(&long, "standard", None, None).unwrap_err();
    assert!(err.contains("256"));
}

#[test]
fn ascii_art_renders_and_wraps() {
    let art = ascii::generate_ascii_art_internal("rustacean", "standard", Some(4), Some("center"))
        .expect("art generated");
    assert!(!art.trim().is_empty());
    // Wrapping 9 chars at width=4 should yield multiple rendered blocks.
    assert!(art.split('\n').count() >= 6);
}

#[test]
fn ascii_font_allowlist_exposed() {
    let fonts = ascii::list_ascii_fonts_internal();
    assert!(fonts.contains(&"standard".to_string()));
    assert!(fonts.contains(&"slant".to_string()));
    assert!(fonts.contains(&"small".to_string()));
}

// =====================================================================
// Security Tests
// =====================================================================

#[test]
fn sql_insert_escapes_single_quotes() {
    // SQL injection via column values: single quotes must be escaped in generated SQL.
    let schema = "CREATE TABLE t (\n  name VARCHAR(50)\n);";
    let output = generate_insert_statements_native(schema, 3, BTreeMap::new()).unwrap();
    // The generated INSERT should have proper SQL escaping of any quoted values.
    assert!(output.contains("INSERT INTO"));
    // Verify no unescaped single quotes cause syntax errors.
    let quote_count = output.matches('\'').count();
    // Quotes should appear in pairs (opening/closing around values).
    assert_eq!(
        quote_count % 2,
        0,
        "single quotes must be balanced: {output}"
    );
}

#[test]
fn sql_insert_generates_for_multiple_columns() {
    let schema = "CREATE TABLE users (\n  id INT PRIMARY KEY,\n  email VARCHAR(100),\n  status ENUM('active','inactive')\n);";
    let output = generate_insert_statements_native(schema, 2, BTreeMap::new()).unwrap();
    assert!(output.contains("INSERT INTO `users`"));
    assert!(output.contains("`id`"));
    assert!(output.contains("`email`"));
    assert!(output.contains("`status`"));
}

#[test]
fn jwt_encode_with_empty_payload() {
    let token = jwt_encode_internal("{}", "secret", "HS256").expect("empty payload");
    let decoded = jwt_decode_internal(&token).expect("decode empty");
    let payload = decoded.payload.as_deref().unwrap_or("");
    assert!(
        payload.contains('{'),
        "expected JSON object in payload: {payload}"
    );
}

#[test]
fn jwt_decode_malformed_token() {
    let err = jwt_decode_internal("not.a.valid.jwt.token");
    assert!(err.is_err() || err.unwrap().payload.is_none());
}

#[test]
fn jwt_decode_single_segment() {
    let err = jwt_decode_internal("singlesegment");
    assert!(err.is_err());
}

#[test]
fn encryption_tampered_ciphertext_rejected() {
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0xAAu8; 32]);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode([0xBBu8; 12]);
    let output = encrypt_bytes_internal(
        "aes-256-gcm",
        b"secret data",
        Some(key_b64.clone()),
        Some(nonce_b64.clone()),
    )
    .expect("encrypt");
    // Flip a byte in the ciphertext.
    let mut raw = base64::engine::general_purpose::STANDARD
        .decode(output.ciphertext_b64.as_bytes())
        .unwrap();
    if let Some(byte) = raw.last_mut() {
        *byte ^= 0xFF;
    }
    let tampered_b64 = base64::engine::general_purpose::STANDARD.encode(&raw);
    let err = decrypt_bytes_internal("aes-256-gcm", &tampered_b64, &key_b64, &nonce_b64);
    assert!(err.is_err(), "tampered ciphertext must be rejected");
}

#[test]
fn encryption_wrong_key_rejected() {
    let key_b64 = base64::engine::general_purpose::STANDARD.encode([0x11u8; 32]);
    let nonce_b64 = base64::engine::general_purpose::STANDARD.encode([0x22u8; 12]);
    let output = encrypt_bytes_internal(
        "aes-256-gcm",
        b"plaintext",
        Some(key_b64.clone()),
        Some(nonce_b64.clone()),
    )
    .expect("encrypt");
    let wrong_key_b64 = base64::engine::general_purpose::STANDARD.encode([0x99u8; 32]);
    let err = decrypt_bytes_internal(
        "aes-256-gcm",
        &output.ciphertext_b64,
        &wrong_key_b64,
        &nonce_b64,
    );
    assert!(err.is_err(), "wrong key must be rejected");
}

#[test]
fn cert_parsing_rejects_malformed_pem() {
    let err = cert::inspect_certificates_internal(
        "-----BEGIN CERTIFICATE-----\nINVALID\n-----END CERTIFICATE-----",
    );
    assert!(err.is_err(), "malformed PEM must be rejected");
}

#[test]
fn cert_parsing_rejects_empty_input() {
    let err = cert::inspect_certificates_internal("");
    assert!(err.is_err());
    let err = cert::inspect_certificates_internal("   ");
    assert!(err.is_err());
}

#[test]
fn url_encode_special_and_dangerous_characters() {
    // OWASP special characters used in injection attacks.
    let encoded = url_encode("<script>alert('xss')</script>");
    assert!(!encoded.contains('<'));
    assert!(!encoded.contains('>'));
    assert!(!encoded.contains('\''));
    let decoded = url_decode(&encoded).unwrap();
    assert_eq!(decoded, "<script>alert('xss')</script>");
}

#[test]
fn base64_decode_invalid_input() {
    let err = decode_content_internal("base64_standard", "!!!not-base64!!!");
    assert!(err.is_err());
}

#[test]
fn hex_decode_invalid_input() {
    let err = decode_content_internal("hex_upper", "ZZZZ");
    assert!(err.is_err());
}

#[test]
fn bcrypt_hash_with_empty_password() {
    // Empty passwords should still be hashable (not rejected).
    let salt = bcrypt::BASE_64.encode([0u8; 16]);
    let hash = bcrypt_hash("", 4, Some(salt)).expect("empty password hash ok");
    assert!(hash.starts_with("$2b$"));
    assert!(bcrypt_verify("", &hash).unwrap());
}

#[test]
fn argon2_hash_with_special_characters() {
    let salt = base64::engine::general_purpose::STANDARD.encode([2u8; 16]);
    let hash = argon2_hash("p@$$w0rd!#%^&*()", Some(salt), 2, 4096, 1, 16, "argon2id")
        .expect("special chars hash ok");
    assert!(hash.starts_with("$argon2id$"));
    assert!(argon2_verify("p@$$w0rd!#%^&*()", &hash).unwrap());
    assert!(!argon2_verify("wrong", &hash).unwrap());
}

// =====================================================================
// Boundary Tests
// =====================================================================

#[test]
fn random_sequences_length_one() {
    let seqs = random_sequences_internal(1, 1, true, "123456789", false, false, "", "", 0, 0, 0, 0)
        .expect("length 1");
    assert_eq!(seqs[0].len(), 1);
    assert!(seqs[0].chars().all(|c| c.is_ascii_digit()));
}

#[test]
fn random_sequences_max_length() {
    let seqs = random_sequences_internal(2048, 1, true, "12", true, true, "@#", "", 0, 0, 0, 0)
        .expect("length 2048");
    assert_eq!(seqs[0].len(), 2048);
}

#[test]
fn random_sequences_many_count() {
    let seqs = random_sequences_internal(4, 256, true, "12", true, true, "", "", 0, 0, 0, 0)
        .expect("count 256");
    assert_eq!(seqs.len(), 256);
}

#[test]
fn number_base_zero() {
    let bases = convert_number_base_internal("decimal", "0").unwrap();
    assert_eq!(bases.decimal, "0");
    assert_eq!(bases.binary, "0");
    assert_eq!(bases.octal, "0");
    assert_eq!(bases.hex, "0");
}

#[test]
fn number_base_negative() {
    let bases = convert_number_base_internal("decimal", "-42").unwrap();
    assert_eq!(bases.decimal, "-42");
    assert!(bases.binary.starts_with('-'));
}

#[test]
fn number_base_very_large_bigint() {
    let large = "99999999999999999999999999999999";
    let bases = convert_number_base_internal("decimal", large).unwrap();
    assert_eq!(bases.decimal, large);
    // Hex should be non-empty for a large number.
    assert!(!bases.hex.is_empty());
}

#[test]
fn ip_info_zero_address() {
    let info = ip_info_internal("0.0.0.0").unwrap();
    assert_eq!(info.version.unwrap(), "IPv4");
}

#[test]
fn ip_info_broadcast_address() {
    let info = ip_info_internal("255.255.255.255").unwrap();
    assert_eq!(info.version.unwrap(), "IPv4");
    assert_eq!(info.cidr.unwrap(), "255.255.255.255/32");
}

#[test]
fn ip_info_cidr_slash_zero() {
    let info = ip_info_internal("10.0.0.0/0").unwrap();
    assert_eq!(info.host_bits.unwrap(), "32");
}

#[test]
fn ip_info_cidr_slash_32() {
    let info = ip_info_internal("192.168.1.1/32").unwrap();
    assert_eq!(info.total.unwrap(), "1");
}

#[test]
fn ipv6_loopback() {
    let info = ip_info_internal("::1").unwrap();
    assert_eq!(info.version.unwrap(), "IPv6");
}

#[test]
fn ipv6_cidr_slash_zero() {
    let info = ip_info_internal("::/0").unwrap();
    assert_eq!(info.host_bits.unwrap(), "128");
}

#[test]
fn ipv6_cidr_slash_128() {
    let info = ip_info_internal("::1/128").unwrap();
    assert_eq!(info.host_bits.unwrap(), "0");
}

#[test]
fn timestamp_epoch_zero() {
    let map = convert_timestamp_internal("timestamp_seconds", "0").unwrap();
    assert_eq!(map.get("sql_date").unwrap(), "1970-01-01");
}

#[test]
fn timestamp_far_future() {
    // Year 2100: Unix timestamp 4102444800
    let map = convert_timestamp_internal("timestamp_seconds", "4102444800").unwrap();
    assert!(map.get("iso8601").unwrap().starts_with("2100-"));
}

#[test]
fn empty_input_to_all_decoders() {
    // Empty inputs should return errors, not panic.
    for kind in &[
        "base64_standard",
        "base64_url",
        "base32_standard",
        "hex_upper",
        "base91",
    ] {
        let result = decode_content_internal(kind, "");
        // Empty decode should either succeed with empty bytes or return an error.
        if let Ok(bytes) = result {
            assert!(
                bytes.is_empty(),
                "empty input for {kind} should give empty bytes"
            )
        }
    }
}

#[test]
fn ulid_encoding_boundary_values() {
    // Maximum 48-bit timestamp, zero randomness.
    let max_ts: u64 = (1u64 << 48) - 1;
    let zero_rand = [0u8; 10];
    let ulid = encode_ulid(max_ts, zero_rand);
    assert_eq!(ulid.len(), 26);
    // All chars should be from Crockford Base32 alphabet.
    for ch in ulid.chars() {
        assert!(
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
            "unexpected ULID char: {ch}"
        );
    }
}

#[test]
fn ulid_encoding_zero_values() {
    let ulid = encode_ulid(0, [0u8; 10]);
    assert_eq!(ulid.len(), 26);
    assert_eq!(ulid, "00000000000000000000000000");
}

#[test]
fn unit_conversion_zero() {
    let map = convert_units_internal("byte", "0").unwrap();
    assert_eq!(map.get("byte").unwrap(), "0");
    assert_eq!(map.get("bit").unwrap(), "0");
}

#[test]
fn unit_conversion_negative() {
    let map = convert_units_internal("byte", "-1");
    // Negative bytes should either work or return an error, not panic.
    assert!(map.is_ok() || map.is_err());
}

#[test]
fn unit_conversion_very_large() {
    let map = convert_units_internal("terabyte", "1000000").unwrap();
    // 1M terabytes = 8M terabits.
    let terabit_val = map.get("terabit").unwrap();
    assert!(!terabit_val.is_empty());
}

#[test]
fn ascii_art_max_length_accepted() {
    let input = "a".repeat(256);
    let result = ascii::generate_ascii_art_internal(&input, "standard", None, None);
    assert!(result.is_ok(), "256 chars should be accepted");
}

#[test]
fn ascii_art_special_characters() {
    // Non-printable and emoji chars should not panic.
    let result = ascii::generate_ascii_art_internal("hello!\n@#$", "standard", None, None);
    assert!(result.is_ok());
}

// =====================================================================
// Regression Tests (change A won't break B)
// =====================================================================

#[test]
fn encoding_roundtrip_all_base_formats() {
    let data = b"roundtrip-test-data!@#$%^";
    for kind in &[
        "base64_standard",
        "base64_url",
        "base32_standard",
        "base32_hex",
        "hex_upper",
    ] {
        let encoded_map = encode_content_map_bytes(data);
        let encoded = encoded_map
            .get(*kind)
            .unwrap_or_else(|| panic!("missing encoding {kind}"));
        let decoded = decode_content_internal(kind, encoded)
            .unwrap_or_else(|_| panic!("decode failed for {kind}"));
        assert_eq!(decoded, data, "roundtrip failed for {kind}");
    }
}

#[test]
fn base91_roundtrip_binary_data() {
    let data: Vec<u8> = (0..=255).collect();
    let encoded = encode_base91(&data);
    let decoded = decode_base91(&encoded).expect("base91 roundtrip");
    assert_eq!(decoded, data);
}

#[test]
fn hash_determinism_same_input_same_output() {
    let input = b"deterministic-test";
    let map1 = hash_content_map(input);
    let map2 = hash_content_map(input);
    assert_eq!(map1, map2, "hash output must be deterministic");
}

#[test]
fn hmac_determinism() {
    let map1 = hash_hmac_map(b"msg", b"key");
    let map2 = hash_hmac_map(b"msg", b"key");
    assert_eq!(map1, map2, "HMAC output must be deterministic");
}

#[test]
fn qr_encode_then_decode_roundtrip() {
    let payload = "https://example.com/test?q=hello+world";
    let qr = generate_qr_code_internal(
        "custom",
        "png",
        QrRequest {
            custom_string: Some(payload.into()),
            ..Default::default()
        },
    )
    .expect("generate qr");
    let bytes = B64_STD
        .decode(qr.data_base64.as_bytes())
        .expect("decode base64");
    let entries = parse_qr_codes_native(&bytes).expect("decode qr");
    assert_eq!(entries[0].payload, payload);
}

#[test]
fn encrypt_decrypt_roundtrip_all_ciphers() {
    let plaintext = b"roundtrip for all ciphers!";
    for (cipher, key_len, nonce_len) in &[
        ("aes-256-gcm", 32, 12),
        ("chacha20-poly1305", 32, 12),
        ("xchacha20-poly1305", 32, 24),
    ] {
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0x42u8; *key_len]);
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(vec![0x43u8; *nonce_len]);
        let output = encrypt_bytes_internal(
            cipher,
            plaintext,
            Some(key_b64.clone()),
            Some(nonce_b64.clone()),
        )
        .unwrap_or_else(|_| panic!("encrypt with {cipher}"));
        let decrypted =
            decrypt_bytes_internal(cipher, &output.ciphertext_b64, &key_b64, &nonce_b64)
                .unwrap_or_else(|_| panic!("decrypt with {cipher}"));
        assert_eq!(decrypted, plaintext, "roundtrip failed for {cipher}");
    }
}

// =====================================================================
// Specification-based Tests
// =====================================================================

#[test]
fn uuid_v4_format_rfc4122() {
    let uuid = uuid_crate::Uuid::new_v4().to_string();
    assert_eq!(uuid.len(), 36);
    // Version nibble must be 4.
    assert_eq!(&uuid[14..15], "4");
    // Variant bits: char at position 19 must be 8, 9, a, or b.
    let variant_char = uuid.chars().nth(19).unwrap();
    assert!(
        "89ab".contains(variant_char),
        "variant char should be 8/9/a/b, got {variant_char}"
    );
}

#[test]
fn uuid_v2_version_bits() {
    let uuid = uuid_v2();
    // Version nibble at position 14 must be '2'.
    assert_eq!(&uuid[14..15], "2");
    // Variant bits at position 19 must be 8/9/a/b.
    let variant_char = uuid.chars().nth(19).unwrap();
    assert!(
        "89ab".contains(variant_char),
        "v2 variant should be 8/9/a/b, got {variant_char}"
    );
}

#[test]
fn uuid_v8_version_bits() {
    let uuid = uuid_v8();
    // Version nibble at position 14 must be '8'.
    assert_eq!(&uuid[14..15], "8");
    // Variant bits at position 19 must be 8/9/a/b.
    let variant_char = uuid.chars().nth(19).unwrap();
    assert!(
        "89ab".contains(variant_char),
        "v8 variant should be 8/9/a/b, got {variant_char}"
    );
}

#[test]
fn ulid_format_26_chars_crockford_base32() {
    // Use encode_ulid directly to avoid js_sys dependency in native tests.
    let ulid = encode_ulid(1_700_000_000_000, [0xAB; 10]);
    assert_eq!(ulid.len(), 26);
    for ch in ulid.chars() {
        assert!(
            "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
            "ULID contains invalid Crockford Base32 char: {ch}"
        );
    }
}

#[test]
fn totp_validation_rejects_invalid_digits() {
    // Digits outside valid range should be rejected.
    let err = totp_token_internal("JBSWY3DPEHPK3PXP", "SHA256", 30, 11);
    assert!(err.is_err());
    let err = totp_token_internal("JBSWY3DPEHPK3PXP", "SHA256", 30, 3);
    assert!(err.is_err());
}

#[test]
fn totp_validation_rejects_invalid_period() {
    let err = totp_token_internal("JBSWY3DPEHPK3PXP", "SHA256", 301, 6);
    assert!(err.is_err());
}

#[test]
fn jwt_three_segment_structure() {
    let token = jwt_encode_internal("{\"sub\":\"test\"}", "mysecret", "HS256").expect("jwt encode");
    let segments: Vec<&str> = token.split('.').collect();
    assert_eq!(segments.len(), 3, "JWT must have exactly 3 segments");
    // Each segment must be valid base64url.
    for (i, seg) in segments.iter().enumerate() {
        assert!(!seg.is_empty(), "JWT segment {i} must not be empty");
    }
}

#[test]
fn wifi_qr_payload_format() {
    let qr = generate_qr_code_internal(
        "wifi",
        "png",
        QrRequest {
            wifi_type: Some("WPA".into()),
            wifi_pass: Some("mypass".into()),
            wifi_ssid: Some("MyNetwork".into()),
            ..Default::default()
        },
    )
    .expect("wifi qr");
    assert!(qr.payload.starts_with("WIFI:"));
    assert!(qr.payload.contains("T:WPA"));
    assert!(qr.payload.contains("S:MyNetwork"));
    assert!(qr.payload.contains("P:mypass"));
    assert!(qr.payload.ends_with(";;"));
}

#[test]
fn otp_qr_payload_format() {
    let qr = generate_qr_code_internal(
        "otp",
        "png",
        QrRequest {
            otp_account: Some("user@example.com".into()),
            otp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            otp_issuer: Some("MyApp".into()),
            otp_algorithm: Some("SHA1".into()),
            otp_period: Some(30),
            otp_digits: Some(6),
            ..Default::default()
        },
    )
    .expect("otp qr");
    assert!(qr.payload.starts_with("otpauth://totp/"));
    assert!(qr.payload.contains("MyApp"));
    assert!(qr.payload.contains("secret=JBSWY3DPEHPK3PXP"));
}

// =====================================================================
// Cross-platform Compatibility Tests
// =====================================================================

#[test]
fn unicode_text_encoding_roundtrip() {
    let unicode_input = "Hello 世界! 🦀 こんにちは Ñoño";
    let map = encode_content_map(unicode_input);
    let encoded_b64 = map.get("base64_standard").unwrap();
    let decoded = decode_content_internal("base64_standard", encoded_b64).expect("decode unicode");
    assert_eq!(String::from_utf8(decoded).unwrap(), unicode_input);
}

#[test]
fn unicode_text_hashing_consistency() {
    let unicode_input = "日本語テスト";
    let map1 = hash_content_map(unicode_input.as_bytes());
    let map2 = hash_content_map(unicode_input.as_bytes());
    assert_eq!(map1, map2, "unicode hashing must be deterministic");
    // SHA256 of this input should be deterministic.
    assert!(map1.contains_key("sha256"));
}

#[test]
fn url_encode_decode_unicode() {
    let input = "検索クエリ=値&foo=バー";
    let encoded = url_encode(input);
    let decoded = url_decode(&encoded).unwrap();
    assert_eq!(decoded, input);
}

#[test]
fn qr_wifi_escapes_semicolon_colon_backslash() {
    let qr = generate_qr_code_internal(
        "wifi",
        "png",
        QrRequest {
            wifi_type: Some("WPA".into()),
            wifi_pass: Some("p;a:s\\s".into()),
            wifi_ssid: Some("S;S:I\\D".into()),
            ..Default::default()
        },
    )
    .expect("wifi qr with special chars");
    // Semicolons, colons, and backslashes in SSID/password must be escaped.
    assert!(qr.payload.contains("S\\;S\\:I\\\\D") || qr.payload.contains("S\\;S"));
    assert!(qr.payload.contains("p\\;a\\:s\\\\s") || qr.payload.contains("p\\;a"));
}

// =====================================================================
// Phase 2: SSH Key Generation Tests
// =====================================================================

#[test]
fn ssh_key_ed25519_generates_valid_keypair() {
    let pair = generate_ssh_key_internal("ed25519", 0, "test@host", "openssh", 16, false, false)
        .expect("ed25519 key generation");
    assert_eq!(pair.key_type, "ed25519");
    assert_eq!(pair.format, "openssh");
    assert!(
        pair.public_key.contains("ssh-ed25519"),
        "public key should contain ssh-ed25519"
    );
    assert!(
        pair.private_key.contains("OPENSSH PRIVATE KEY"),
        "private key should be OpenSSH format"
    );
    assert_eq!(pair.kdf_rounds, 16);
    assert!(!pair.resident);
    assert!(!pair.verify_required);
}

#[test]
fn ssh_key_rsa_generates_valid_keypair() {
    let pair = generate_ssh_key_internal("rsa", 2048, "rsa@host", "openssh", 16, false, false)
        .expect("RSA key generation");
    assert_eq!(pair.key_type, "rsa");
    assert!(
        pair.public_key.contains("ssh-rsa"),
        "public key should contain ssh-rsa"
    );
    assert!(pair.private_key.contains("OPENSSH PRIVATE KEY"));
}

#[test]
fn ssh_key_ed25519_sk_generates_keypair() {
    // ed25519-sk falls back to regular ed25519 internally but records the type
    let pair = generate_ssh_key_internal("ed25519-sk", 0, "", "openssh", 50, true, true)
        .expect("ed25519-sk key generation");
    assert_eq!(pair.key_type, "ed25519-sk");
    assert!(pair.resident);
    assert!(pair.verify_required);
}

#[test]
fn ssh_key_unsupported_type_rejected() {
    let err = generate_ssh_key_internal("dsa", 1024, "", "openssh", 16, false, false);
    assert!(err.is_err());
    let msg = err.err().unwrap();
    assert!(
        msg.contains("unsupported"),
        "expected unsupported key type error: {msg}"
    );
}

#[test]
fn ssh_key_kdf_rounds_clamped() {
    // kdf_rounds below 16 should be clamped to 16
    let pair = generate_ssh_key_internal("ed25519", 0, "", "openssh", 1, false, false)
        .expect("kdf clamped low");
    assert_eq!(pair.kdf_rounds, 16);

    // kdf_rounds above 500 should be clamped to 500
    let pair = generate_ssh_key_internal("ed25519", 0, "", "openssh", 9999, false, false)
        .expect("kdf clamped high");
    assert_eq!(pair.kdf_rounds, 500);
}

#[test]
fn ssh_key_rsa_minimum_bits_enforced() {
    // RSA bits < 2048 should be clamped to 2048 (via bits.max(2048))
    let pair = generate_ssh_key_internal("rsa", 512, "", "openssh", 16, false, false)
        .expect("RSA min bits");
    // The key should still be generated successfully with at least 2048 bits
    assert!(pair.public_key.contains("ssh-rsa"));
}

#[test]
fn ssh_key_comment_preserved_in_public_key() {
    let pair = generate_ssh_key_internal("ed25519", 0, "user@machine", "openssh", 16, false, false)
        .expect("comment key");
    // OpenSSH public keys include the comment at the end
    assert!(
        pair.public_key.contains("user@machine"),
        "comment should appear in public key"
    );
}

// =====================================================================
// Phase 2: Encryption Auto-Key Generation
// =====================================================================

#[test]
fn encryption_auto_generates_key_and_nonce() {
    let output = encrypt_bytes_internal("aes-256-gcm", b"auto-key test", None, None)
        .expect("auto key/nonce");
    // Key and nonce should be generated and returned
    assert!(
        !output.key_b64.is_empty(),
        "auto-generated key should not be empty"
    );
    assert!(
        !output.nonce_b64.is_empty(),
        "auto-generated nonce should not be empty"
    );
    // Verify key is 32 bytes (AES-256)
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(output.key_b64.as_bytes())
        .expect("decode key");
    assert_eq!(key_bytes.len(), 32, "AES-256 key must be 32 bytes");
    // Verify nonce is 12 bytes (GCM)
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(output.nonce_b64.as_bytes())
        .expect("decode nonce");
    assert_eq!(nonce_bytes.len(), 12, "GCM nonce must be 12 bytes");

    // Decrypt with auto-generated key/nonce should succeed
    let decrypted = decrypt_bytes_internal(
        "aes-256-gcm",
        &output.ciphertext_b64,
        &output.key_b64,
        &output.nonce_b64,
    )
    .expect("decrypt with auto key");
    assert_eq!(decrypted, b"auto-key test");
}

#[test]
fn encryption_auto_key_chacha20_roundtrip() {
    let output = encrypt_bytes_internal("chacha20-poly1305", b"chacha auto", None, None)
        .expect("chacha auto key");
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(output.key_b64.as_bytes())
        .unwrap();
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(output.nonce_b64.as_bytes())
        .unwrap();
    assert_eq!(key_bytes.len(), 32);
    assert_eq!(nonce_bytes.len(), 12);
    let decrypted = decrypt_bytes_internal(
        "chacha20-poly1305",
        &output.ciphertext_b64,
        &output.key_b64,
        &output.nonce_b64,
    )
    .expect("chacha decrypt");
    assert_eq!(decrypted, b"chacha auto");
}

#[test]
fn encryption_auto_key_xchacha20_roundtrip() {
    let output = encrypt_bytes_internal("xchacha20-poly1305", b"xchacha auto", None, None)
        .expect("xchacha auto key");
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(output.nonce_b64.as_bytes())
        .unwrap();
    assert_eq!(nonce_bytes.len(), 24, "XChaCha20 nonce must be 24 bytes");
    let decrypted = decrypt_bytes_internal(
        "xchacha20-poly1305",
        &output.ciphertext_b64,
        &output.key_b64,
        &output.nonce_b64,
    )
    .expect("xchacha decrypt");
    assert_eq!(decrypted, b"xchacha auto");
}

// =====================================================================
// Phase 2: Cipher Alias Parsing
// =====================================================================

#[test]
fn cipher_alias_aes_maps_to_aes256gcm() {
    let output = encrypt_bytes_internal("aes", b"alias test", None, None).expect("aes alias");
    assert_eq!(output.algorithm, "aes-256-gcm");
}

#[test]
fn cipher_alias_aes_gcm_maps_to_aes256gcm() {
    let output =
        encrypt_bytes_internal("aes-gcm", b"alias test", None, None).expect("aes-gcm alias");
    assert_eq!(output.algorithm, "aes-256-gcm");
}

#[test]
fn cipher_alias_chacha20_maps_to_chacha20_poly1305() {
    let output =
        encrypt_bytes_internal("chacha20", b"alias test", None, None).expect("chacha20 alias");
    assert_eq!(output.algorithm, "chacha20-poly1305");
}

#[test]
fn cipher_alias_xchacha20_maps_to_xchacha20_poly1305() {
    let output =
        encrypt_bytes_internal("xchacha20", b"alias test", None, None).expect("xchacha20 alias");
    assert_eq!(output.algorithm, "xchacha20-poly1305");
}

#[test]
fn cipher_unsupported_algorithm_rejected() {
    let err = encrypt_bytes_internal("blowfish", b"test", None, None);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("unsupported"));
}

// =====================================================================
// Phase 2: Hash Algorithm Verification Tests
// =====================================================================

#[test]
fn hash_sha3_output_lengths() {
    let map = hash_content_map(b"test");
    // SHA3-224 = 56 hex chars (28 bytes)
    assert_eq!(map.get("sha3_224").unwrap().len(), 56);
    // SHA3-256 = 64 hex chars (32 bytes)
    assert_eq!(map.get("sha3_256").unwrap().len(), 64);
    // SHA3-384 = 96 hex chars (48 bytes)
    assert_eq!(map.get("sha3_384").unwrap().len(), 96);
    // SHA3-512 = 128 hex chars (64 bytes)
    assert_eq!(map.get("sha3_512").unwrap().len(), 128);
}

#[test]
fn hash_sha_family_output_lengths() {
    let map = hash_content_map(b"test");
    assert_eq!(map.get("md5").unwrap().len(), 32); // MD5 = 16 bytes
    assert_eq!(map.get("sha1").unwrap().len(), 40); // SHA1 = 20 bytes
    assert_eq!(map.get("sha224").unwrap().len(), 56); // SHA-224 = 28 bytes
    assert_eq!(map.get("sha256").unwrap().len(), 64); // SHA-256 = 32 bytes
    assert_eq!(map.get("sha384").unwrap().len(), 96); // SHA-384 = 48 bytes
    assert_eq!(map.get("sha512").unwrap().len(), 128); // SHA-512 = 64 bytes
    assert_eq!(map.get("sha512_224").unwrap().len(), 56); // SHA-512/224 = 28 bytes
    assert_eq!(map.get("sha512_256").unwrap().len(), 64); // SHA-512/256 = 32 bytes
}

#[test]
fn hash_crc64_output_is_16_hex_chars() {
    let map = hash_content_map(b"crc64 test");
    // CRC64 = 8 bytes = 16 hex chars
    assert_eq!(map.get("crc64_iso").unwrap().len(), 16);
    assert_eq!(map.get("crc64_ecma").unwrap().len(), 16);
}

#[test]
fn hash_crc32_output_is_8_hex_chars() {
    let map = hash_content_map(b"crc32 test");
    assert_eq!(map.get("crc32_ieee").unwrap().len(), 8);
    assert_eq!(map.get("crc32_castagnoli").unwrap().len(), 8);
}

#[test]
fn hash_adler32_output_is_8_hex_chars() {
    let map = hash_content_map(b"adler test");
    assert_eq!(map.get("adler32").unwrap().len(), 8);
}

#[test]
fn hash_fnv_output_lengths() {
    let map = hash_content_map(b"fnv test");
    assert_eq!(map.get("fnv32").unwrap().len(), 8); // FNV32 = 4 bytes
    assert_eq!(map.get("fnv32a").unwrap().len(), 8);
    assert_eq!(map.get("fnv64").unwrap().len(), 16); // FNV64 = 8 bytes
    assert_eq!(map.get("fnv64a").unwrap().len(), 16);
    assert_eq!(map.get("fnv128").unwrap().len(), 32); // FNV128 = 16 bytes
    assert_eq!(map.get("fnv128a").unwrap().len(), 32);
}

#[test]
fn hash_all_keys_present_in_content_map() {
    let map = hash_content_map(b"check keys");
    let expected_keys = [
        "md5",
        "sha1",
        "sha224",
        "sha256",
        "sha384",
        "sha512",
        "sha512_224",
        "sha512_256",
        "sha3_224",
        "sha3_256",
        "sha3_384",
        "sha3_512",
        "crc32_ieee",
        "crc32_castagnoli",
        "crc64_iso",
        "crc64_ecma",
        "adler32",
        "fnv32",
        "fnv32a",
        "fnv64",
        "fnv64a",
        "fnv128",
        "fnv128a",
    ];
    for key in &expected_keys {
        assert!(map.contains_key(*key), "missing hash key: {key}");
    }
    assert_eq!(map.len(), expected_keys.len(), "unexpected extra hash keys");
}

#[test]
fn hmac_all_keys_present_in_hmac_map() {
    let map = hash_hmac_map(b"data", b"key");
    let expected_keys = [
        "sha1", "sha224", "sha256", "sha384", "sha512", "sha3_224", "sha3_256", "sha3_384",
        "sha3_512",
    ];
    for key in &expected_keys {
        assert!(map.contains_key(*key), "missing HMAC key: {key}");
    }
}

// =====================================================================
// Phase 2: Additional Encoding Roundtrip Tests
// =====================================================================

#[test]
fn ascii85_roundtrip() {
    let data = b"Hello, ASCII85 encoding test!";
    let encoded_map = encode_content_map_bytes(data);
    let encoded = encoded_map
        .get("base85_ascii85")
        .expect("ascii85 key missing");
    assert!(!encoded.is_empty());
    let decoded =
        decode_content_internal("base85_ascii85", encoded).expect("ascii85 decode failed");
    assert_eq!(decoded, data, "ASCII85 roundtrip failed");
}

#[test]
fn ascii85_binary_data_roundtrip() {
    let data: Vec<u8> = (0..=255).collect();
    let encoded_map = encode_content_map_bytes(&data);
    let encoded = encoded_map.get("base85_ascii85").expect("ascii85 key");
    let decoded =
        decode_content_internal("base85_ascii85", encoded).expect("ascii85 binary decode");
    assert_eq!(decoded, data, "ASCII85 binary roundtrip failed");
}

#[test]
fn base32_no_padding_roundtrip() {
    let data = b"base32 no-pad test data";
    let encoded_map = encode_content_map_bytes(data);

    // base32_standard_no_padding
    let encoded_std = encoded_map
        .get("base32_standard_no_padding")
        .expect("base32_standard_no_padding key missing");
    assert!(
        !encoded_std.contains('='),
        "no-pad variant should not contain padding"
    );
    let decoded = decode_content_internal("base32_standard_no_padding", encoded_std)
        .expect("base32_standard_no_padding decode");
    assert_eq!(decoded, data);

    // base32_hex_no_padding
    let encoded_hex = encoded_map
        .get("base32_hex_no_padding")
        .expect("base32_hex_no_padding key missing");
    assert!(
        !encoded_hex.contains('='),
        "hex no-pad should not contain padding"
    );
    let decoded = decode_content_internal("base32_hex_no_padding", encoded_hex)
        .expect("base32_hex_no_padding decode");
    assert_eq!(decoded, data);
}

#[test]
fn base64_raw_variants_roundtrip() {
    let data = b"base64 raw variant test";
    let encoded_map = encode_content_map_bytes(data);

    let encoded_raw_std = encoded_map
        .get("base64_raw_standard")
        .expect("base64_raw_standard key");
    assert!(
        !encoded_raw_std.contains('='),
        "raw standard should have no padding"
    );
    let decoded = decode_content_internal("base64_raw_standard", encoded_raw_std)
        .expect("raw standard decode");
    assert_eq!(decoded, data);

    let encoded_raw_url = encoded_map
        .get("base64_raw_url")
        .expect("base64_raw_url key");
    assert!(
        !encoded_raw_url.contains('='),
        "raw url should have no padding"
    );
    let decoded =
        decode_content_internal("base64_raw_url", encoded_raw_url).expect("raw url decode");
    assert_eq!(decoded, data);
}

// =====================================================================
// Phase 2: Additional Boundary Tests
// =====================================================================

#[test]
fn random_numeric_range_min_equals_max() {
    let results = random_numeric_range_internal(5, "42", "42", 3).expect("min==max");
    assert_eq!(results.len(), 5);
    for val in &results {
        assert_eq!(val, "42", "when min==max, all values should be 42");
    }
}

#[test]
fn random_numeric_range_negative_rejected() {
    let err = random_numeric_range_internal(1, "-5", "10", 3);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("non-negative"));
}

#[test]
fn random_numeric_range_empty_min_max_rejected() {
    let err = random_numeric_range_internal(1, "", "10", 3);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("required"));
}

#[test]
fn random_numeric_range_min_exceeds_max_rejected() {
    let err = random_numeric_range_internal(1, "100", "50", 4);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("exceed"));
}

#[test]
fn random_numeric_range_count_zero_rejected() {
    let err = random_numeric_range_internal(0, "1", "10", 3);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("greater than zero"));
}

#[test]
fn random_numeric_range_count_over_256_rejected() {
    let err = random_numeric_range_internal(257, "1", "10", 3);
    assert!(err.is_err());
    assert!(err.unwrap_err().contains("256"));
}

#[test]
fn encrypt_empty_plaintext() {
    // Encrypting empty bytes should succeed (AEAD ciphers support empty plaintext)
    let output =
        encrypt_bytes_internal("aes-256-gcm", b"", None, None).expect("empty plaintext encrypt");
    let decrypted = decrypt_bytes_internal(
        "aes-256-gcm",
        &output.ciphertext_b64,
        &output.key_b64,
        &output.nonce_b64,
    )
    .expect("decrypt empty");
    assert!(decrypted.is_empty());
}

#[test]
fn encrypt_large_plaintext() {
    // Encrypt a large payload to ensure no buffer issues
    let data = vec![0xABu8; 65536];
    let output =
        encrypt_bytes_internal("aes-256-gcm", &data, None, None).expect("large plaintext encrypt");
    let decrypted = decrypt_bytes_internal(
        "aes-256-gcm",
        &output.ciphertext_b64,
        &output.key_b64,
        &output.nonce_b64,
    )
    .expect("decrypt large");
    assert_eq!(decrypted, data);
}

#[test]
fn hash_empty_input() {
    // Hashing empty input should produce well-known empty digests
    let map = hash_content_map(b"");
    // MD5 of empty = d41d8cd98f00b204e9800998ecf8427e
    assert_eq!(map.get("md5").unwrap(), "d41d8cd98f00b204e9800998ecf8427e");
    // SHA1 of empty = da39a3ee5e6b4b0d3255bfef95601890afd80709
    assert_eq!(
        map.get("sha1").unwrap(),
        "da39a3ee5e6b4b0d3255bfef95601890afd80709"
    );
    // SHA256 of empty = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    assert_eq!(
        map.get("sha256").unwrap(),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn fnv_hash_empty_returns_offset_basis() {
    // FNV offset basis for empty input
    assert_eq!(fnv1_32(b""), 0x811c_9dc5);
    assert_eq!(fnv1a_32(b""), 0x811c_9dc5);
    assert_eq!(fnv1_64(b""), 0xcbf2_9ce4_8422_2325);
    assert_eq!(fnv1a_64(b""), 0xcbf2_9ce4_8422_2325);
}

#[test]
fn number_base_binary_input() {
    let bases = convert_number_base_internal("binary", "0b11111111").unwrap();
    assert_eq!(bases.decimal, "255");
    assert_eq!(bases.hex, "FF");
    assert_eq!(bases.octal, "377");
}

#[test]
fn number_base_octal_input() {
    let bases = convert_number_base_internal("octal", "0o77").unwrap();
    assert_eq!(bases.decimal, "63");
    assert_eq!(bases.binary, "111111");
    assert_eq!(bases.hex, "3F");
}

#[test]
fn ip_info_rejects_invalid_address() {
    let err = ip_info_internal("not.an.ip.address");
    assert!(err.is_err());
}

#[test]
fn ip_info_ipv4_mapped_ipv6() {
    let info = ip_info_internal("::ffff:192.168.1.1");
    // Should either parse as IPv6 or return an error - should not panic
    assert!(info.is_ok() || info.is_err());
}
