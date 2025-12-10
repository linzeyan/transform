#![cfg(target_arch = "wasm32")]

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64_STD;
use bcrypt::BASE_64;
use js_sys::{Object, Reflect}; // Build JS payloads for wasm bindings.
use serde_json::Value as JsonValue;
use wasm_bindgen::JsValue;
use wasm_bindgen_test::*;

use wasm_core::{
    argon2_hash, argon2_verify, bcrypt_hash, bcrypt_verify, convert_image_format,
    convert_number_base, convert_tabular_format, convert_timestamp, convert_units, decode_content,
    decode_content_bytes, decrypt_bytes, encode_content, encode_content_bytes, encrypt_bytes,
    generate_insert_statements, generate_qr_code, generate_text_diff, generate_unified_text_diff,
    generate_user_agents, generate_uuids, hash_content, hash_content_bytes, html_to_markdown_text,
    inspect_certificates, ipv4_info, jwt_decode, jwt_encode, markdown_to_html_text,
    random_number_sequences, random_numeric_range_sequences, totp_token, transform_format,
    url_decode, url_encode,
};

wasm_bindgen_test_configure!(run_in_browser);

fn js_to_json(value: JsValue) -> JsonValue {
    serde_wasm_bindgen::from_value(value).expect("JsValue -> JSON map")
}

fn field<'a>(map: &'a JsonValue, key: &str) -> &'a str {
    map.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("missing string field {key}"))
}

#[wasm_bindgen_test]
fn landing_page_shows_converter_by_default() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"converterWorkspace\" class=\"tool-view\""),
        "converter workspace should be visible by default"
    );
    assert!(
        INDEX_HTML.contains("id=\"numberWorkspace\" class=\"tool-view hidden\""),
        "number converter workspace should start hidden"
    );
    assert!(
        INDEX_HTML.contains("<h1 id=\"toolName\">Format Converter</h1>"),
        "landing title should be Format Converter"
    );
}

#[wasm_bindgen_test]
fn url_tool_exposes_query_editor_markup() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"urlQuerySection\""),
        "URL tool should render the query parameter section"
    );
    assert!(
        INDEX_HTML.contains("id=\"urlQueryTable\""),
        "query parameter table container should exist"
    );
    assert!(
        INDEX_HTML.contains("id=\"urlQueryAdd\""),
        "query editor should offer an add button"
    );
}

#[wasm_bindgen_test]
fn kdf_random_salt_controls_exist() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"kdfRefreshSalts\""),
        "Random salt button should be present for KDF tools"
    );
    assert!(
        INDEX_HTML.contains("id=\"bcryptSalt\""),
        "Bcrypt salt input should be present"
    );
    assert!(
        INDEX_HTML.contains("id=\"argonSalt\""),
        "Argon2 salt input should be present"
    );
}

#[wasm_bindgen_test]
fn random_workspace_exposes_minimum_and_range_controls() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    for id in [
        "randomMinDigitsRow",
        "randomMinLowerRow",
        "randomMinUpperRow",
        "randomDigitRangeRow",
        "randomDigitMin",
        "randomDigitMax",
    ] {
        assert!(
            INDEX_HTML.contains(&format!("id=\"{id}\"")),
            "Random workspace should expose control {id}"
        );
    }
}

#[wasm_bindgen_test]
fn image_converter_workspace_has_controls() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    for id in [
        "imageWorkspace",
        "imageFile",
        "imageTargetFormat",
        "imageConvert",
        "imageDownload",
    ] {
        assert!(
            INDEX_HTML.contains(&format!("id=\"{id}\"")),
            "expected image converter control {id}"
        );
    }
}

#[wasm_bindgen_test]
fn qr_workspace_includes_core_controls() {
    // Ensure the QR generator UI ships with mode radios, format select, and action buttons.
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"qrWorkspace\""),
        "workspace container should exist"
    );
    assert!(
        INDEX_HTML.contains("id=\"qrModeOtp\""),
        "OTP mode radio should be present"
    );
    assert!(
        INDEX_HTML.contains("name=\"qrMode\""),
        "QR mode radios should share the same name"
    );
    assert!(
        INDEX_HTML.contains("id=\"qrFormat\""),
        "format select should exist"
    );
    assert!(
        INDEX_HTML.contains("id=\"qrGenerate\""),
        "generate button should be wired"
    );
    assert!(
        INDEX_HTML.contains("id=\"qrDownload\""),
        "download control should exist"
    );
}

#[wasm_bindgen_test]
fn ssl_inspector_workspace_is_wired() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"certWorkspace\""),
        "SSL inspector workspace should exist in DOM"
    );
    assert!(
        INDEX_HTML.contains("id=\"certInput\""),
        "SSL inspector input textarea should be present"
    );
    assert!(
        INDEX_HTML.contains("id=\"certResults\""),
        "SSL inspector results container should be present"
    );
}

#[wasm_bindgen_test]
fn diff_workspace_is_present_in_html() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"diffWorkspace\""),
        "diff workspace container should exist"
    );
    assert!(
        INDEX_HTML.contains("id=\"diffLeftInput\""),
        "diff left input textarea should be present"
    );
    assert!(
        INDEX_HTML.contains("id=\"diffRightInput\""),
        "diff right input textarea should be present"
    );
    assert!(
        INDEX_HTML.contains("id=\"diffOutput\""),
        "diff output container should be present"
    );
}

#[wasm_bindgen_test]
fn number_bases_decimal_100_flow() {
    let map = js_to_json(convert_number_base("decimal", "100").expect("convert number base"));
    assert_eq!(field(&map, "binary"), "1100100");
    assert_eq!(field(&map, "octal"), "144");
    assert_eq!(field(&map, "decimal"), "100");
    assert_eq!(field(&map, "hex"), "64");
}

#[wasm_bindgen_test]
fn random_numeric_range_sequences_respects_bounds() {
    let values =
        js_to_json(random_numeric_range_sequences(3, "5", "7", 3).expect("range sequences"));
    let array = values
        .as_array()
        .cloned()
        .unwrap_or_else(|| panic!("expected array, got {values:?}"));
    assert_eq!(array.len(), 3);
    for entry in array {
        let text = entry.as_str().unwrap_or_default();
        let parsed: i32 = text.parse().unwrap();
        assert!(
            (5..=7).contains(&parsed),
            "value {parsed} fell outside range"
        );
        assert!(!text.starts_with('0'));
    }
}

#[wasm_bindgen_test]
fn format_converter_json_to_yaml() {
    let yaml = transform_format("JSON", "YAML", r#"{"name":"Ada","age":27}"#)
        .expect("json -> yaml transform");
    assert!(
        yaml.contains("name: Ada") && yaml.contains("age: 27"),
        "yaml output should contain converted fields"
    );
}

#[wasm_bindgen_test]
fn tabular_converter_dom_controls_exist() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    for id in [
        "tabularSection",
        "tabularFile",
        "tabularFrom",
        "tabularTo",
        "tabularConvert",
        "tabularDownload",
        "tabularProgress",
        "tabularStatus",
    ] {
        assert!(
            INDEX_HTML.contains(&format!("id=\"{id}\"")),
            "Missing tabular control {id}"
        );
    }
}

#[wasm_bindgen_test]
fn tabular_round_trip_csv_to_parquet_and_back() {
    let csv = b"id,name\n1,Ada\n2,Bob\n";
    let parquet = convert_tabular_format("CSV", "Parquet", csv).expect("csv -> parquet");
    assert_eq!(parquet.mime_type(), "application/x-parquet");
    assert_eq!(parquet.row_count(), 2);
    let back = convert_tabular_format("Parquet", "CSV", &parquet.bytes()).expect("parquet -> csv");
    let text = String::from_utf8(back.bytes()).unwrap();
    assert!(text.contains("Ada"));
    assert!(text.contains("Bob"));
}

#[wasm_bindgen_test]
fn image_converter_png_to_webp_via_wasm() {
    // Generate a tiny PNG on the fly to avoid shipping fixtures in the wasm bundle.
    let mut png_bytes = Vec::new();
    let png = image::DynamicImage::new_rgba8(1, 1);
    png.write_to(
        &mut std::io::Cursor::new(&mut png_bytes),
        image::ImageFormat::Png,
    )
    .expect("encode png fixture");
    let js_val = convert_image_format("png", "webp", &png_bytes, JsValue::NULL)
        .expect("png -> webp conversion");
    let obj = js_to_json(js_val);
    let data_url = obj
        .get("data_url")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(data_url.starts_with("data:image/webp;base64,"));
    let width = obj
        .get("width")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let height = obj
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    assert_eq!((width, height), (1, 1));
    assert_eq!(field(&obj, "format"), "webp");
}

#[wasm_bindgen_test]
// Guard the UI contract: the WebP quality slider must be declared in the shipped JS bundle.
fn webp_quality_slider_is_declared_in_frontend() {
    const MAIN_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/main.js"));
    assert!(
        MAIN_JS.contains("webp: [")
            && MAIN_JS.contains("key: 'quality'")
            && MAIN_JS.contains("hint: '100 = lossless (default)'"),
        "frontend config should ship a WebP quality control while keeping libwebp out"
    );
}

#[wasm_bindgen_test]
fn format_converter_json_to_go_struct_handles_nested_objects() {
    let input = r#"{"plugins":{"proxy-rewrite":{"uri":"/x"}},"update_time":1}"#;
    let go = transform_format("JSON", "Go Struct", input).expect("json -> go struct");
    assert!(go.contains("type Plugins struct"));
    assert!(go.contains("type ProxyRewrite struct"));
    assert!(go.contains("UpdateTime"));
}

#[wasm_bindgen_test]
fn format_converter_json_to_graphql_camelizes_field_names() {
    let input = r#"{"plugins":{"proxy-rewrite":{"uri":"/x"}}}"#;
    let gql = transform_format("JSON", "GraphQL Schema", input).expect("json -> gql");
    assert!(gql.contains("plugins: Plugins"));
    assert!(gql.contains("proxyRewrite: ProxyRewrite"));
}

#[wasm_bindgen_test]
fn format_content_handles_proto_and_graphql() {
    let proto_src = "message AutoGenerated{ string name =1;}";
    let proto_fmt =
        wasm_core::format_content_text("Protobuf", proto_src, false).expect("format proto");
    assert!(proto_fmt.contains("message AutoGenerated"));

    let gql_src = "type AutoGenerated{ name:String age:Int }";
    let gql_fmt =
        wasm_core::format_content_text("GraphQL Schema", gql_src, false).expect("format graphql");
    assert!(gql_fmt.contains("name: String"));
}

#[wasm_bindgen_test]
fn format_minify_preserves_proto_and_graphql_structure() {
    let proto_src = "message AutoGenerated { string name = 1; message Inner { string id = 1; } }";
    let proto_min =
        wasm_core::format_content_text("Protobuf", proto_src, true).expect("minify proto");
    assert!(proto_min.contains("message AutoGenerated"));
    assert!(proto_min.contains("Inner"));
    assert!(proto_min.contains("name = 1"));

    let gql_src = "type Root{ user:User } type User{ id:ID name:String }";
    let gql_min =
        wasm_core::format_content_text("GraphQL Schema", gql_src, true).expect("minify gql");
    assert!(gql_min.contains("type Root"));
    assert!(gql_min.contains("user: User") || gql_min.contains("user:User"));
    assert!(gql_min.contains("type User"));
}

#[wasm_bindgen_test]
fn format_then_pretty_protobuf_restores_layout() {
    let src = "message AutoGenerated { string name = 1; message Inner { string id = 1; } }";
    let min = wasm_core::format_content_text("Protobuf", src, true).expect("minify proto");
    let pretty = wasm_core::format_content_text("Protobuf", &min, false).expect("pretty proto");
    assert!(pretty.contains("\n"));
    assert!(pretty.contains("message Inner"));
}

#[wasm_bindgen_test]
fn ssh_key_generator_returns_keys() {
    let result =
        wasm_core::generate_ssh_key("ed25519", 0, "test@local", "openssh", 16, false, false)
            .expect("ssh key");
    let map = js_to_json(result);
    assert_eq!(field(&map, "keyType"), "ed25519");
    assert!(field(&map, "publicKey").starts_with("ssh-ed25519 "));
    assert!(field(&map, "privateKey").contains("OPENSSH PRIVATE KEY"));
}

#[wasm_bindgen_test]
fn ssh_key_generator_clamps_rsa_bits_and_supports_sk() {
    // bits below 2048 should still produce a key
    let rsa_res =
        wasm_core::generate_ssh_key("rsa", 1024, "rsa@local", "openssh", 16, false, false)
            .expect("rsa key");
    let rsa_map = js_to_json(rsa_res);
    assert_eq!(field(&rsa_map, "keyType"), "rsa");
    assert!(field(&rsa_map, "publicKey").contains("ssh-rsa"));

    // ed25519-sk should also work and return public/private material
    let sk_res =
        wasm_core::generate_ssh_key("ed25519-sk", 0, "sk@local", "openssh", 20, true, true)
            .expect("sk key");
    let sk_map = js_to_json(sk_res);
    assert_eq!(field(&sk_map, "keyType"), "ed25519-sk");
    assert!(field(&sk_map, "publicKey").contains("ssh-ed25519"));
}

#[wasm_bindgen_test]
fn qr_generator_returns_png_data_url() {
    // Smoke test the wasm binding: ensure data URL prefix and otpauth payload are present.
    let payload = Object::new();
    let set_field = |key: &str, value: JsValue| {
        Reflect::set(&payload, &JsValue::from_str(key), &value).expect("set payload field");
    };
    set_field("otpAccount", JsValue::from_str("demo"));
    set_field("otpSecret", JsValue::from_str("JBSWY3DPEHPK3PXP"));
    set_field("otpIssuer", JsValue::from_str("Transform"));
    set_field("otpAlgorithm", JsValue::from_str("SHA1"));
    set_field("otpPeriod", JsValue::from_f64(30.0));
    set_field("otpDigits", JsValue::from_f64(6.0));

    let js_val = generate_qr_code("otp", "png", JsValue::from(payload)).expect("qr wasm call");
    let obj = js_to_json(js_val);
    let data_url = field(&obj, "dataUrl");
    assert!(data_url.starts_with("data:image/png;base64,"));
    assert_eq!(field(&obj, "format"), "png");
    let payload_text = field(&obj, "payload");
    assert!(payload_text.contains("otpauth://totp/Transform:demo"));

    let width = obj
        .get("width")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    let height = obj
        .get("height")
        .and_then(|v| v.as_u64())
        .unwrap_or_default();
    assert_eq!(width, 250);
    assert_eq!(height, 250);
}

#[wasm_bindgen_test]
fn format_converter_json_to_proto_snake_case_fields() {
    let input = r#"{"plugins":{"proxy-rewrite":{"uri":"/x"}}}"#;
    let proto_text = transform_format("JSON", "Protobuf", input).expect("json -> proto");
    assert!(proto_text.contains("proxy_rewrite"));
    assert!(!proto_text.contains("proxy-rewrite"));
}

#[wasm_bindgen_test]
fn markdown_html_roundtrip() {
    let html =
        markdown_to_html_text("# Title\n\n- item").expect("markdown to html conversion works");
    assert!(html.contains("<h1>Title</h1>"));
    let markdown = html_to_markdown_text("<h1>Title</h1>").expect("html to markdown conversion");
    assert!(markdown.to_lowercase().contains("# title"));
}

#[wasm_bindgen_test]
fn unit_converter_bits_and_bytes() {
    let map = js_to_json(convert_units("byte", "1024").expect("unit conversion"));
    assert_eq!(field(&map, "bit"), "8192");
    assert_eq!(field(&map, "kilobit"), "8");
    assert_eq!(field(&map, "byte"), "1024");
}

#[wasm_bindgen_test]
fn timestamp_sql_datetime_to_epoch() {
    let map = js_to_json(
        convert_timestamp("sql_datetime", "2025-01-02 03:04:05").expect("timestamp conversion"),
    );
    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");
    assert_eq!(field(&map, "timestamp_seconds"), "1735787045");
    assert_eq!(field(&map, "timestamp_milliseconds"), "1735787045000");
}

#[wasm_bindgen_test]
fn timestamp_converter_supports_new_formats() {
    let map = js_to_json(
        convert_timestamp("sql_datetime", "2025-01-02 03:04:05").expect("timestamp conversion"),
    );

    // Test ISO 8601 format (basic format without nanoseconds)
    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");

    // Test RFC 3339 format (with nanoseconds)
    let rfc3339 = field(&map, "rfc3339");
    assert!(rfc3339.starts_with("2025-01-02T03:04:05."));
    assert!(rfc3339.ends_with("Z"));

    // Test RFC 2822 format
    assert_eq!(field(&map, "rfc2822"), "Thu, 2 Jan 2025 03:04:05 +0000");

    // Test ISO 9075 format (SQL timestamp with timezone)
    assert_eq!(field(&map, "iso9075"), "2025-01-02 03:04:05+00:00");

    // Test RFC 7231 format (HTTP date format)
    assert_eq!(field(&map, "rfc7231"), "Thu, 02 Jan 2025 03:04:05 GMT");

    // Test SQL formats
    assert_eq!(field(&map, "sql_datetime"), "2025-01-02 03:04:05");
    assert_eq!(field(&map, "sql_date"), "2025-01-02");

    // Test Unix timestamp formats
    assert_eq!(field(&map, "timestamp_seconds"), "1735787045");
    assert_eq!(field(&map, "timestamp_milliseconds"), "1735787045000");
    assert_eq!(field(&map, "timestamp_microseconds"), "1735787045000000");
    assert_eq!(field(&map, "timestamp_nanoseconds"), "1735787045000000000");

    // Test browser timezone formats exist
    assert!(
        map.get("browser_iso8601")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_rfc3339")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_rfc2822")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_iso9075")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_rfc7231")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_sql_datetime")
            .and_then(|v| v.as_str())
            .is_some()
    );
    assert!(
        map.get("browser_sql_date")
            .and_then(|v| v.as_str())
            .is_some()
    );
}

#[wasm_bindgen_test]
fn timestamp_converter_now_source_returns_result() {
    let map = js_to_json(convert_timestamp("now", "").expect("timestamp conversion for now"));

    // Verify we get a populated map
    assert!(field(&map, "iso8601").len() > 0);
    assert!(field(&map, "rfc3339").len() > 0);

    // Verify RFC 3339 has nanoseconds (contains dot)
    assert!(field(&map, "rfc3339").contains('.'));
}

#[wasm_bindgen_test]
fn timestamp_converter_from_iso8601() {
    let map = js_to_json(
        convert_timestamp("iso8601", "2025-01-02T03:04:05Z").expect("timestamp conversion"),
    );

    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");
    assert!(field(&map, "rfc3339").starts_with("2025-01-02T03:04:05."));
    assert_eq!(field(&map, "rfc2822"), "Thu, 2 Jan 2025 03:04:05 +0000");
    assert_eq!(field(&map, "iso9075"), "2025-01-02 03:04:05+00:00");
    assert_eq!(field(&map, "rfc7231"), "Thu, 02 Jan 2025 03:04:05 GMT");
}

#[wasm_bindgen_test]
fn timestamp_converter_from_rfc3339_with_nanos() {
    let map = js_to_json(
        convert_timestamp("rfc3339", "2025-01-02T03:04:05.123456789Z")
            .expect("timestamp conversion"),
    );

    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");
    assert_eq!(field(&map, "rfc3339"), "2025-01-02T03:04:05.123456789Z");
    assert_eq!(field(&map, "rfc2822"), "Thu, 2 Jan 2025 03:04:05 +0000");
}

#[wasm_bindgen_test]
fn timestamp_converter_from_iso9075() {
    let map = js_to_json(
        convert_timestamp("iso9075", "2025-01-02 03:04:05+00:00").expect("timestamp conversion"),
    );

    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");
    assert!(field(&map, "rfc3339").starts_with("2025-01-02T03:04:05."));
    assert_eq!(field(&map, "iso9075"), "2025-01-02 03:04:05+00:00");
}

#[wasm_bindgen_test]
fn timestamp_converter_from_rfc7231() {
    let map = js_to_json(
        convert_timestamp("rfc7231", "Thu, 02 Jan 2025 03:04:05 GMT")
            .expect("timestamp conversion"),
    );

    assert_eq!(field(&map, "iso8601"), "2025-01-02T03:04:05Z");
    assert!(field(&map, "rfc3339").starts_with("2025-01-02T03:04:05."));
    assert_eq!(field(&map, "rfc7231"), "Thu, 02 Jan 2025 03:04:05 GMT");
}

#[wasm_bindgen_test]
fn timestamp_workspace_has_new_format_controls() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));

    // Check that new format inputs exist
    for id in [
        "timestampIso",       // ISO 8601
        "timestampRfc3339",   // RFC 3339
        "timestampRfc",       // RFC 2822
        "timestampIso9075",   // ISO 9075
        "timestampRfc7231",   // RFC 7231
        "timestampSql",       // SQL datetime
        "timestampSqlDate",   // SQL date
        "timestampSeconds",   // Unix seconds
        "timestampMillis",    // Unix milliseconds
        "timestampMicros",    // Unix microseconds
        "timestampNanos",     // Unix nanoseconds
        "browserIso8601",     // Browser ISO 8601 (readonly)
        "browserRfc3339",     // Browser RFC 3339 (readonly)
        "browserRfc2822",     // Browser RFC 2822 (readonly)
        "browserIso9075",     // Browser ISO 9075 (readonly)
        "browserRfc7231",     // Browser RFC 7231 (readonly)
        "browserSqlDatetime", // Browser SQL datetime (readonly)
        "browserSqlDate",     // Browser SQL date (readonly)
    ] {
        assert!(
            INDEX_HTML.contains(&format!("id=\"{id}\"")),
            "timestamp converter should have control {id}"
        );
    }

    // Check that Now button exists
    assert!(
        INDEX_HTML.contains("data-preset=\"now\""),
        "timestamp converter should have Now button"
    );
}

#[wasm_bindgen_test]
fn ipv4_range_reports_total_hosts() {
    let map = js_to_json(ipv4_info("192.168.0.1-192.168.0.3").expect("ipv4 range info"));
    assert_eq!(field(&map, "type"), "range");
    assert_eq!(field(&map, "total"), "3");
}

#[wasm_bindgen_test]
fn ipv4_single_includes_mapped_ipv6() {
    let map = js_to_json(ipv4_info("10.0.0.1").expect("ipv4 single info"));
    assert_eq!(field(&map, "version"), "IPv4");
    assert_eq!(
        field(&map, "ipv6Mapped"),
        "0000:0000:0000:0000:0000:ffff:0a00:0001"
    );
}

#[wasm_bindgen_test]
fn coder_encode_and_decode_cycle() {
    let enc = js_to_json(encode_content("rust").expect("encode content"));
    assert_eq!(field(&enc, "base64_standard"), "cnVzdA==");

    let decoded = decode_content("base64_standard", "cnVzdA==").expect("decode content");
    assert_eq!(decoded, "rust");
}

#[wasm_bindgen_test]
fn coder_supports_file_controls_in_markup() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"coderModeFile\""),
        "file toggle should exist for coder workspace"
    );
    assert!(
        INDEX_HTML.contains("id=\"coderFile\""),
        "file input should exist for coder workspace"
    );
    assert!(
        INDEX_HTML.contains("id=\"coderDownloadDecoded\""),
        "decoded download action should be present"
    );
}

#[wasm_bindgen_test]
fn base_encode_accepts_raw_bytes() {
    let map = js_to_json(encode_content_bytes(&[0u8, 0xFF, 0x10]).expect("encode bytes"));
    assert_eq!(field(&map, "base64_standard"), "AP8Q");
    assert_eq!(field(&map, "hex_upper"), "00FF10");
}

#[wasm_bindgen_test]
fn base_decode_returns_raw_bytes() {
    let encoded = B64_STD.encode([9u8, 8u8, 7u8]);
    let decoded = decode_content_bytes("base64_standard", &encoded).expect("decode bytes");
    assert_eq!(decoded, [9u8, 8u8, 7u8]);
}

#[wasm_bindgen_test]
fn file_hash_matches_known_sha256() {
    let map = js_to_json(hash_content_bytes(b"abc").expect("hash bytes"));
    assert_eq!(
        field(&map, "sha256"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[wasm_bindgen_test]
fn hash_content_sha256_matches_known_value() {
    let map = js_to_json(hash_content("abc").expect("hash content"));
    assert_eq!(
        field(&map, "sha256"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[wasm_bindgen_test]
fn crypto_workspace_controls_exist() {
    const INDEX_HTML: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/index.html"));
    assert!(
        INDEX_HTML.contains("id=\"cryptoWorkspace\""),
        "crypto workspace container should exist"
    );
    for id in [
        "cryptoAlgorithm",
        "cryptoKey",
        "cryptoNonce",
        "cryptoPlaintext",
        "cryptoCiphertext",
        "cryptoDecryptOutput",
    ] {
        assert!(
            INDEX_HTML.contains(&format!("id=\"{id}\"")),
            "expected control {id}"
        );
    }
}

#[wasm_bindgen_test]
fn encrypt_bytes_roundtrip_in_browser() {
    let key = B64_STD.encode([0x77u8; 32]);
    let nonce = B64_STD.encode([0x55u8; 12]);
    let encrypted = js_to_json(
        encrypt_bytes(
            "aes-256-gcm",
            b"browser-flow",
            Some(key.clone()),
            Some(nonce.clone()),
        )
        .expect("encrypt"),
    );
    let cipher = field(&encrypted, "ciphertextB64");
    let decrypted = decrypt_bytes("aes-256-gcm", cipher, &key, &nonce).expect("decrypt");
    let text = String::from_utf8(decrypted).expect("utf8 plaintext");
    assert_eq!(text, "browser-flow");
}

#[wasm_bindgen_test]
fn url_encode_and_decode_roundtrip() {
    let encoded = url_encode("a b+c");
    assert_eq!(encoded, "a+b%2Bc");
    let decoded = url_decode(&encoded).expect("url decode");
    assert_eq!(decoded, "a b+c");
}

#[wasm_bindgen_test]
fn jwt_encode_and_decode_roundtrip() {
    let payload = r#"{"sub":"1234567890","name":"John Doe"}"#;
    let token = jwt_encode(payload, "secret", "").expect("jwt encode");
    let decoded = js_to_json(jwt_decode(&token).expect("jwt decode"));
    let payload_text = field(&decoded, "payload");
    let payload_json: JsonValue =
        serde_json::from_str(payload_text).expect("payload should be valid json");
    assert_eq!(payload_json["sub"], "1234567890");
}

#[wasm_bindgen_test]
fn bcrypt_and_argon2_deterministic_hashes() {
    let bcrypt_salt = BASE_64.encode([0u8; 16]);
    let bcrypt_hash_val =
        bcrypt_hash("apple111", 10, Some(bcrypt_salt)).expect("bcrypt hash generation");
    assert!(bcrypt_hash_val.starts_with("$2b$10$"));
    assert!(bcrypt_verify("apple111", &bcrypt_hash_val).expect("bcrypt verify true"));

    let argon_salt = B64_STD.encode([1u8; 16]);
    let argon_hash_val = argon2_hash("apple111", Some(argon_salt), 2, 4096, 1, 16, "argon2id")
        .expect("argon2 hash generation");
    assert!(argon_hash_val.starts_with("$argon2id$"));
    assert!(argon2_verify("apple111", &argon_hash_val).expect("argon2 verify true"));
}

#[wasm_bindgen_test]
fn uuid_and_user_agent_generators_return_values() {
    let uuid_map = js_to_json(generate_uuids());
    for key in ["v1", "v4", "ulid"] {
        assert!(
            uuid_map.get(key).and_then(|v| v.as_str()).is_some(),
            "missing {key} in uuid map"
        );
    }

    let uas = js_to_json(generate_user_agents("chrome", "macos"));
    assert!(
        uas.as_array().map(|arr| !arr.is_empty()).unwrap_or(false),
        "user agent list should not be empty"
    );
    if let Some(first) = uas.as_array().and_then(|arr| arr.first()) {
        assert_eq!(field(first, "browserName"), "chrome");
        assert_eq!(field(first, "osName"), "macos");
    }
}

#[wasm_bindgen_test]
fn random_sequences_respect_length_and_charset() {
    let results = js_to_json(
        random_number_sequences(8, 3, true, "01", true, true, "!@", "", 1, 1, 1, 1)
            .expect("random sequences"),
    );
    let arr = results.as_array().expect("results array");
    assert_eq!(arr.len(), 3);
    for entry in arr {
        let s = entry.as_str().expect("string entry");
        assert_eq!(s.len(), 8);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '!' || c == '@'),
            "unexpected character in {s}"
        );
    }
}

#[wasm_bindgen_test]
fn totp_token_has_expected_length() {
    let res = js_to_json(totp_token("JBSWY3DPEHPK3PXP", "SHA256", 30, 6).expect("totp token"));
    let code = field(&res, "code");
    assert_eq!(code.len(), 6);
    assert!(code.chars().all(|c| c.is_ascii_digit()));
}

#[wasm_bindgen_test]
fn sql_insert_generator_includes_table_name() {
    let schema = "CREATE TABLE users (id INT PRIMARY KEY, name VARCHAR(10));";
    let inserts =
        generate_insert_statements(schema, 2, JsValue::NULL).expect("generate insert statements");
    assert!(inserts.contains("INSERT INTO `users`"));
    assert!(inserts.contains("VALUES"));
}

#[wasm_bindgen_test]
fn ssl_inspector_parses_chain_via_wasm() {
    const CHAIN: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/test_chain.pem"
    ));
    let value = inspect_certificates(CHAIN).expect("certificates parsed");
    let list = js_to_json(value);
    let arr = list
        .as_array()
        .unwrap_or_else(|| panic!("expected array from inspect_certificates"));
    assert_eq!(arr.len(), 2);
    let leaf = arr[0].as_object().expect("leaf map");
    assert_eq!(
        field(&JsonValue::Object(leaf.clone()), "subjectCommonName"),
        "transform.test"
    );
}

#[wasm_bindgen_test]
fn diff_tool_generates_structured_diff_output() {
    let diff_result = js_to_json(
        generate_text_diff("line 1\nline 2\nline 3", "line 1\nline 2\nline 4")
            .expect("generate text diff"),
    );
    let binding = Vec::new();
    let lines = diff_result
        .get("lines")
        .and_then(|v| v.as_array())
        .unwrap_or(&binding);
    assert_eq!(lines.len(), 4); // 3 context + 1 deletion + 1 addition = 5 lines, but let's check the actual count

    // Check that we have the expected diff structure
    let stats = diff_result
        .get("stats")
        .and_then(|v| v.as_object())
        .expect("stats object");
    let additions = stats.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
    let deletions = stats.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(additions, 1);
    assert_eq!(deletions, 1);
}

#[wasm_bindgen_test]
fn diff_tool_generates_unified_diff_format() {
    let unified_diff = generate_unified_text_diff(
        "line 1\nline 2\nline 3",
        "line 1\nline 2\nline 4",
        "a/file.txt",
        "b/file.txt",
    );

    assert!(unified_diff.contains("--- a/file.txt"));
    assert!(unified_diff.contains("+++ b/file.txt"));
    assert!(unified_diff.contains("@@"));
    assert!(unified_diff.contains("-line 3"));
    assert!(unified_diff.contains("+line 4"));
}

#[wasm_bindgen_test]
fn diff_tool_handles_identical_texts() {
    let diff_result = js_to_json(
        generate_text_diff("same\ncontent", "same\ncontent").expect("generate identical text diff"),
    );
    let stats = diff_result
        .get("stats")
        .and_then(|v| v.as_object())
        .expect("stats object");
    let additions = stats.get("additions").and_then(|v| v.as_u64()).unwrap_or(0);
    let deletions = stats.get("deletions").and_then(|v| v.as_u64()).unwrap_or(0);
    let context = stats.get("context").and_then(|v| v.as_u64()).unwrap_or(0);
    assert_eq!(additions, 0);
    assert_eq!(deletions, 0);
    assert_eq!(context, 2);
}

/// Test that the image converter workspace includes range input controls for quality/compression.
/// This verifies that the UI properly renders sliders with value displays for image options.
#[wasm_bindgen_test]
fn image_converter_has_range_slider_support() {
    const MAIN_JS: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../www/main.js"));

    // Verify that the JavaScript includes range input wrapper for value display
    assert!(
        MAIN_JS.contains("range-input-wrapper"),
        "main.js should include range-input-wrapper class for slider UI"
    );

    // Verify that range value display element is created
    assert!(
        MAIN_JS.contains("range-value"),
        "main.js should include range-value class for displaying slider values"
    );

    // Verify that the code handles range input type specifically
    assert!(
        MAIN_JS.contains("spec.type === 'range'"),
        "main.js should have special handling for range input type"
    );

    // Verify that value display is updated on input change
    assert!(
        MAIN_JS.contains("event.target.type === 'range'"),
        "main.js should update range value display on input change"
    );
}

/// Test that the CSS includes proper styling for range input sliders.
/// This ensures sliders are visible with proper track, thumb, and value display styling.
#[wasm_bindgen_test]
fn range_slider_css_styles_exist() {
    const FORMS_CSS: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../www/css/components/forms.css"
    ));

    // Verify range input wrapper styles exist
    assert!(
        FORMS_CSS.contains(".range-input-wrapper"),
        "forms.css should include range-input-wrapper styles"
    );

    // Verify range value display styles exist
    assert!(
        FORMS_CSS.contains(".range-value"),
        "forms.css should include range-value display styles"
    );

    // Verify WebKit slider track styles exist
    assert!(
        FORMS_CSS.contains("input[type='range']::-webkit-slider-runnable-track"),
        "forms.css should include WebKit slider track styles"
    );

    // Verify WebKit slider thumb styles exist
    assert!(
        FORMS_CSS.contains("input[type='range']::-webkit-slider-thumb"),
        "forms.css should include WebKit slider thumb styles"
    );

    // Verify Firefox slider track styles exist
    assert!(
        FORMS_CSS.contains("input[type='range']::-moz-range-track"),
        "forms.css should include Firefox slider track styles"
    );

    // Verify Firefox slider thumb styles exist
    assert!(
        FORMS_CSS.contains("input[type='range']::-moz-range-thumb"),
        "forms.css should include Firefox slider thumb styles"
    );

    // Verify that range input has appearance reset
    assert!(
        FORMS_CSS.contains("appearance: none"),
        "forms.css should reset default range input appearance"
    );
}
