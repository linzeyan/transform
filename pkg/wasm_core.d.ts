/* tslint:disable */
/* eslint-disable */
/**
 * Converts a numeric value between bit/byte units (bit, byte, kilo/mega/giga/tera in both)
 * returning a JS map so the UI can show every unit side-by-side.
 */
export function convert_units(unit: string, value: string): any;
/**
 * Decodes a text payload and returns the raw bytes so callers can trigger file downloads
 * when the decoded data is not valid UTF-8.
 */
export function decode_content_bytes(kind: string, input: string): Uint8Array;
/**
 * Batch watermarking helper so the UI can keep the progress bar in sync.
 */
export function apply_image_watermark_batch(files: any): any;
/**
 * Batch image conversion so the frontend can queue multiple uploads and reuse the same options.
 */
export function convert_image_format_batch(files: any): any;
/**
 * Hashes arbitrary bytes (including uploaded files) using the same digest set used for text.
 */
export function hash_content_bytes(input: Uint8Array): any;
/**
 * Decodes URL-encoded strings, treating `+` as space to align with form submissions.
 */
export function url_decode(input: string): string;
/**
 * Converts Markdown to HTML using the same rules as the web playground so previews
 * look identical between Rust tests and the browser.
 */
export function markdown_to_html_text(input: string): string;
/**
 * Hashes input bytes with common digests (MD5, SHA1/2/3, CRC32/64, FNV, Adler) and
 * returns a JS map keyed by algorithm name so callers can render many digests at once.
 */
export function hash_content(input: string): any;
/**
 * Decodes a text payload using the specified format (Base32/64/85/91 or hex) and returns UTF-8 text.
 * On failure the error message matches the variant, making it easier to surface in the UI.
 */
export function decode_content(kind: string, input: string): string;
/**
 * Computes HMAC digests for arbitrary bytes (such as file payloads) so file hashing
 * behaves consistently with text hashing in the UI.
 */
export function hash_content_hmac_bytes(input: Uint8Array, key: Uint8Array): any;
/**
 * Encrypts arbitrary bytes (UTF-8 text or file contents) using modern AEAD
 * ciphers (AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305). Keys/nonces
 * are accepted as Base64; when omitted, cryptographically random values are
 * generated and returned alongside the ciphertext for easier reuse in the UI.
 */
export function encrypt_bytes(algorithm: string, plaintext: Uint8Array, key_b64?: string | null, nonce_b64?: string | null): any;
/**
 * Encodes arbitrary bytes (text or file contents) into common bases so file uploads can
 * share the same output grid as text input in the UI.
 */
export function encode_content_bytes(data: Uint8Array): any;
/**
 * Encodes the given text into multiple bases (Base32/64/85/91, hex) and returns a JS map keyed
 * by the encoding name—handy for previewing many encodings from a single input.
 */
export function encode_content(input: string): any;
/**
 * Converts image bytes (JPG/PNG/WebP/AVIF) and returns data URLs for download in the UI.
 */
export function convert_image_format(from: string, to: string, bytes: Uint8Array, options: any): any;
/**
 * Formats or minifies structured content (JSON, XML, YAML, TOML) while preserving semantics,
 * mirroring the "Prettify / Minify" buttons in the UI.
 */
export function format_content_text(format: string, input: string, minify: boolean): string;
/**
 * Generates an SSH keypair.
 * `key_type`: "rsa", "ed25519", "ed25519-sk" (security key).
 * `bits`: RSA key size (min 2048). `comment`: appended to public key. `format`: "openssh" or "pem" (pem aliases openssh output).
 * `kdf_rounds`: UI hint (16-500) preserved in output; resident/verify flags are informational for *-sk types.
 */
export function generate_ssh_key(key_type: string, bits: number, comment: string, format: string, kdf_rounds: number, resident: boolean, verify_required: boolean): any;
/**
 * Generates `count` random strings with per-class minimums (digits/upper/lower/symbols),
 * exclusion lists, and optional leading-zero guard—mirrors the "password / random string" UI.
 */
export function random_number_sequences(length: number, count: number, allow_leading_zero: boolean, digits: string, include_lowercase: boolean, include_uppercase: boolean, symbols: string, exclude_chars: string, min_digits: number, min_lowercase: number, min_uppercase: number, min_symbols: number): any;
/**
 * Hashes a password with Argon2 (i/d/id) using caller-supplied parameters; generates a random salt
 * when one is not provided and returns the encoded PHC string ready for verification elsewhere.
 */
export function argon2_hash(password: string, salt_b64: string | null | undefined, time_cost: number, memory_kib: number, parallelism: number, hash_len: number, variant: string): string;
/**
 * Percent-encodes a string for URL query contexts while keeping spaces as `+`
 * to match the browser form-encoding convention.
 */
export function url_encode(input: string): string;
/**
 * Converts HTML snippets back into Markdown, enabling round-trip formatting checks in tests/UI.
 */
export function html_to_markdown_text(input: string): string;
/**
 * Converts between structured-text formats (JSON, YAML, TOML, XML, etc.) using the shared
 * `convert` helpers so the web UI can provide format-to-format transforms in one call.
 */
export function transform_format(from: string, to: string, input: string): string;
/**
 * Builds an HMAC-signed JWT from a JSON payload and secret, defaulting to HS256 when
 * the algorithm input is empty; returns the compact token string.
 */
export function jwt_encode(payload_input: string, secret: string, algorithm: string): string;
/**
 * Inspects IPv4/IPv6 strings, CIDR blocks, or IPv4 ranges and returns a rich
 * breakdown (network, broadcast, total hosts, binary masks) for display in the UI.
 */
export function ipv4_info(input: string): any;
/**
 * Parses a number expressed in binary/octal/decimal/hex and returns all four representations,
 * making it easy for the UI to cross-display values (e.g., `0x10` → `"16"` and `"10000"`).
 */
export function convert_number_base(base: string, value: string): any;
/**
 * Parses MySQL `CREATE TABLE` DDL and emits deterministic sample `INSERT` statements,
 * letting the frontend show plausible rows without connecting to a database.
 */
export function generate_insert_statements(schema: string, rows: number, overrides: any): string;
/**
 * Applies a text watermark to an image and returns the encoded result as a data URL.
 */
export function apply_image_watermark(from: string, to: string, bytes: Uint8Array, watermark: any, options: any): any;
/**
 * Computes HMAC digests (SHA1/2/3 families) for the provided key+message and
 * returns them as a JS map, keeping the UI preview in sync with the plain-hash output.
 */
export function hash_content_hmac(input: string, key: string): any;
export function generate_user_agents(browser: string, os: string): any;
/**
 * Generates digit-only sequences within an inclusive numeric range while enforcing the UI length
 * cap; used when the Random tool is restricted to numbers without leading zeros.
 */
export function random_numeric_range_sequences(count: number, min: string, max: string, max_length: number): any;
/**
 * Normalizes timestamps supplied as epoch seconds/millis/micros/nanos or textual dates
 * into a map of common formats (ISO8601, RFC2822, SQL datetime/date, multiple epoch precisions).
 */
export function convert_timestamp(source: string, value: string): any;
export function convert_tabular_format(from: string, to: string, data: Uint8Array): TabularConversionResult;
/**
 * Verifies a plaintext password against a bcrypt hash, returning `true` on success without panics.
 */
export function bcrypt_verify(password: string, hash: string): boolean;
/**
 * Decodes a JWT without verifying the signature, returning pretty-printed header/payload
 * text plus the algorithm and raw signature segment for inspection.
 */
export function jwt_decode(token: string): any;
/**
 * Batch-friendly QR parser that keeps the existing single-image decoder but runs
 * it per entry so one bad file does not block the rest of the queue.
 */
export function parse_qr_codes_batch(files: any): any;
/**
 * Computes a TOTP value following RFC 6238 for the supplied Base32 secret and parameters.
 * Example: `totp_token("JBSWY3DPEHPK3PXP", "SHA256", 30, 6)` returns a code plus metadata.
 */
export function totp_token(secret: string, algorithm: string, period: number, digits: number): any;
/**
 * Wasm entry point that installs a panic hook so Rust panics appear in the browser console.
 */
export function wasm_start(): void;
/**
 * Parses MySQL DDL and returns column-level metadata (type, default, enum values, min/max)
 * so the UI can surface validation hints next to each field.
 */
export function inspect_schema(schema: string): any;
/**
 * Decrypts a Base64 ciphertext produced by `encrypt_bytes`, returning raw
 * bytes so the caller can treat them as UTF-8 text or feed them to a file
 * download flow. Authentication failures bubble up as descriptive errors.
 */
export function decrypt_bytes(algorithm: string, ciphertext_b64: string, key_b64: string, nonce_b64: string): Uint8Array;
/**
 * Verifies a password against an Argon2 PHC string, returning `false` for mismatches
 * and bubbling up malformed encodings as JavaScript errors for clearer UI messaging.
 */
export function argon2_verify(password: string, encoded: string): boolean;
/**
 * Renders a 250×250 QR code for OTP, WiFi, or custom payloads. Accepts a kind (otp/wifi/custom),
 * output format (png/jpg/svg/webp), and a JSON payload that mirrors the UI fields.
 */
export function generate_qr_code(kind: string, format: string, payload: any): any;
/**
 * Generate unified diff format string (git-style diff)
 */
export function generate_unified_text_diff(old_text: string, new_text: string, old_name: string, new_name: string): string;
/**
 * Produces a bcrypt hash with an optional pre-specified salt; errors if the cost is outside 4-31.
 * Example: providing your own 22-char bcrypt-base64 salt keeps results reproducible in tests.
 */
export function bcrypt_hash(password: string, cost: number, salt_b64?: string | null): string;
/**
 * Generates UUID-style identifiers across all supported variants (v1-v8, GUID, ULID).
 * Returns a JS map keyed by the variant name so the UI can render every example side by side.
 */
export function generate_uuids(): any;
/**
 * Generate a text diff between two inputs using patience diff algorithm
 */
export function generate_text_diff(old_text: string, new_text: string): any;
/**
 * Parses one or more QR codes embedded in a bitmap (PNG/JPG/WebP/AVIF) and
 * returns their textual payloads. Useful for the QR Parse UI so users can
 * upload any screenshot/photo and copy decoded contents.
 */
export function parse_qr_codes(bytes: Uint8Array): any;
/**
 * Parses one or more PEM/DER certificates (including full chains) and surfaces
 * human-readable metadata for each certificate so the UI can render details
 * without shipping OpenSSL to the browser.
 */
export function inspect_certificates(input: string): any;
export function list_ascii_fonts(): any;
export function generate_ascii_art(text: string, font: string, width?: number | null, align?: string | null): string;
/**
 * Tabular conversion entrypoint for binary/text table files (Parquet, Avro, Arrow IPC/Feather,
 * CSV/TSV, JSON). Returns bytes plus metadata so the frontend can stream a download.
 */
export class TabularConversionResult {
  private constructor();
  free(): void;
  [Symbol.dispose](): void;
  readonly bytes: Uint8Array;
  readonly file_name: string;
  readonly mime_type: string;
  readonly row_count: bigint;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_tabularconversionresult_free: (a: number, b: number) => void;
  readonly apply_image_watermark: (a: number, b: number, c: number, d: number, e: number, f: number, g: any, h: any) => [number, number, number];
  readonly apply_image_watermark_batch: (a: any) => [number, number, number];
  readonly argon2_hash: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number, number];
  readonly argon2_verify: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly bcrypt_hash: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly bcrypt_verify: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly convert_image_format: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number, number];
  readonly convert_image_format_batch: (a: any) => [number, number, number];
  readonly convert_number_base: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly convert_tabular_format: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly convert_timestamp: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly convert_units: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly decode_content: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly decode_content_bytes: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly decrypt_bytes: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
  readonly encode_content: (a: number, b: number) => [number, number, number];
  readonly encode_content_bytes: (a: number, b: number) => [number, number, number];
  readonly encrypt_bytes: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
  readonly format_content_text: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly generate_insert_statements: (a: number, b: number, c: number, d: any) => [number, number, number, number];
  readonly generate_qr_code: (a: number, b: number, c: number, d: number, e: any) => [number, number, number];
  readonly generate_ssh_key: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number) => [number, number, number];
  readonly generate_text_diff: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly generate_unified_text_diff: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number];
  readonly generate_user_agents: (a: number, b: number, c: number, d: number) => any;
  readonly generate_uuids: () => any;
  readonly hash_content: (a: number, b: number) => [number, number, number];
  readonly hash_content_bytes: (a: number, b: number) => [number, number, number];
  readonly hash_content_hmac: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly hash_content_hmac_bytes: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly html_to_markdown_text: (a: number, b: number) => [number, number, number, number];
  readonly inspect_certificates: (a: number, b: number) => [number, number, number];
  readonly inspect_schema: (a: number, b: number) => [number, number, number];
  readonly ipv4_info: (a: number, b: number) => [number, number, number];
  readonly jwt_decode: (a: number, b: number) => [number, number, number];
  readonly jwt_encode: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly markdown_to_html_text: (a: number, b: number) => [number, number, number, number];
  readonly parse_qr_codes: (a: number, b: number) => [number, number, number];
  readonly parse_qr_codes_batch: (a: any) => [number, number, number];
  readonly random_number_sequences: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
  readonly random_numeric_range_sequences: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly tabularconversionresult_bytes: (a: number) => [number, number];
  readonly tabularconversionresult_file_name: (a: number) => [number, number];
  readonly tabularconversionresult_mime_type: (a: number) => [number, number];
  readonly tabularconversionresult_row_count: (a: number) => bigint;
  readonly totp_token: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number];
  readonly transform_format: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly url_decode: (a: number, b: number) => [number, number, number, number];
  readonly url_encode: (a: number, b: number) => [number, number];
  readonly wasm_start: () => void;
  readonly generate_ascii_art: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number, number];
  readonly list_ascii_fonts: () => [number, number, number];
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
