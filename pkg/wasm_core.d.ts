/* tslint:disable */
/* eslint-disable */
export function convert_units(unit: string, value: string): any;
export function generate_user_agents(browser: string, os: string): any;
export function markdown_to_html_text(input: string): string;
export function random_number_sequences(length: number, count: number, allow_leading_zero: boolean, digits: string, include_lowercase: boolean, include_uppercase: boolean, symbols: string, exclude_chars: string, min_digits: number, min_lowercase: number, min_uppercase: number, min_symbols: number): any;
export function url_decode(input: string): string;
export function hash_content(input: string): any;
export function convert_number_base(base: string, value: string): any;
export function format_content_text(format: string, input: string, minify: boolean): string;
export function jwt_decode(token: string): any;
export function html_to_markdown_text(input: string): string;
export function transform_format(from: string, to: string, input: string): string;
export function jwt_encode(payload_input: string, secret: string, algorithm: string): string;
export function decode_content(kind: string, input: string): string;
export function generate_uuids(): any;
export function ipv4_info(input: string): any;
export function encode_content(input: string): any;
export function wasm_start(): void;
export function url_encode(input: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly convert_number_base: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly convert_units: (a: number, b: number, c: number, d: number) => [number, number, number];
  readonly decode_content: (a: number, b: number, c: number, d: number) => [number, number, number, number];
  readonly encode_content: (a: number, b: number) => [number, number, number];
  readonly format_content_text: (a: number, b: number, c: number, d: number, e: number) => [number, number, number, number];
  readonly generate_user_agents: (a: number, b: number, c: number, d: number) => any;
  readonly generate_uuids: () => any;
  readonly hash_content: (a: number, b: number) => [number, number, number];
  readonly html_to_markdown_text: (a: number, b: number) => [number, number, number, number];
  readonly ipv4_info: (a: number, b: number) => [number, number, number];
  readonly jwt_decode: (a: number, b: number) => [number, number, number];
  readonly jwt_encode: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly markdown_to_html_text: (a: number, b: number) => [number, number, number, number];
  readonly random_number_sequences: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: number, l: number, m: number, n: number, o: number) => [number, number, number];
  readonly transform_format: (a: number, b: number, c: number, d: number, e: number, f: number) => [number, number, number, number];
  readonly url_decode: (a: number, b: number) => [number, number, number, number];
  readonly url_encode: (a: number, b: number) => [number, number];
  readonly wasm_start: () => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_externrefs: WebAssembly.Table;
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
