//! Conversion helpers that replace the original Go `pkg/convert` package.
//!
//! Each submodule focuses on a single spec area (e.g., TOON array headers,
//! MsgPack transport, GraphQL schema normalization). Centralizing them under
//! `convert` helps keep the wasm bindings small and makes it easier for future
//! sessions to find the right surface when new formats are added.
pub mod formats;
pub mod go_struct;
pub mod graphql;
pub mod helpers;
pub mod json_utils;
pub mod markdown;
pub mod msgpack;
pub mod proto;
pub mod schema;
pub mod structs;
pub mod toon;
pub mod xml;

pub use formats::{convert_formats, format_content};

#[cfg(test)]
mod convert_tests;
