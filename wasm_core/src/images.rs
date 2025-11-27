//! Image format conversion helpers shared by wasm bindings and unit tests.
//!
//! All conversions normalize pixel data to either RGB (for JPEG) or RGBA
//! (for PNG/WebP/AVIF) so alpha channels are preserved whenever the
//! target container supports it.

use std::io::Cursor;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use image::{
    DynamicImage, ExtendedColorType, GenericImageView, ImageEncoder, ImageFormat, ImageReader,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PictureFormat {
    Png,
    Jpeg,
    Webp,
    Avif,
}

impl PictureFormat {
    fn parse(input: &str) -> Result<Self, String> {
        let normalized = input.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "png" => Ok(Self::Png),
            "jpg" | "jpeg" => Ok(Self::Jpeg),
            "webp" => Ok(Self::Webp),
            "avif" => Ok(Self::Avif),
            other => Err(format!("unsupported image format: {other}")),
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Png => "PNG",
            Self::Jpeg => "JPG",
            Self::Webp => "WebP",
            Self::Avif => "AVIF",
        }
    }

    fn extension(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpg",
            Self::Webp => "webp",
            Self::Avif => "avif",
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
            Self::Avif => "image/avif",
        }
    }

    fn image_format(self) -> ImageFormat {
        match self {
            Self::Png => ImageFormat::Png,
            Self::Jpeg => ImageFormat::Jpeg,
            Self::Webp => ImageFormat::WebP,
            Self::Avif => ImageFormat::Avif,
        }
    }
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct ImageConversionResult {
    pub format: String,
    pub mime: String,
    pub width: u32,
    pub height: u32,
    pub data_base64: String,
    pub data_url: String,
    pub download_name: String,
}

#[derive(Debug, Default, Deserialize, Clone, Copy)]
pub struct ImageOptions {
    /// 1-100 quality where supported (JPEG/AVIF); defaults per format.
    pub quality: Option<u8>,
    /// For formats that expose an encoder speed knob (AVIF 1-10).
    pub speed: Option<u8>,
    /// PNG compression level 0-9 (0 = none, 9 = max).
    pub compression: Option<u8>,
    /// Request lossless when the encoder supports it (only AVIF toggleable here).
    pub lossless: Option<bool>,
}

/// Converts image bytes between JPG/PNG/WebP/AVIF.
pub fn convert_image_bytes(
    from: &str,
    to: &str,
    bytes: &[u8],
    options: ImageOptions,
) -> Result<ImageConversionResult, String> {
    if bytes.is_empty() {
        return Err("input image is empty".into());
    }
    let source = PictureFormat::parse(from)?;
    let target = PictureFormat::parse(to)?;
    let decoded = decode_image(bytes, source)?;
    let (width, height) = decoded.dimensions();
    let encoded = encode_image(&decoded, target, options)?;
    let data_base64 = STANDARD.encode(&encoded);
    let data_url = format!("data:{};base64,{}", target.mime(), data_base64);
    Ok(ImageConversionResult {
        format: target.extension().into(),
        mime: target.mime().into(),
        width,
        height,
        data_base64,
        data_url,
        download_name: format!("converted.{}", target.extension()),
    })
}

fn decode_image(bytes: &[u8], fallback: PictureFormat) -> Result<DynamicImage, String> {
    // Try to honor magic bytes when present so mismatched extensions still work.
    if let Ok(reader) = ImageReader::new(Cursor::new(bytes)).with_guessed_format() {
        if let Ok(image) = reader.decode() {
            return Ok(image);
        }
    }
    image::load_from_memory_with_format(bytes, fallback.image_format())
        .or_else(|_| image::load_from_memory(bytes))
        .map_err(|err| {
            if matches!(fallback, PictureFormat::Avif) {
                format!(
                    "decoding {} requires native AVIF support in this build: {err}",
                    fallback.label()
                )
            } else {
                format!("failed to decode {}: {err}", fallback.label())
            }
        })
}

fn encode_image(
    image: &DynamicImage,
    target: PictureFormat,
    options: ImageOptions,
) -> Result<Vec<u8>, String> {
    let mut buffer = Vec::new();
    match target {
        PictureFormat::Jpeg => {
            let quality = options.quality.unwrap_or(85).clamp(1, 100);
            let rgb = image.to_rgb8();
            let (width, height) = rgb.dimensions();
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(
                Cursor::new(&mut buffer),
                quality,
            );
            enc.encode(rgb.as_raw(), width, height, image::ColorType::Rgb8.into())
                .map_err(|err| format!("failed to encode JPG: {err}"))?;
        }
        PictureFormat::Png => {
            use image::codecs::png::{CompressionType, FilterType, PngEncoder};
            let level = options.compression.unwrap_or(6).clamp(0, 9);
            let compression = if level == 0 {
                CompressionType::Uncompressed
            } else {
                CompressionType::Level(level)
            };
            let encoder = PngEncoder::new_with_quality(
                Cursor::new(&mut buffer),
                compression,
                FilterType::Adaptive,
            );
            let rgba = image.to_rgba8();
            let (width, height) = rgba.dimensions();
            encoder
                .write_image(rgba.as_raw(), width, height, ExtendedColorType::Rgba8)
                .map_err(|err| format!("failed to encode PNG: {err}"))?;
        }
        PictureFormat::Webp => {
            // The pure-Rust WebP encoder is lossless-only today.
            if options.lossless == Some(false) || options.quality.is_some() {
                return Err(
                    "This build encodes WebP losslessly; lossy WebP requires libwebp.".into(),
                );
            }
            let rgba = image.to_rgba8();
            let (width, height) = rgba.dimensions();
            let enc = image::codecs::webp::WebPEncoder::new_lossless(Cursor::new(&mut buffer));
            enc.encode(rgba.as_raw(), width, height, ExtendedColorType::Rgba8)
                .map_err(|err| format!("failed to encode WebP: {err}"))?;
        }
        PictureFormat::Avif => {
            let quality = options.quality.unwrap_or(80).clamp(1, 100);
            let speed = options.speed.unwrap_or(4).clamp(1, 10);
            let lossless = options.lossless.unwrap_or(false);
            let final_quality = if lossless { 100 } else { quality };
            let encoder = image::codecs::avif::AvifEncoder::new_with_speed_quality(
                Cursor::new(&mut buffer),
                speed,
                final_quality,
            );
            let rgba = image.to_rgba8();
            let (width, height) = rgba.dimensions();
            encoder
                .write_image(rgba.as_raw(), width, height, ExtendedColorType::Rgba8)
                .map_err(|err| format!("failed to encode {}: {err}", target.label()))?;
        }
    }
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{ImageBuffer, Rgba};

    fn sample_rgba() -> DynamicImage {
        // 2×2 image with a transparent pixel to ensure alpha survives WebP/AVIF.
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_fn(2, 2, |x, y| match (x, y) {
            (0, 0) => Rgba([255, 0, 0, 255]),
            (1, 0) => Rgba([0, 255, 0, 255]),
            (0, 1) => Rgba([0, 0, 255, 128]),
            _ => Rgba([255, 255, 255, 0]),
        });
        DynamicImage::ImageRgba8(buf)
    }

    fn encode_sample_as(format: PictureFormat) -> Vec<u8> {
        let mut bytes = Vec::new();
        let image = sample_rgba();
        image
            .write_to(&mut Cursor::new(&mut bytes), format.image_format())
            .expect("encode fixture");
        bytes
    }

    fn decode_rgba(bytes: &[u8], format: PictureFormat) -> DynamicImage {
        image::load_from_memory_with_format(bytes, format.image_format()).expect("decode")
    }

    #[test]
    fn png_to_webp_preserves_alpha_channel() {
        let png_bytes = encode_sample_as(PictureFormat::Png);
        let result = convert_image_bytes("png", "webp", &png_bytes, ImageOptions::default())
            .expect("png -> webp");
        let decoded_bytes = STANDARD
            .decode(result.data_base64.as_bytes())
            .expect("decode base64");
        let decoded = decode_rgba(&decoded_bytes, PictureFormat::Webp).to_rgba8();
        // Transparent pixel should remain fully transparent.
        assert_eq!(decoded.get_pixel(1, 1).0[3], 0);
        assert_eq!(result.mime, "image/webp");
        assert_eq!(result.format, "webp");
    }

    #[test]
    fn jpg_to_avif_sets_metadata() {
        let jpg_bytes = encode_sample_as(PictureFormat::Jpeg);
        let avif_res = convert_image_bytes("jpg", "avif", &jpg_bytes, ImageOptions::default())
            .expect("jpg -> avif");
        assert_eq!(avif_res.format, "avif");
        assert_eq!(avif_res.mime, "image/avif");
        assert!(avif_res.data_url.starts_with("data:image/avif;base64,"));
        assert!(avif_res.data_base64.len() > 24);
        assert_eq!(avif_res.width, 2);
        assert_eq!(avif_res.height, 2);
    }

    #[test]
    fn avif_decode_failure_surfaces_clear_error() {
        let jpg_bytes = encode_sample_as(PictureFormat::Jpeg);
        let avif_res = convert_image_bytes("jpg", "avif", &jpg_bytes, ImageOptions::default())
            .expect("encode avif");
        let avif_bytes = STANDARD.decode(&avif_res.data_base64).expect("decode avif");
        let err =
            convert_image_bytes("avif", "png", &avif_bytes, ImageOptions::default()).unwrap_err();
        let err_lower = err.to_lowercase();
        assert!(
            err_lower.contains("avif"),
            "unexpected avif decode error message: {err}"
        );
    }
}
