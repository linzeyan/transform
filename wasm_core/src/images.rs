//! Image format conversion helpers shared by wasm bindings and unit tests.
//!
//! All conversions normalize pixel data to either RGB (for JPEG) or RGBA
//! (for PNG/WebP/AVIF) so alpha channels are preserved whenever the
//! target container supports it.

use std::io::Cursor;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use font8x8::{BASIC_FONTS, UnicodeFonts};
use image::{
    DynamicImage, ExtendedColorType, GenericImageView, ImageEncoder, ImageFormat, ImageReader,
    Rgba, RgbaImage,
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

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageBatchInput {
    /// Source format hint (file extension) used when magic bytes are ambiguous.
    pub from: String,
    /// Target format requested by the UI.
    pub to: String,
    /// Raw image bytes selected by the user.
    pub bytes: Vec<u8>,
    /// Original file name so we can preserve the stem in downloads.
    pub file_name: Option<String>,
    /// Optional per-format encoder options.
    #[serde(default)]
    pub options: ImageOptions,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ImageBatchResult {
    pub file_name: String,
    pub result: Option<ImageConversionResult>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum WatermarkDirection {
    Horizontal,
    Vertical,
    #[default]
    Both,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatermarkOptions {
    /// Text to render as the watermark.
    pub text: String,
    /// Opacity in the range [0.0, 1.0]; clamped during normalization.
    #[serde(default = "default_watermark_opacity")]
    pub opacity: f32,
    /// Rotation in degrees applied around the image center.
    #[serde(default)]
    pub rotation_deg: f32,
    /// Pixel spacing between repeated watermarks; clamped to a minimum of 10px.
    #[serde(default = "default_watermark_spacing")]
    pub spacing: u32,
    /// Requested font size in pixels; rendered using a compact bitmap font.
    #[serde(default = "default_watermark_font_size")]
    pub font_size: u32,
    /// Text color in hex (e.g., #FFFFFF or FFFFFF); alpha channel optional.
    #[serde(default = "default_watermark_color")]
    pub color: String,
    /// Tiling direction across the canvas.
    #[serde(default)]
    pub direction: WatermarkDirection,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WatermarkBatchInput {
    pub from: String,
    pub to: String,
    pub bytes: Vec<u8>,
    pub file_name: Option<String>,
    #[serde(default)]
    pub options: ImageOptions,
    pub watermark: WatermarkOptions,
}

fn default_watermark_opacity() -> f32 {
    0.35
}

fn default_watermark_spacing() -> u32 {
    32
}

fn default_watermark_font_size() -> u32 {
    32
}

fn default_watermark_color() -> String {
    "#FFFFFF".into()
}

#[derive(Clone, Copy, Debug)]
struct RgbaColor {
    r: u8,
    g: u8,
    b: u8,
    a: u8,
}

#[derive(Clone, Debug)]
struct NormalizedWatermark {
    text: String,
    opacity: f32,
    rotation_rad: f32,
    spacing: u32,
    font_size: u32,
    color: RgbaColor,
    direction: WatermarkDirection,
}

impl WatermarkOptions {
    fn normalize(&self) -> Result<NormalizedWatermark, String> {
        let text = self.text.trim().to_string();
        if text.is_empty() {
            return Err("watermark text cannot be empty".into());
        }
        let opacity = self.opacity.clamp(0.0, 1.0);
        if opacity <= f32::EPSILON {
            return Err("watermark opacity must be greater than 0".into());
        }
        let spacing = self.spacing.clamp(10, 2_000);
        let font_size = self.font_size.clamp(8, 256);
        let color = parse_hex_color(&self.color).unwrap_or(RgbaColor {
            r: 255,
            g: 255,
            b: 255,
            a: 255,
        });
        let rotation_rad = self.rotation_deg.to_radians();
        Ok(NormalizedWatermark {
            text,
            opacity,
            rotation_rad,
            spacing,
            font_size,
            color,
            direction: self.direction,
        })
    }
}

impl Default for WatermarkOptions {
    fn default() -> Self {
        Self {
            text: "watermark".into(),
            opacity: default_watermark_opacity(),
            rotation_deg: 0.0,
            spacing: default_watermark_spacing(),
            font_size: default_watermark_font_size(),
            color: default_watermark_color(),
            direction: WatermarkDirection::Both,
        }
    }
}

fn parse_hex_color(input: &str) -> Option<RgbaColor> {
    let trimmed = input.trim().trim_start_matches('#');
    let hex = if trimmed.len() == 6 || trimmed.len() == 8 {
        trimmed
    } else {
        return None;
    };
    let (rgb, alpha) = if hex.len() == 6 {
        (hex, "ff")
    } else {
        hex.split_at(6)
    };
    let r = u8::from_str_radix(&rgb[0..2], 16).ok()?;
    let g = u8::from_str_radix(&rgb[2..4], 16).ok()?;
    let b = u8::from_str_radix(&rgb[4..6], 16).ok()?;
    let a = u8::from_str_radix(alpha, 16).ok()?;
    Some(RgbaColor { r, g, b, a })
}

#[derive(Debug, Default, Deserialize, Clone, Copy)]
pub struct ImageOptions {
    /// 1-100 quality where supported (JPEG/AVIF); defaults per format.
    /// For WebP we stay pure-Rust by applying a perceptual RGB quantizer when
    /// quality < 100, letting callers trade detail for size without libwebp.
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

/// Runs the single-file converter for each entry while preserving names and isolating failures.
pub fn convert_image_batch(entries: Vec<ImageBatchInput>) -> Result<Vec<ImageBatchResult>, String> {
    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .file_name
            .as_deref()
            .map(str::to_string)
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "converted".to_string());
        if entry.bytes.is_empty() {
            results.push(ImageBatchResult {
                file_name: name,
                result: None,
                error: Some("input image is empty".into()),
            });
            continue;
        }
        match convert_image_bytes(&entry.from, &entry.to, &entry.bytes, entry.options) {
            Ok(mut res) => {
                res.download_name = derive_download_name(&name, &res.format);
                results.push(ImageBatchResult {
                    file_name: name,
                    result: Some(res),
                    error: None,
                });
            }
            Err(err) => results.push(ImageBatchResult {
                file_name: name,
                result: None,
                error: Some(err),
            }),
        }
    }
    Ok(results)
}

fn resolve_target_format(source: &str, target: &str) -> Result<PictureFormat, String> {
    if target.trim().eq_ignore_ascii_case("original") {
        PictureFormat::parse(source)
    } else {
        PictureFormat::parse(target)
    }
}

fn conversion_result_from_bytes(
    encoded: Vec<u8>,
    target: PictureFormat,
    width: u32,
    height: u32,
    download_name: String,
) -> ImageConversionResult {
    let data_base64 = STANDARD.encode(&encoded);
    let data_url = format!("data:{};base64,{}", target.mime(), data_base64);
    ImageConversionResult {
        format: target.extension().into(),
        mime: target.mime().into(),
        width,
        height,
        data_base64,
        data_url,
        download_name,
    }
}

fn encode_image_result(
    image: &DynamicImage,
    target: PictureFormat,
    options: ImageOptions,
    download_name: String,
) -> Result<ImageConversionResult, String> {
    let (width, height) = image.dimensions();
    encode_image(image, target, options)
        .map(|bytes| conversion_result_from_bytes(bytes, target, width, height, download_name))
}

pub fn apply_image_watermark_bytes(
    from: &str,
    to: &str,
    bytes: &[u8],
    options: ImageOptions,
    watermark: WatermarkOptions,
) -> Result<ImageConversionResult, String> {
    if bytes.is_empty() {
        return Err("input image is empty".into());
    }
    let source_fmt = PictureFormat::parse(from)?;
    let target_fmt = resolve_target_format(from, to)?;
    let decoded = decode_image(bytes, source_fmt)?;
    let normalized = watermark.normalize()?;
    let stamped = apply_watermark(&decoded, &normalized);
    let download_name = derive_download_name("watermarked", target_fmt.extension());
    encode_image_result(
        &DynamicImage::ImageRgba8(stamped),
        target_fmt,
        options,
        download_name,
    )
}

pub fn apply_image_watermark_batch(
    entries: Vec<WatermarkBatchInput>,
) -> Result<Vec<ImageBatchResult>, String> {
    let mut results = Vec::with_capacity(entries.len());
    for entry in entries {
        let name = entry
            .file_name
            .as_deref()
            .map(str::to_string)
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| "converted".to_string());
        if entry.bytes.is_empty() {
            results.push(ImageBatchResult {
                file_name: name,
                result: None,
                error: Some("input image is empty".into()),
            });
            continue;
        }
        match apply_image_watermark_bytes(
            &entry.from,
            &entry.to,
            &entry.bytes,
            entry.options,
            entry.watermark.clone(),
        ) {
            Ok(mut res) => {
                res.download_name = derive_download_name(&name, &res.format);
                results.push(ImageBatchResult {
                    file_name: name,
                    result: Some(res),
                    error: None,
                });
            }
            Err(err) => results.push(ImageBatchResult {
                file_name: name,
                result: None,
                error: Some(err),
            }),
        }
    }
    Ok(results)
}

fn derive_download_name(original: &str, target_ext: &str) -> String {
    let ext = if target_ext.is_empty() {
        "img"
    } else {
        target_ext
    };
    let path = Path::new(original);
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("converted");
    // Ignore directory segments to keep downloads tidy inside the browser.
    let safe_stem: String = stem
        .chars()
        .map(|ch| if ch == '/' || ch == '\\' { '_' } else { ch })
        .collect();
    format!("{safe_stem}.{ext}")
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
            // Keep the pure-Rust encoder by quantizing RGB channels ourselves when
            // callers request quality < 100, so we avoid pulling libwebp C bindings.
            let requested_quality = options.quality.unwrap_or(100).clamp(1, 100);
            let lossless = options.lossless.unwrap_or(requested_quality == 100);
            let mut rgba = image.to_rgba8();
            if !lossless {
                quantize_rgb_for_webp(rgba.as_mut(), requested_quality);
            }
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

fn build_watermark_bitmap(text: &str, scale: u32, alpha: u8) -> (Vec<(i32, i32, u8)>, i32, i32) {
    let scale = scale.max(1);
    let glyph_gap = scale.max(1);
    let mut cursor_x: i32 = 0;
    let mut max_height: i32 = 0;
    let mut pixels: Vec<(i32, i32, u8)> = Vec::new();

    let total = text.chars().count();
    for (idx, ch) in text.chars().enumerate() {
        let glyph = BASIC_FONTS
            .get(ch)
            .unwrap_or_else(|| BASIC_FONTS.get('?').unwrap());
        // Each glyph is 8x8 bits; we scale it up using nearest-neighbor.
        let glyph_width = (8 * scale) as i32;
        let glyph_height = (8 * scale) as i32;
        max_height = max_height.max(glyph_height);

        for (row, bits) in glyph.iter().enumerate() {
            for col in 0..8 {
                if (bits >> col) & 1 == 0 {
                    continue;
                }
                let base_x = cursor_x + (col * scale as usize) as i32;
                let base_y = (row * scale as usize) as i32;
                for dx in 0..scale {
                    for dy in 0..scale {
                        pixels.push((base_x + dx as i32, base_y + dy as i32, alpha));
                    }
                }
            }
        }
        // Advance cursor with a small gap to keep glyphs readable.
        cursor_x += glyph_width + glyph_gap as i32;
        // Avoid trailing gap on the final glyph.
        if idx + 1 == total {
            cursor_x -= glyph_gap as i32;
        }
    }

    let width = cursor_x.max(1);
    let height = max_height.max(1);
    (pixels, width, height)
}

fn apply_watermark(image: &DynamicImage, opts: &NormalizedWatermark) -> RgbaImage {
    let mut canvas = image.to_rgba8();
    let (img_w, img_h) = canvas.dimensions();
    let center_x = img_w as f32 / 2.0;
    let center_y = img_h as f32 / 2.0;

    let alpha = ((opts.opacity * opts.color.a as f32).clamp(0.0, 255.0)).round() as u8;
    let (bitmap, text_w, text_h) = build_watermark_bitmap(&opts.text, opts.font_size, alpha);

    let step_x = (text_w + opts.spacing as i32).max((opts.spacing as i32) + 1);
    let step_y = (text_h + opts.spacing as i32).max((opts.spacing as i32) + 1);

    let mut x_starts: Vec<i32> = Vec::new();
    let mut y_starts: Vec<i32> = Vec::new();

    match opts.direction {
        WatermarkDirection::Horizontal => {
            x_starts.extend((-text_w..img_w as i32 + text_w).step_by(step_x as usize));
            y_starts.push((img_h as i32 / 2).saturating_sub(text_h / 2));
        }
        WatermarkDirection::Vertical => {
            x_starts.push((img_w as i32 / 2).saturating_sub(text_w / 2));
            y_starts.extend((-text_h..img_h as i32 + text_h).step_by(step_y as usize));
        }
        WatermarkDirection::Both => {
            x_starts.extend((-text_w..img_w as i32 + text_w).step_by(step_x as usize));
            y_starts.extend((-text_h..img_h as i32 + text_h).step_by(step_y as usize));
        }
    }

    if y_starts.is_empty() {
        y_starts.push(0);
    }
    if x_starts.is_empty() {
        x_starts.push(0);
    }

    let cos_t = opts.rotation_rad.cos();
    let sin_t = opts.rotation_rad.sin();

    for base_y in &y_starts {
        for base_x in &x_starts {
            for (px, py, px_alpha) in bitmap.iter().copied() {
                let src_x = *base_x + px;
                let src_y = *base_y + py;
                let dx = src_x as f32 - center_x;
                let dy = src_y as f32 - center_y;
                let rx = dx * cos_t - dy * sin_t + center_x;
                let ry = dx * sin_t + dy * cos_t + center_y;
                let tx = rx.round() as i32;
                let ty = ry.round() as i32;
                if tx < 0 || ty < 0 || tx >= img_w as i32 || ty >= img_h as i32 {
                    continue;
                }
                let dst = canvas.get_pixel_mut(tx as u32, ty as u32);
                let alpha = px_alpha;
                if alpha == 0 {
                    continue;
                }
                // Standard "over" alpha blending.
                let inv = 255u16 - alpha as u16;
                let blend = |dst_c: u8, src_c: u8| -> u8 {
                    (((dst_c as u16 * inv) + (src_c as u16 * alpha as u16)) / 255) as u8
                };
                let out_alpha = alpha as u16 + (dst[3] as u16 * inv + 127) / 255; // rounded over operator
                *dst = Rgba([
                    blend(dst[0], opts.color.r),
                    blend(dst[1], opts.color.g),
                    blend(dst[2], opts.color.b),
                    out_alpha.min(255) as u8,
                ]);
            }
        }
    }

    canvas
}

/// Maps a WebP quality slider (1-100) to a reduced RGB palette and updates the
/// provided RGBA buffer in place. Alpha is left untouched so transparency stays
/// crisp while color detail becomes more compressible for the pure-Rust encoder.
fn quantize_rgb_for_webp(data: &mut [u8], quality: u8) {
    if quality >= 100 {
        return;
    }
    let levels = webp_levels_from_quality(quality);
    let step = 255.0 / (levels as f32 - 1.0);
    for pixel in data.chunks_exact_mut(4) {
        for channel in pixel.iter_mut().take(3) {
            let value = f32::from(*channel);
            let bucket = (value / step).round();
            let quantized = (bucket * step).round().clamp(0.0, 255.0) as u8;
            *channel = quantized;
        }
    }
}

/// Bias the bucket count toward finer palettes at high quality while keeping
/// very low qualities aggressively coarse for size wins.
fn webp_levels_from_quality(quality: u8) -> u16 {
    if quality >= 100 {
        return 256;
    }
    let normalized = (quality as f32).clamp(1.0, 100.0) / 100.0;
    let levels = 2.0 + normalized * normalized * 254.0;
    levels.round().clamp(2.0, 256.0) as u16
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

    fn gradient_rgba(width: u32, height: u32) -> DynamicImage {
        // Deliberately varied pattern so quantization has visible impact.
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |x, y| {
            let r = ((x * 5 + y * 3) % 256) as u8;
            let g = ((x * 7 + y * 11) % 256) as u8;
            let b = ((x * 13 + y * 17) % 256) as u8;
            Rgba([r, g, b, 255])
        });
        DynamicImage::ImageRgba8(buf)
    }

    fn noisy_rgba(width: u32, height: u32) -> DynamicImage {
        // Deterministic pseudo-random colors to keep the size comparison stable.
        let mut seed: u32 = 0x4d59_5df4;
        let buf: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_fn(width, height, |_x, _y| {
            seed = seed
                .wrapping_mul(1_664_525)
                .wrapping_add(1_013_904_223)
                .rotate_left(5);
            let r = (seed & 0xff) as u8;
            let g = ((seed >> 8) & 0xff) as u8;
            let b = ((seed >> 16) & 0xff) as u8;
            Rgba([r, g, b, 255])
        });
        DynamicImage::ImageRgba8(buf)
    }

    fn encode_dynamic_as(image: &DynamicImage, format: PictureFormat) -> Vec<u8> {
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), format.image_format())
            .expect("encode dynamic fixture");
        bytes
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
    fn webp_quality_100_stays_lossless() {
        let fixture = gradient_rgba(8, 8);
        let png_bytes = encode_dynamic_as(&fixture, PictureFormat::Png);
        let result = convert_image_bytes(
            "png",
            "webp",
            &png_bytes,
            ImageOptions {
                quality: Some(100),
                ..ImageOptions::default()
            },
        )
        .expect("png -> webp q100");
        let decoded_bytes = STANDARD
            .decode(result.data_base64.as_bytes())
            .expect("decode webp b64");
        let decoded = decode_rgba(&decoded_bytes, PictureFormat::Webp).to_rgba8();
        assert_eq!(
            decoded,
            fixture.to_rgba8(),
            "quality 100 should round-trip through the lossless encoder"
        );
    }

    #[test]
    fn webp_quality_controls_size_and_pixels() {
        let fixture = noisy_rgba(64, 64);
        let png_bytes = encode_dynamic_as(&fixture, PictureFormat::Png);

        let lossless = convert_image_bytes("png", "webp", &png_bytes, ImageOptions::default())
            .expect("webp default");
        let lossy = convert_image_bytes(
            "png",
            "webp",
            &png_bytes,
            ImageOptions {
                quality: Some(35),
                lossless: Some(false),
                ..ImageOptions::default()
            },
        )
        .expect("webp q35");

        let lossless_bytes = STANDARD
            .decode(lossless.data_base64.as_bytes())
            .expect("decode lossless webp");
        let lossy_bytes = STANDARD
            .decode(lossy.data_base64.as_bytes())
            .expect("decode lossy webp");

        assert!(
            lossy_bytes.len() < lossless_bytes.len(),
            "reduced quality should shrink WebP payload ({} -> {})",
            lossless_bytes.len(),
            lossy_bytes.len()
        );

        let lossless_img = decode_rgba(&lossless_bytes, PictureFormat::Webp).to_rgba8();
        let lossy_img = decode_rgba(&lossy_bytes, PictureFormat::Webp).to_rgba8();
        let changed_pixels = lossless_img
            .pixels()
            .zip(lossy_img.pixels())
            .filter(|(a, b)| a.0[..3] != b.0[..3])
            .count();
        assert!(
            changed_pixels > 0,
            "lowering WebP quality should alter at least one RGB pixel"
        );
        for pixel in lossy_img.pixels() {
            assert_eq!(pixel.0[3], 255, "alpha channel must remain intact");
        }
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

    #[test]
    fn convert_image_batch_preserves_names_and_results() {
        let png_bytes = encode_sample_as(PictureFormat::Png);
        let jpg_bytes = encode_sample_as(PictureFormat::Jpeg);
        let batch = vec![
            ImageBatchInput {
                from: "png".into(),
                to: "webp".into(),
                bytes: png_bytes.clone(),
                file_name: Some("first.png".into()),
                options: ImageOptions::default(),
            },
            ImageBatchInput {
                from: "jpg".into(),
                to: "avif".into(),
                bytes: jpg_bytes.clone(),
                file_name: Some("second photo.jpg".into()),
                options: ImageOptions::default(),
            },
        ];
        let results = convert_image_batch(batch).expect("batch convert");
        assert_eq!(results.len(), 2);
        let first = results.first().expect("first result");
        let second = results.get(1).expect("second result");
        assert_eq!(first.file_name, "first.png");
        assert!(first.error.is_none(), "unexpected error: {:?}", first.error);
        let first_res = first.result.as_ref().expect("first payload");
        assert_eq!(first_res.format, "webp");
        assert_eq!(first_res.download_name, "first.webp");
        assert_eq!(second.file_name, "second photo.jpg");
        let second_res = second.result.as_ref().expect("second payload");
        assert_eq!(second_res.format, "avif");
        assert_eq!(second_res.download_name, "second photo.avif");
    }

    #[test]
    fn convert_image_batch_handles_empty_inputs() {
        let batch = vec![ImageBatchInput {
            from: "png".into(),
            to: "jpg".into(),
            bytes: Vec::new(),
            file_name: Some("blank.png".into()),
            options: ImageOptions::default(),
        }];
        let results = convert_image_batch(batch).expect("batch convert");
        assert_eq!(results.len(), 1);
        let res = &results[0];
        assert_eq!(res.file_name, "blank.png");
        assert!(res.result.is_none());
        assert_eq!(res.error.as_deref(), Some("input image is empty"));
    }

    #[test]
    fn watermark_rejects_empty_text() {
        let png_bytes = encode_sample_as(PictureFormat::Png);
        let err = apply_image_watermark_bytes(
            "png",
            "png",
            &png_bytes,
            ImageOptions::default(),
            WatermarkOptions {
                text: "".into(),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(err.to_lowercase().contains("watermark text"));
    }

    #[test]
    fn watermark_draws_and_preserves_dimensions() {
        let png_bytes = encode_sample_as(PictureFormat::Png);
        let res = apply_image_watermark_bytes(
            "png",
            "png",
            &png_bytes,
            ImageOptions::default(),
            WatermarkOptions {
                text: "WATERMARK".into(),
                opacity: 0.5,
                rotation_deg: 30.0,
                spacing: 12,
                font_size: 16,
                color: "#FF0000".into(),
                direction: WatermarkDirection::Both,
            },
        )
        .expect("watermark applied");
        assert_eq!(res.width, 2);
        assert_eq!(res.height, 2);
        assert!(res.data_base64.len() > 8);
    }

    #[test]
    fn watermark_spacing_is_clamped() {
        let png_bytes = encode_sample_as(PictureFormat::Png);
        let res = apply_image_watermark_bytes(
            "png",
            "png",
            &png_bytes,
            ImageOptions::default(),
            WatermarkOptions {
                text: "X".into(),
                opacity: 0.7,
                rotation_deg: 0.0,
                spacing: 1, // below minimum
                font_size: 12,
                color: "#00FF00".into(),
                direction: WatermarkDirection::Horizontal,
            },
        )
        .expect("watermark applied");
        assert!(res.data_url.starts_with("data:image/png;base64,"));
    }
}
