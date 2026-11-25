//! Zero-decode Pure-Rust image dimension & format inspector (PNG, JPEG, GIF, WebP).
//! Eliminates heavy native C/C++ dependencies like `libvips` / `sharp` when uploading photos.

use crate::error::{ZaloxError, ZaloxResult};

/// Detected image container format and pixel geometry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageGeometry {
    pub width: u32,
    pub height: u32,
    pub format: ImageFormatKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormatKind {
    Png,
    Jpeg,
    Gif,
    Webp,
}

/// Reads pixel width and height directly from binary container headers without decoding pixels.
pub fn probe_image_dimensions(bytes: &[u8]) -> ZaloxResult<ImageGeometry> {
    if bytes.len() < 16 {
        return Err(ZaloxError::Media(
            "Image buffer too small to contain a valid header".into(),
        ));
    }

    // 1. PNG: 89 50 4E 47 0D 0A 1A 0A + IHDR at offset 16..24
    if bytes.len() >= 24 && &bytes[0..8] == b"\x89PNG\r\n\x1a\n" {
        let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
        return Ok(ImageGeometry {
            width,
            height,
            format: ImageFormatKind::Png,
        });
    }

    // 2. GIF87a / GIF89a: width LE u16 at 6..8, height LE u16 at 8..10
    if &bytes[0..6] == b"GIF87a" || &bytes[0..6] == b"GIF89a" {
        let width = u32::from(u16::from_le_bytes([bytes[6], bytes[7]]));
        let height = u32::from(u16::from_le_bytes([bytes[8], bytes[9]]));
        return Ok(ImageGeometry {
            width,
            height,
            format: ImageFormatKind::Gif,
        });
    }

    // 3. WebP: RIFF....WEBP
    if bytes.len() >= 30 && &bytes[0..4] == b"RIFF" && &bytes[8..12] == b"WEBP" {
        return parse_webp_header(bytes);
    }

    // 4. JPEG: FF D8 ... scan SOF markers
    if bytes[0] == 0xFF && bytes[1] == 0xD8 {
        return parse_jpeg_sof(bytes);
    }

    Err(ZaloxError::Media(
        "Unsupported or unrecognized image header (expected PNG, JPEG, GIF, or WebP)".into(),
    ))
}

fn parse_webp_header(bytes: &[u8]) -> ZaloxResult<ImageGeometry> {
    let chunk = &bytes[12..16];
    match chunk {
        b"VP8 " if bytes.len() >= 30 => {
            let width = u32::from(u16::from_le_bytes([bytes[26], bytes[27]]) & 0x3FFF);
            let height = u32::from(u16::from_le_bytes([bytes[28], bytes[29]]) & 0x3FFF);
            Ok(ImageGeometry {
                width,
                height,
                format: ImageFormatKind::Webp,
            })
        }
        b"VP8L" if bytes.len() >= 25 => {
            let bits = u32::from_le_bytes([bytes[21], bytes[22], bytes[23], bytes[24]]);
            let width = (bits & 0x3FFF) + 1;
            let height = ((bits >> 14) & 0x3FFF) + 1;
            Ok(ImageGeometry {
                width,
                height,
                format: ImageFormatKind::Webp,
            })
        }
        b"VP8X" if bytes.len() >= 30 => {
            let width =
                (u32::from(bytes[24]) | (u32::from(bytes[25]) << 8) | (u32::from(bytes[26]) << 16))
                    + 1;
            let height =
                (u32::from(bytes[27]) | (u32::from(bytes[28]) << 8) | (u32::from(bytes[29]) << 16))
                    + 1;
            Ok(ImageGeometry {
                width,
                height,
                format: ImageFormatKind::Webp,
            })
        }
        _ => Err(ZaloxError::Media("Unrecognized WebP chunk layout".into())),
    }
}

fn parse_jpeg_sof(bytes: &[u8]) -> ZaloxResult<ImageGeometry> {
    let mut pos = 2usize;
    while pos + 4 < bytes.len() {
        if bytes[pos] != 0xFF {
            pos += 1;
            continue;
        }
        while pos < bytes.len() && bytes[pos] == 0xFF {
            pos += 1;
        }
        if pos >= bytes.len() {
            break;
        }
        let marker = bytes[pos];
        pos += 1;

        if marker == 0xD8 || marker == 0xD9 || (0xD0..=0xD7).contains(&marker) || marker == 0x01 {
            continue;
        }
        if pos + 2 > bytes.len() {
            break;
        }
        let seg_len = usize::from(u16::from_be_bytes([bytes[pos], bytes[pos + 1]]));
        if seg_len < 2 || pos + seg_len > bytes.len() {
            break;
        }

        // SOF0..SOF3, SOF5..SOF7, SOF9..SOF11, SOF13..SOF15
        let is_sof = matches!(
            marker,
            0xC0..=0xC3 | 0xC5..=0xC7 | 0xC9..=0xCB | 0xCD..=0xCF
        );
        if is_sof && seg_len >= 7 {
            let height = u32::from(u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]));
            let width = u32::from(u16::from_be_bytes([bytes[pos + 5], bytes[pos + 6]]));
            return Ok(ImageGeometry {
                width,
                height,
                format: ImageFormatKind::Jpeg,
            });
        }

        pos += seg_len;
    }
    Err(ZaloxError::Media(
        "Could not find JPEG SOF dimension marker".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_png_and_gif_headers_accurately() {
        let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        png.extend_from_slice(&[0, 0, 0, 13, b'I', b'H', b'D', b'R']);
        png.extend_from_slice(&1920u32.to_be_bytes());
        png.extend_from_slice(&1080u32.to_be_bytes());
        let g = probe_image_dimensions(&png).unwrap();
        assert_eq!(g.width, 1920);
        assert_eq!(g.height, 1080);
        assert_eq!(g.format, ImageFormatKind::Png);

        let mut gif = b"GIF89a".to_vec();
        gif.extend_from_slice(&480u16.to_le_bytes());
        gif.extend_from_slice(&360u16.to_le_bytes());
        gif.extend_from_slice(&[0u8; 10]);
        let g2 = probe_image_dimensions(&gif).unwrap();
        assert_eq!(g2.width, 480);
        assert_eq!(g2.height, 360);
    }
}
