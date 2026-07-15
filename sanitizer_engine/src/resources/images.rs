/// Strips EXIF/metadata segment (APP1 0xFFE1) from JPEG files.
///
/// # Inputs
/// * `data` - A byte slice containing raw JPEG data.
///
/// # Returns
/// * `Vec<u8>` - A new vector with all APP1 (`0xFFE1`) metadata segments removed.
pub fn strip_jpeg_metadata(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(data.len());
    if data.len() < 2 || data[0] != 0xFF || data[1] != 0xD8 {
        return data.to_vec();
    }
    output.push(0xFF);
    output.push(0xD8);
    let mut i = 2;
    while i < data.len() {
        if data[i] == 0xFF {
            if i + 1 >= data.len() {
                output.push(0xFF);
                break;
            }
            let marker = data[i + 1];
            if marker == 0x00 {
                output.push(0xFF);
                output.push(0x00);
                i += 2;
                continue;
            }
            if marker == 0xD9 {
                output.push(0xFF);
                output.push(0xD9);
                break;
            }
            if (0xD0..=0xD7).contains(&marker) {
                output.push(0xFF);
                output.push(marker);
                i += 2;
                continue;
            }
            if i + 3 >= data.len() {
                output.extend_from_slice(&data[i..]);
                break;
            }
            let len = ((data[i + 2] as usize) << 8) | (data[i + 3] as usize);
            if i + 2 + len > data.len() {
                output.extend_from_slice(&data[i..]);
                break;
            }
            if marker == 0xE1 {
                // Strip APP1 marker which typically contains EXIF metadata
                i += 2 + len;
            } else {
                output.extend_from_slice(&data[i..i + 2 + len]);
                i += 2 + len;
            }
        } else {
            output.push(data[i]);
            i += 1;
        }
    }
    output
}

/// Strips metadata chunks from PNG files.
///
/// # Inputs
/// * `data` - A byte slice containing raw PNG data.
///
/// # Returns
/// * `Vec<u8>` - A new vector with metadata chunks (`tEXt`, `zTXt`, `iTXt`, `eXIf`, `iCCP`, `gAMA`, `sRGB`, `tIME`) removed.
pub fn strip_png_metadata(data: &[u8]) -> Vec<u8> {
    let sig = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if data.len() < 8 || &data[0..8] != sig {
        return data.to_vec();
    }
    let mut output = Vec::with_capacity(data.len());
    output.extend_from_slice(sig);
    let mut i = 8;
    while i + 8 <= data.len() {
        let chunk_len = ((data[i] as u32) << 24
            | (data[i + 1] as u32) << 16
            | (data[i + 2] as u32) << 8
            | (data[i + 3] as u32)) as usize;
        let chunk_type = &data[i + 4..i + 8];

        if i + 12 + chunk_len > data.len() {
            output.extend_from_slice(&data[i..]);
            break;
        }

        let is_metadata = matches!(
            chunk_type,
            b"tEXt" | b"zTXt" | b"iTXt" | b"eXIf" | b"iCCP" | b"gAMA" | b"sRGB" | b"tIME"
        );

        if is_metadata {
            i += 12 + chunk_len;
        } else {
            output.extend_from_slice(&data[i..i + 12 + chunk_len]);
            i += 12 + chunk_len;
        }
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strip_jpeg_metadata() {
        let jpeg = vec![
            0xFF, 0xD8, 0xFF, 0xE1, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
        ];
        let stripped = strip_jpeg_metadata(&jpeg);
        assert_eq!(stripped, vec![0xFF, 0xD8, 0xFF, 0xD9]);
    }

    #[test]
    fn test_strip_png_metadata() {
        let mut png = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        // add tEXt chunk
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x04]); // length
        png.extend_from_slice(b"tEXt"); // type
        png.extend_from_slice(b"data"); // data
        png.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // CRC

        let stripped = strip_png_metadata(&png);
        assert_eq!(
            stripped,
            vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        );
    }
}
