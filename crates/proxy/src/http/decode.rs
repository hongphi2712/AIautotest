use std::io::Read;

use flate2::read::{GzDecoder, ZlibDecoder};

use super::parse::Header;

/// Returns the normalized `Content-Encoding` header value.
pub fn content_encoding(headers: &[Header]) -> String {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-encoding"))
        .map(|header| header.value.to_ascii_lowercase())
        .unwrap_or_default()
}

/// Decodes a body for gzip/deflate (brotli is a no-op fallback), then caps
/// the result at `max` bytes. A failed decompression falls back to the raw
/// bytes so the flow is never lost.
pub fn decode_body(body: &[u8], encoding: &str, max: usize) -> Vec<u8> {
    let mut decoded = match encoding {
        "gzip" => inflate_gzip(body).unwrap_or_else(|| body.to_vec()),
        "deflate" => inflate_zlib(body).unwrap_or_else(|| body.to_vec()),
        _ => body.to_vec(),
    };
    if decoded.len() > max {
        decoded.truncate(max);
    }
    decoded
}

fn inflate_gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(body);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn inflate_zlib(body: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(body);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::decode_body;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn decodes_gzip() {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(b"hello world").unwrap();
        let compressed = encoder.finish().unwrap();

        let decoded = decode_body(&compressed, "gzip", 1024);

        assert_eq!(decoded, b"hello world");
    }

    #[test]
    fn truncates_over_max() {
        let decoded = decode_body(b"aaaaaaaaaaaaaaaaaaaa", "identity", 5);
        assert_eq!(decoded.len(), 5);
    }

    #[test]
    fn failed_decompress_falls_back_to_raw() {
        let decoded = decode_body(b"not-gzip", "gzip", 1024);
        assert_eq!(decoded, b"not-gzip");
    }
}
