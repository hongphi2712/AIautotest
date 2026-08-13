use std::borrow::Cow;

pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: String,
    pub value: String,
}

impl Header {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedRequest<'a> {
    pub method: &'a str,
    pub target: &'a str,
    pub version: &'a str,
    pub headers: Vec<Header>,
    pub body: Option<&'a [u8]>,
    pub consumed: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse<'a> {
    pub version: &'a str,
    pub status: u16,
    pub reason: &'a str,
    pub headers: Vec<Header>,
    pub body: Option<Cow<'a, [u8]>>,
    pub head_len: usize,
}

pub fn parse_request(buffer: &[u8]) -> Option<ParsedRequest<'_>> {
    let head_end = find_head_end(buffer)?;
    let head = std::str::from_utf8(&buffer[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next()?;

    let headers = parse_header_lines(lines)?;
    let content_length = content_length(&headers);

    let body_start = head_end + 4;
    if buffer.len().saturating_sub(body_start) < content_length {
        return None;
    }
    let body = if content_length > 0 {
        Some(&buffer[body_start..body_start + content_length])
    } else {
        None
    };

    Some(ParsedRequest {
        method,
        target,
        version,
        headers,
        body,
        consumed: body_start + content_length,
    })
}

pub fn parse_response(raw: &[u8]) -> Option<ParsedResponse<'_>> {
    let head_end = find_head_end(raw)?;
    let head = std::str::from_utf8(&raw[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?;
    let status = parts.next()?.parse::<u16>().ok()?;
    let reason = parts.next().unwrap_or("");

    let headers = parse_header_lines(lines)?;
    let body_raw = &raw[head_end + 4..];
    let body = if body_raw.is_empty() {
        None
    } else if is_chunked(&headers) {
        decode_chunked(body_raw).map(Cow::Owned)
    } else {
        Some(Cow::Borrowed(body_raw))
    };

    Some(ParsedResponse {
        version,
        status,
        reason,
        headers,
        body,
        head_len: head_end + 4,
    })
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_header_lines<'a>(lines: impl Iterator<Item = &'a str>) -> Option<Vec<Header>> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(':')?;
        headers.push(Header {
            name: name.trim().to_owned(),
            value: value.trim().to_owned(),
        });
    }
    Some(headers)
}

fn content_length(headers: &[Header]) -> usize {
    headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
        .and_then(|header| header.value.trim().parse::<usize>().ok())
        .unwrap_or(0)
}

fn is_chunked(headers: &[Header]) -> bool {
    headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header.value.to_ascii_lowercase().contains("chunked")
    })
}

/// Removes HTTP chunk framing, returning the reassembled body.
pub fn decode_chunked(body: &[u8]) -> Option<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut pos = 0usize;
    while pos < body.len() {
        let line_end = find_crlf(body, pos)?;
        let size_line = std::str::from_utf8(&body[pos..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_line, 16).ok()?;
        pos = line_end + 2;
        if size == 0 {
            break;
        }
        let end = pos.checked_add(size)?;
        if end > body.len() {
            return None;
        }
        decoded.extend_from_slice(&body[pos..end]);
        pos = end;
        if body.get(pos..pos + 2) == Some(b"\r\n") {
            pos += 2;
        }
    }
    Some(decoded)
}

fn find_crlf(body: &[u8], from: usize) -> Option<usize> {
    body[from..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|index| from + index)
}

#[cfg(test)]
mod tests {
    use super::{Header, parse_request, parse_response};

    #[test]
    fn request_with_content_length() {
        let raw =
            b"POST /api/login HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
        let parsed = parse_request(raw).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.target, "/api/login");
        assert_eq!(parsed.version, "HTTP/1.1");
        assert_eq!(parsed.body, Some(&b"hello"[..]));
        assert_eq!(parsed.consumed, raw.len());
        assert_eq!(parsed.headers[0], Header::new("Host", "example.com"));
    }

    #[test]
    fn incomplete_request_returns_none() {
        let raw = b"POST /api/login HTTP/1.1\r\nContent-Length: 10\r\n\r\nhi";
        assert!(parse_request(raw).is_none());
    }

    #[test]
    fn request_without_body() {
        let raw = b"GET /api/health HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let parsed = parse_request(raw).unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.body, None);
    }

    #[test]
    fn response_plain() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let parsed = parse_response(raw).unwrap();
        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.reason, "OK");
        assert_eq!(parsed.body.as_deref(), Some(&b"{}"[..]));
    }

    #[test]
    fn response_chunked() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let parsed = parse_response(raw).unwrap();
        assert_eq!(parsed.body.as_deref(), Some(&b"hello world"[..]));
    }
}
