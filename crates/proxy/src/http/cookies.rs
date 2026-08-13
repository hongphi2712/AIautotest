use std::collections::BTreeMap;

use super::parse::Header;

/// Extracts cookie names without retaining sensitive cookie values.
pub fn cookie_names(headers: &[Header], response: bool) -> Vec<String> {
    let mut names = std::collections::BTreeSet::new();
    if response {
        for header in headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
        {
            if let Some(first) = header.value.split(['=', ';']).next() {
                names.insert(first.trim().to_owned());
            }
        }
    } else {
        for header in headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("cookie"))
        {
            for part in header.value.split(';') {
                if let Some((name, _)) = part.split_once('=') {
                    names.insert(name.trim().to_owned());
                }
            }
        }
    }
    names.into_iter().collect()
}

/// Extracts cookie name/value pairs from request or response headers.
pub fn cookie_values(headers: &[Header], response: bool) -> BTreeMap<String, String> {
    let source: Vec<&Header> = if response {
        headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("set-cookie"))
            .collect()
    } else {
        headers
            .iter()
            .filter(|header| header.name.eq_ignore_ascii_case("cookie"))
            .collect()
    };

    let mut values = BTreeMap::new();
    for header in source {
        let pairs: Vec<&str> = if response {
            header.value.split(';').next().into_iter().collect()
        } else {
            header.value.split(';').collect()
        };
        for pair in pairs {
            if let Some((name, value)) = pair.split_once('=') {
                values.insert(name.trim().to_owned(), value.trim().to_owned());
            }
        }
    }
    values
}

#[cfg(test)]
mod tests {
    use super::{cookie_names, cookie_values};
    use crate::http::parse::Header;

    #[test]
    fn extracts_request_cookies() {
        let headers = vec![Header::new("Cookie", "a=1; b=2; session=abc")];
        assert_eq!(cookie_names(&headers, false), vec!["a", "b", "session"]);
        let values = cookie_values(&headers, false);
        assert_eq!(values.get("session").map(String::as_str), Some("abc"));
    }

    #[test]
    fn extracts_set_cookie_names_only() {
        let headers = vec![Header::new("Set-Cookie", "sid=xyz; Path=/; HttpOnly")];
        assert_eq!(cookie_names(&headers, true), vec!["sid"]);
        let values = cookie_values(&headers, true);
        assert_eq!(values.get("sid").map(String::as_str), Some("xyz"));
    }
}
