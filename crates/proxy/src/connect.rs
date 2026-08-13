/// Splits a `host[:port]` authority into host and port, handling IPv6
/// literals. Mirrors the Python `_split_host_port` helper.
pub fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    if let Some(host) = authority.strip_prefix('[') {
        if let Some(end) = host.find(']') {
            let ipv6 = &host[..end];
            let rest = &host[end + 1..];
            if let Some(port_str) = rest.strip_prefix(':') {
                if let Ok(port) = port_str.parse::<u16>() {
                    return (ipv6.to_owned(), port);
                }
            }
            return (ipv6.to_owned(), default_port);
        }
        return (authority.to_owned(), default_port);
    }

    if let Some((host, port_str)) = authority.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_owned(), port);
        }
    }
    (authority.to_owned(), default_port)
}

pub fn parse_connect_target(target: &str) -> (String, u16) {
    split_host_port(target, 443)
}

#[cfg(test)]
mod tests {
    use super::{parse_connect_target, split_host_port};

    #[test]
    fn splits_host_port() {
        assert_eq!(
            split_host_port("example.com:8080", 80),
            ("example.com".to_owned(), 8080)
        );
        assert_eq!(
            split_host_port("example.com", 80),
            ("example.com".to_owned(), 80)
        );
    }

    #[test]
    fn handles_ipv6_literal() {
        assert_eq!(split_host_port("[::1]:8443", 443), ("::1".to_owned(), 8443));
        assert_eq!(split_host_port("[::1]", 443), ("::1".to_owned(), 443));
    }

    #[test]
    fn connect_defaults_to_443() {
        assert_eq!(
            parse_connect_target("api.example.com:443"),
            ("api.example.com".to_owned(), 443)
        );
        assert_eq!(
            parse_connect_target("api.example.com"),
            ("api.example.com".to_owned(), 443)
        );
    }
}
