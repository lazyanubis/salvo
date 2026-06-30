use salvo_core::http::header::HeaderValue;

pub(crate) fn wildcard_origin_matches(pattern: &HeaderValue, origin: &HeaderValue) -> bool {
    let Ok(pattern) = pattern.to_str() else {
        return false;
    };
    let Ok(origin) = origin.to_str() else {
        return false;
    };
    let Some(pattern_parts) = OriginPatternParts::parse(pattern) else {
        return false;
    };
    if !pattern_parts.host_pattern.starts_with("*.") {
        return false;
    }
    let Some(origin_parts) = OriginParts::parse(origin) else {
        return false;
    };

    if let Some(pattern_scheme) = pattern_parts.scheme
        && !pattern_scheme.eq_ignore_ascii_case(origin_parts.scheme)
    {
        return false;
    }
    if let Some(pattern_port) = pattern_parts.port
        && Some(pattern_port) != origin_parts.port
    {
        return false;
    }

    let suffix = &pattern_parts.host_pattern[1..];
    origin_parts.host.ends_with(suffix) && origin_parts.host.len() > suffix.len()
}

struct OriginPatternParts<'a> {
    scheme: Option<&'a str>,
    host_pattern: String,
    port: Option<&'a str>,
}

impl<'a> OriginPatternParts<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (scheme, rest) = if let Some((scheme, rest)) = value.split_once("://") {
            (Some(scheme), rest)
        } else {
            (None, value)
        };
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host_pattern, port) = split_host_port(authority)?;
        Some(Self {
            scheme,
            host_pattern: host_pattern.to_ascii_lowercase(),
            port,
        })
    }
}

struct OriginParts<'a> {
    scheme: &'a str,
    host: String,
    port: Option<&'a str>,
}

impl<'a> OriginParts<'a> {
    fn parse(value: &'a str) -> Option<Self> {
        let (scheme, rest) = value.split_once("://")?;
        let authority = rest.split('/').next().unwrap_or(rest);
        let (host, port) = split_host_port(authority)?;
        Some(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
        })
    }
}

fn split_host_port(authority: &str) -> Option<(&str, Option<&str>)> {
    if authority.is_empty() || authority.starts_with('[') {
        return None;
    }
    if let Some((host, port)) = authority.rsplit_once(':') {
        if host.contains(':') {
            return Some((authority, None));
        }
        if host.is_empty() || port.is_empty() {
            return None;
        }
        Some((host, Some(port)))
    } else {
        Some((authority, None))
    }
}
