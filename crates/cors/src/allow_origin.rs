use std::fmt::{self, Debug, Formatter};
use std::pin::Pin;
use std::sync::Arc;

use salvo_core::http::header::{self, HeaderName, HeaderValue};
use salvo_core::{Depot, Request};

use super::{Any, WILDCARD};

/// Holds configuration for how to set the [`Access-Control-Allow-Origin`][mdn] header.
///
/// See [`Cors::allow_origin`] for more details.
///
/// [mdn]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Origin
/// [`Cors::allow_origin`]: super::Cors::allow_origin
#[derive(Clone, Default)]
#[must_use]
pub struct AllowOrigin(OriginInner);

impl AllowOrigin {
    /// Allow any origin by sending a wildcard (`*`)
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn any() -> Self {
        Self(OriginInner::Exact(WILDCARD.clone()))
    }

    /// Set a single allowed origin
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn exact(origin: HeaderValue) -> Self {
        Self(OriginInner::Exact(origin))
    }

    /// Set multiple allowed origins
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// # Panics
    ///
    /// Panics if the iterator contains a wildcard (`*`).
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn list<I>(origins: I) -> Self
    where
        I: IntoIterator<Item = HeaderValue>,
    {
        let origins = origins.into_iter().collect::<Vec<_>>();
        if origins.contains(&WILDCARD) {
            panic!(
                "Wildcard origin (`*`) cannot be passed to `AllowOrigin::list`. Use `AllowOrigin::any()` instead"
            );
        } else {
            Self(OriginInner::List(origins))
        }
    }

    /// Set the allowed origins by a closure
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn dynamic<C>(c: C) -> Self
    where
        C: Fn(Option<&HeaderValue>, &Request, &Depot) -> Option<HeaderValue>
            + Send
            + Sync
            + 'static,
    {
        Self(OriginInner::Dynamic(Arc::new(c)))
    }

    /// Set the allowed origins by a async closure
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn dynamic_async<C, Fut>(c: C) -> Self
    where
        C: Fn(Option<&HeaderValue>, &Request, &Depot) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Option<HeaderValue>> + Send + 'static,
    {
        Self(OriginInner::DynamicAsync(Arc::new(
            move |header, req, depot| Box::pin(c(header, req, depot)),
        )))
    }

    /// Allow any origin, by mirroring the request origin.
    ///
    /// See [`Cors::allow_origin`] for more details.
    ///
    /// [`Cors::allow_origin`]: super::Cors::allow_origin
    pub fn mirror_request() -> Self {
        Self::dynamic(|v, _, _| v.cloned())
    }

    pub(super) fn is_wildcard(&self) -> bool {
        matches!(&self.0, OriginInner::Exact(v) if v == WILDCARD)
    }

    pub(super) async fn to_header(
        &self,
        origin: Option<&HeaderValue>,
        req: &Request,
        depot: &Depot,
    ) -> Option<(HeaderName, HeaderValue)> {
        let allow_origin = match &self.0 {
            OriginInner::Exact(v) => v.clone(),
            OriginInner::List(l) => {
                let origin = origin?;
                if l.iter()
                    .any(|allowed| allowed == origin || wildcard_origin_matches(allowed, origin))
                {
                    origin.clone()
                } else {
                    return None;
                }
            }
            OriginInner::Dynamic(c) => c(origin, req, depot)?,
            OriginInner::DynamicAsync(c) => c(origin, req, depot).await?,
        };

        Some((header::ACCESS_CONTROL_ALLOW_ORIGIN, allow_origin))
    }
}

impl Debug for AllowOrigin {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            OriginInner::Exact(inner) => f.debug_tuple("Exact").field(inner).finish(),
            OriginInner::List(inner) => f.debug_tuple("List").field(inner).finish(),
            OriginInner::Dynamic(_) => f.debug_tuple("Dynamic").finish(),
            OriginInner::DynamicAsync(_) => f.debug_tuple("DynamicAsync").finish(),
        }
    }
}

impl From<Any> for AllowOrigin {
    fn from(_: Any) -> Self {
        Self::any()
    }
}

impl From<HeaderValue> for AllowOrigin {
    fn from(val: HeaderValue) -> Self {
        Self::exact(val)
    }
}

impl<const N: usize> From<[HeaderValue; N]> for AllowOrigin {
    fn from(arr: [HeaderValue; N]) -> Self {
        Self::list(arr)
    }
}

impl From<Vec<HeaderValue>> for AllowOrigin {
    fn from(vec: Vec<HeaderValue>) -> Self {
        Self::list(vec)
    }
}

impl From<&str> for AllowOrigin {
    fn from(val: &str) -> Self {
        Self::exact(HeaderValue::from_str(val).expect("invalid `HeaderValue`"))
    }
}

impl From<&String> for AllowOrigin {
    fn from(val: &String) -> Self {
        Self::exact(HeaderValue::from_str(val).expect("invalid `HeaderValue`"))
    }
}

impl From<Vec<&str>> for AllowOrigin {
    fn from(vals: Vec<&str>) -> Self {
        Self::list(
            vals.iter()
                .map(|v| HeaderValue::from_str(v).expect("invalid `HeaderValue`"))
                .collect::<Vec<_>>(),
        )
    }
}
impl<const N: usize> From<[&str; N]> for AllowOrigin {
    fn from(vals: [&str; N]) -> Self {
        Self::list(
            vals.iter()
                .map(|v| HeaderValue::from_str(v).expect("invalid `HeaderValue`"))
                .collect::<Vec<_>>(),
        )
    }
}
impl From<&Vec<String>> for AllowOrigin {
    fn from(vals: &Vec<String>) -> Self {
        Self::list(
            vals.iter()
                .map(|v| HeaderValue::from_str(v).expect("invalid `HeaderValue`"))
                .collect::<Vec<_>>(),
        )
    }
}

#[derive(Clone)]
enum OriginInner {
    Exact(HeaderValue),
    List(Vec<HeaderValue>),
    Dynamic(
        Arc<dyn Fn(Option<&HeaderValue>, &Request, &Depot) -> Option<HeaderValue> + Send + Sync>,
    ),
    DynamicAsync(
        Arc<
            dyn Fn(
                    Option<&HeaderValue>,
                    &Request,
                    &Depot,
                ) -> Pin<Box<dyn Future<Output = Option<HeaderValue>> + Send>>
                + Send
                + Sync,
        >,
    ),
}

impl Default for OriginInner {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

fn wildcard_origin_matches(pattern: &HeaderValue, origin: &HeaderValue) -> bool {
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

    if let Some(pattern_scheme) = pattern_parts.scheme {
        if !pattern_scheme.eq_ignore_ascii_case(origin_parts.scheme) {
            return false;
        }
    }
    if let Some(pattern_port) = pattern_parts.port {
        if Some(pattern_port) != origin_parts.port {
            return false;
        }
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

#[cfg(test)]
mod tests {
    use salvo_core::http::header::HeaderValue;

    use super::{AllowOrigin, Any, OriginInner, WILDCARD, wildcard_origin_matches};

    #[test]
    fn test_from_any() {
        let origin: AllowOrigin = Any.into();
        assert!(matches!(origin.0, OriginInner::Exact(ref v) if v == "*"));
    }

    #[test]
    fn test_from_list() {
        let origin: AllowOrigin = vec!["https://example.com"].into();
        assert!(
            matches!(origin.0, OriginInner::List(ref v) if v == &vec![HeaderValue::from_static("https://example.com")])
        );
    }

    #[test]
    #[should_panic]
    fn test_list_with_wildcard() {
        let _: AllowOrigin = vec![WILDCARD.clone()].into();
    }

    #[test]
    fn test_wildcard_origin_matches_subdomain() {
        let pattern = HeaderValue::from_static("https://*.example.com");
        let origin = HeaderValue::from_static("https://api.example.com");
        assert!(wildcard_origin_matches(&pattern, &origin));
    }

    #[test]
    fn test_wildcard_origin_matches_nested_subdomain() {
        let pattern = HeaderValue::from_static("*.example.com");
        let origin = HeaderValue::from_static("https://foo.api.example.com");
        assert!(wildcard_origin_matches(&pattern, &origin));
    }

    #[test]
    fn test_wildcard_origin_does_not_match_root_domain() {
        let pattern = HeaderValue::from_static("https://*.example.com");
        let origin = HeaderValue::from_static("https://example.com");
        assert!(!wildcard_origin_matches(&pattern, &origin));
    }

    #[test]
    fn test_wildcard_origin_requires_scheme_when_configured() {
        let pattern = HeaderValue::from_static("https://*.example.com");
        let origin = HeaderValue::from_static("http://api.example.com");
        assert!(!wildcard_origin_matches(&pattern, &origin));
    }

    #[test]
    fn test_wildcard_origin_requires_port_when_configured() {
        let pattern = HeaderValue::from_static("https://*.example.com:8443");
        let matching_origin = HeaderValue::from_static("https://api.example.com:8443");
        let other_origin = HeaderValue::from_static("https://api.example.com:9443");
        assert!(wildcard_origin_matches(&pattern, &matching_origin));
        assert!(!wildcard_origin_matches(&pattern, &other_origin));
    }
}
