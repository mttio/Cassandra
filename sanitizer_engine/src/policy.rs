use std::{fmt::Debug, ops::Range, time::Duration};

use nutype::nutype;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::{
    errors::RuleError,
    log::LogLevel,
    rules::{CssUrl, JsReplace, RuleWithReplace, RuleWithValue, Verify},
    url::host_matches,
};

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyHost(pub Host);

impl<'de> Deserialize<'de> for PolicyHost {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        Host::parse(&string)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

impl Serialize for PolicyHost {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct Policy {
    pub html: HtmlPolicy,
    pub urls: UrlsPolicy,
    pub resources: ResourcesPolicy,
    pub connections: ConnectionsPolicy,
}

pub fn sanitize_attribute(s: &str) -> String {
    s.replace([' ', '\n', '\r', '\t', '\x0C', '/', '>', '='], "")
}

/// Newtype to remove invalid characters in HTML url attributes.
/// Removes the attribute if empty.
#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct IdnRule(String);

impl Verify for IdnRule {
    type Item<'a> = &'a Url;

    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(_this: Option<&Self>, value: &Self::Item<'_>) -> Option<crate::errors::RuleError> {
        crate::url::check_domain(value).map(RuleError::Idn)
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = ""
)]
pub struct EventHandlerRule(String);

impl Verify for EventHandlerRule {
    type Item<'a> = &'a lol_html::html_content::Attribute<'a>;

    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(_this: Option<&Self>, value: &Self::Item<'_>) -> Option<RuleError> {
        let name = value.name().to_lowercase();

        if name.starts_with("on") {
            let location = value
                .value_source_location()
                .or_else(|| value.name_source_location())
                .map(|x| x.bytes());

            Some(RuleError::EventHandler(name, location))
        } else {
            None
        }
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousUriRule(String);

impl Verify for DangerousUriRule {
    type Item<'a> = &'a lol_html::html_content::Attribute<'a>;

    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(_this: Option<&Self>, value: &Self::Item<'_>) -> Option<RuleError> {
        let attr_value = value.value().trim().to_lowercase();

        if attr_value.starts_with("javascript:") || attr_value.starts_with("data:") {
            let location = value.value_source_location().map(|x| x.bytes());

            Some(RuleError::DangerousUri(attr_value, location))
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    /// Action to perform when an event handler is encountered
    pub event_handlers: RuleWithReplace<EventHandlerRule>,
    /// Action to perform when a dangerous domain is encountered
    pub dangerous_domain: RuleWithReplace<DangerousDomain2>,
    /// Action to perform when a dangerous URI (javascript:, data:) is encountered
    pub dangerous_uris: RuleWithReplace<DangerousUriRule>,
}

impl Default for HtmlPolicy {
    fn default() -> Self {
        Self {
            allow_scripts: vec![],
            allow_origins: ["trusted.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            event_handlers: RuleWithReplace::with_default(LogLevel::Info),
            dangerous_domain: RuleWithReplace::with_default(LogLevel::Error),
            dangerous_uris: RuleWithReplace::with_default(LogLevel::Info),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct UrlsPolicy {
    /// List of domains considered dangerous
    /// Ignores prefix labels (e.g. `youtube.com` matches `www.youtube.com`)
    pub dangerous_domains: Vec<PolicyHost>,
    /// Action to perform when a non-latin url is encountered
    pub idn: RuleWithReplace<IdnRule>,
}

impl Default for UrlsPolicy {
    fn default() -> Self {
        Self {
            dangerous_domains: ["malicious-domain.com", "evil.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            idn: RuleWithReplace::with_default(LogLevel::Warn),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: RuleWithValue<usize>,
    pub max_bytes: RuleWithValue<usize>,
    pub max_requests: RuleWithValue<usize>,
    pub mismatched_mime: LogLevel,
    pub unknown_resource: LogLevel,
    pub pdf_active_content: LogLevel,
    pub dangerous_js: RuleWithReplace<JsReplace>,
    pub dangerous_css: RuleWithReplace<CssUrl>,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: RuleWithValue::new(1, LogLevel::Error),
            max_bytes: RuleWithValue::new(1024 * 1024, LogLevel::Error),
            max_requests: RuleWithValue::new(5, LogLevel::Error),
            mismatched_mime: LogLevel::Error,
            unknown_resource: LogLevel::Error,
            pdf_active_content: LogLevel::Error,
            dangerous_js: RuleWithReplace::with_default(LogLevel::Error),
            dangerous_css: RuleWithReplace::with_default(LogLevel::Warn),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct DangerousDomain;

impl Verify for DangerousDomain {
    type Item<'a> = (&'a Host, &'a [PolicyHost]);

    type Output = ();

    fn to_output(&self) -> Self::Output {}

    fn verify(_: Option<&Self>, &(host, domains): &Self::Item<'_>) -> Option<RuleError> {
        if domains.iter().any(|x| host_matches(host, &x.0)) {
            Some(RuleError::DangerousDomain(host.to_owned(), None))
        } else {
            None
        }
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousDomain2(String);

impl Verify for DangerousDomain2 {
    type Item<'a> = (&'a Host, &'a [PolicyHost], Range<usize>);

    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(
        _: Option<&Self>,
        &(host, domains, ref location): &Self::Item<'_>,
    ) -> Option<RuleError> {
        if domains.iter().any(|x| host_matches(host, &x.0)) {
            Some(RuleError::DangerousDomain(
                host.to_owned(),
                Some(location.clone()),
            ))
        } else {
            None
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ConnectionsPolicy {
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub overall_timeout: Duration,
    /// Maximum number of redirects for a single connection
    pub max_redirects: RuleWithValue<usize>,
    /// User agent to include in every request
    pub user_agent: String,
    /// Action to perform when connecting to a dangerous domain
    pub dangerous_domain: RuleWithReplace<DangerousDomain>,
}

impl Default for ConnectionsPolicy {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(3),
            overall_timeout: Duration::from_secs(15),
            max_redirects: RuleWithValue::new(2, LogLevel::Error),
            user_agent: "CoolBot/0.0 (https://example.org/coolbot/; coolbot@example.org) generic-library/0.0".to_owned(),
            dangerous_domain: RuleWithReplace::keep(LogLevel::Error),
        }
    }
}
