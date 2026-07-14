use std::{fmt::Debug, time::Duration};

use serde::{Deserialize, Serialize};
use url::Host;

use crate::{
    log::LogLevel,
    rules::{self, ReplaceRule, RuleWithValue},
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

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    /// Action to perform when an event handler is encountered
    pub event_handlers: ReplaceRule<rules::EventHandlers>,
    pub dangerous_scripts: ReplaceRule<rules::DangerousScripts>,
    pub dangerous_origins: ReplaceRule<rules::DangerousOrigins>,
    /// Rule for dangerous domains
    pub dangerous_domain: ReplaceRule<rules::DangerousDomain2>,
    /// Rule for dangerous URIs (javascript:, data:)
    pub dangerous_uris: ReplaceRule<rules::DangerousUris>,
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
            event_handlers: ReplaceRule::with_default(LogLevel::Info),
            dangerous_scripts: ReplaceRule::with_default(LogLevel::Error),
            dangerous_origins: ReplaceRule::with_default(LogLevel::Error),
            dangerous_domain: ReplaceRule::with_default(LogLevel::Error),
            dangerous_uris: ReplaceRule::with_default(LogLevel::Info),
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct UrlsPolicy {
    /// List of domains considered dangerous
    /// Ignores prefix labels (e.g. `youtube.com` matches `www.youtube.com`)
    pub dangerous_domains: Vec<PolicyHost>,
    /// Action to perform when a IDN url is found in a file
    pub idn: ReplaceRule<rules::Idn>,
    /// Action to perform when connecting to a IDN url
    pub idn_connection: LogLevel,
}

impl Default for UrlsPolicy {
    fn default() -> Self {
        Self {
            dangerous_domains: ["malicious-domain.com", "evil.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            idn: ReplaceRule::with_default(LogLevel::Warn),
            idn_connection: LogLevel::Warn,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: RuleWithValue<rules::MaxSubresourceDepth>,
    pub max_bytes: RuleWithValue<rules::MaxBytes>,
    pub max_requests: RuleWithValue<rules::MaxSubresources>,
    pub mismatched_mime: LogLevel,
    pub unknown_resource: LogLevel,
    pub pdf_active_content: LogLevel,
    pub dangerous_js: ReplaceRule<rules::JsReplace>,
    pub dangerous_css: ReplaceRule<rules::CssUrl>,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: RuleWithValue::with_default(LogLevel::Error),
            max_bytes: RuleWithValue::with_default(LogLevel::Error),
            max_requests: RuleWithValue::with_default(LogLevel::Error),
            mismatched_mime: LogLevel::Error,
            unknown_resource: LogLevel::Error,
            pdf_active_content: LogLevel::Error,
            dangerous_js: ReplaceRule::with_default(LogLevel::Error),
            dangerous_css: ReplaceRule::with_default(LogLevel::Warn),
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
    pub max_redirects: RuleWithValue<rules::MaxRedirects>,
    /// User agent to include in every request
    pub user_agent: String,
    /// Action to perform when connecting to a dangerous domain
    pub dangerous_domain: RuleWithValue<rules::DangerousDomain>,
}

impl Default for ConnectionsPolicy {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(3),
            overall_timeout: Duration::from_secs(15),
            max_redirects: RuleWithValue::with_default(LogLevel::Error),
            user_agent: format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            dangerous_domain: RuleWithValue::with_default(LogLevel::Error),
        }
    }
}
