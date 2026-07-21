use std::{fmt::Debug, str::FromStr, time::Duration};

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

impl FromStr for PolicyHost {
    type Err = url::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Host::parse(s).map(Self)
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

/// Rules for handling HTML files
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct HtmlPolicy {
    /// List of allowed script sources.
    pub allow_scripts: Vec<PolicyHost>,
    /// List of allowed origins for content tags
    pub allow_origins: Vec<PolicyHost>,
    /// Handles event handler attributes
    pub event_handlers: ReplaceRule<rules::EventHandlers>,
    /// Handles custom xml entities (potential XML bomb)
    pub xml_entities: ReplaceRule<rules::XmlEntities>,
    /// Handles `<meta http-equiv="Refresh">` tags
    pub meta_refresh: ReplaceRule<rules::MetaRefresh>,
    /// Handles dangerous (not allowed) scripts in `<script>` tags
    pub dangerous_scripts: ReplaceRule<rules::DangerousScripts>,
    /// Handles dangerous origins in `<iframe>` and `<object>` tags
    pub dangerous_origins: ReplaceRule<rules::DangerousOrigins>,
    /// Handles dangerous domains (see `urls.dangerous_domains`)
    pub dangerous_domain: ReplaceRule<rules::DangerousDomain2>,
    /// Handles dangerous URIs (`javascript:...`, `data:...`) in tag attributes
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
            xml_entities: ReplaceRule::with_default(LogLevel::Error),
            meta_refresh: ReplaceRule::with_default(LogLevel::Warn),
            dangerous_scripts: ReplaceRule::with_default(LogLevel::Error),
            dangerous_origins: ReplaceRule::with_default(LogLevel::Error),
            dangerous_domain: ReplaceRule::with_default(LogLevel::Error),
            dangerous_uris: ReplaceRule::with_default(LogLevel::Info),
        }
    }
}

/// Rules for handling URLs
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct UrlsPolicy {
    /// List of domains considered **dangerous**
    /// Ignores prefix labels (e.g. `wikipedia.org` matches `www.wikipedia.org`)
    pub dangerous_domains: Vec<PolicyHost>,
    /// Handles IDN urls detected in files
    pub idn: ReplaceRule<rules::Idn>,
    /// Handles connecting to IDN urls
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

/// Rule for handling resource files
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ResourcesPolicy {
    /// Whether to fetch subresources references in processed files
    pub fetch_sub_resources: bool,
    /// Maximum subresource depth
    pub max_depth: RuleWithValue<rules::MaxSubresourceDepth>,
    /// Maximum subresource amount
    pub max_requests: RuleWithValue<rules::MaxSubresources>,
    /// Maximum resource length
    pub max_bytes: RuleWithValue<rules::MaxBytes>,
    /// Handles mismatches MIME types
    pub mismatched_mime: LogLevel,
    /// Handles unknown resource types
    pub unknown_resource: LogLevel,
    /// Handles active content in PDF files
    pub pdf_active_content: LogLevel,
    /// Handles dangerous constructs in JS files
    pub dangerous_js: ReplaceRule<rules::JsReplace>,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: RuleWithValue::with_default(LogLevel::Error),
            max_requests: RuleWithValue::with_default(LogLevel::Error),
            max_bytes: RuleWithValue::with_default(LogLevel::Error),
            mismatched_mime: LogLevel::Error,
            unknown_resource: LogLevel::Error,
            pdf_active_content: LogLevel::Error,
            dangerous_js: ReplaceRule::with_default(LogLevel::Error),
        }
    }
}

/// Rules for handling http requests
#[derive(Debug, Deserialize, Serialize, PartialEq)]
#[serde(default)]
pub struct ConnectionsPolicy {
    /// Maximum timeout for the connection phase of a request
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    /// Maximum timeout for a request (including reading the body)
    #[serde(with = "humantime_serde")]
    pub overall_timeout: Duration,
    /// Maximum number of redirects for a single request
    pub max_redirects: RuleWithValue<rules::MaxRedirects>,
    /// User agent to include in every request
    pub user_agent: String,
    /// Handles connections to dangerous domain (see `urls.dangerous_domains`)
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
