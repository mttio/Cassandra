use std::{error::Error, time::Duration};

use serde::Deserialize;
use url::Host;

use crate::sanitizer_engine::errors::warn;

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    Allow,
    Replace,
    Warn,
    WarnAndReplace,
    Deny,
}

impl PolicyAction {
    pub fn handle_error<E: Into<Box<dyn Error>>>(self, error: E) -> Result<(), E> {
        match self {
            PolicyAction::Allow | PolicyAction::Replace => {}
            PolicyAction::Warn | PolicyAction::WarnAndReplace => {
                warn(error);
            }
            PolicyAction::Deny => {
                return Err(error);
            }
        }

        Ok(())
    }
}

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

#[derive(Debug, Default, Deserialize)]
pub struct Policy {
    pub html: HtmlPolicy,
    pub urls: UrlsPolicy,
    pub resources: ResourcesPolicy,
    pub connections: ConnectionsPolicy,
}

#[derive(Debug, Deserialize)]
pub struct HtmlPolicy {
    pub allow_scripts: Vec<String>,
    pub allow_origins: Vec<PolicyHost>,
    pub strip_event_handlers: bool,
    pub rewrite_dangerous_uris: bool,
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
            strip_event_handlers: true,
            rewrite_dangerous_uris: true,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UrlsPolicy {
    pub dangerous_domains: Vec<PolicyHost>,
    pub dangerous_domain_action: PolicyAction,
    pub idn_action: PolicyAction,
}

impl Default for UrlsPolicy {
    fn default() -> Self {
        Self {
            dangerous_domains: ["malicious-domain.com", "evil.com"]
                .into_iter()
                .flat_map(Host::parse)
                .map(PolicyHost)
                .collect(),
            dangerous_domain_action: PolicyAction::WarnAndReplace,
            idn_action: PolicyAction::Deny,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ResourcesPolicy {
    pub fetch_sub_resources: bool,
    pub max_depth: usize,
    pub max_bytes: usize,
    pub max_requests: usize,
}

impl Default for ResourcesPolicy {
    fn default() -> Self {
        Self {
            fetch_sub_resources: true,
            max_depth: 1,
            max_bytes: 1024 * 1024,
            max_requests: 5,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnectionsPolicy {
    #[serde(with = "humantime_serde")]
    pub connection_timeout: Duration,
    #[serde(with = "humantime_serde")]
    pub overall_timeout: Duration,
    pub max_redirects: Option<usize>,
    pub max_redirects_action: PolicyAction,
    pub user_agent: String,
}

impl Default for ConnectionsPolicy {
    fn default() -> Self {
        Self {
            connection_timeout: Duration::from_secs(3),
            overall_timeout: Duration::from_secs(15),
            max_redirects: Some(2),
            max_redirects_action: PolicyAction::Deny,
            user_agent: "CoolBot/0.0 (https://example.org/coolbot/; coolbot@example.org) generic-library/0.0".to_owned(),
        }
    }
}
