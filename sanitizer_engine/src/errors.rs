use std::{fmt::Display, ops::Range, path::PathBuf};

use colored::Colorize;
use hickory_resolver::net::NetError;
use lol_html::errors::RewritingError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::{Host, Url};

fn format_option_range(range: &Option<Range<usize>>) -> String {
    match range {
        Some(x) => format!(" {}", format_range(x)),
        None => "".to_owned(),
    }
}

fn format_range(range: &Range<usize>) -> String {
    format!(
        "@ {}..{}",
        range.start.to_string().bright_magenta(),
        range.end.to_string().bright_magenta()
    )
}

trait Pretty {
    fn pretty(&self) -> colored::ColoredString;
}

impl<T: ToString> Pretty for T {
    fn pretty(&self) -> colored::ColoredString {
        self.to_string().bright_cyan()
    }
}

#[derive(Debug, Clone, Error, Deserialize, Serialize, PartialEq)]
#[error(transparent)]
#[serde(tag = "type")]
pub enum RuleError {
    #[error("too many redirects (max = {})", max.pretty())]
    #[serde(rename = "too_many_redirects")]
    TooManyRedirects { max: usize },
    #[error("blocked script {} (source = {})", format_range(offset), original.pretty())]
    #[serde(rename = "allow_scripts")]
    BlockedScript {
        original: String,
        offset: Range<usize>,
    },
    #[error("connecting to dangerous domain ({})", original.pretty())]
    #[serde(rename = "dangerous_domain_connection")]
    DangerousDomainConnection { original: Host },
    #[error(
        "blocked origin (tag = {}, source = {}) {}",
        tag.pretty(),
        original.pretty(),
        format_range(offset)
    )]
    #[serde(rename = "allow_origin")]
    BlockedOrigin {
        tag: String,
        original: String,
        offset: Range<usize>,
    },
    #[error(
        "blocked meta refresh (content = {}) {}",
        original.pretty(),
        format_range(offset),
    )]
    #[serde(rename = "meta_refresh")]
    BlockedMetaRefresh {
        original: String,
        offset: Range<usize>,
    },
    #[error(
        "MIME mismatch (expected = {}, actual = {})",
        expected.as_deref().unwrap_or("<none>"),
        actual.as_deref().unwrap_or("<none>"),
    )]
    #[serde(rename = "mime_mismatch")]
    MimeMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("response body exceeds maximum size ({} bytes)", max.pretty())]
    #[serde(rename = "content_too_long")]
    ContentTooLong { max: usize },
    #[error("Sub-resource crawl limit reached: max_requests = {}", max.pretty())]
    #[serde(rename = "too_many_subresources")]
    MaxSubresources { max: usize },
    #[error("Sub-resource crawl depth limit reached: max_requests = {}", max.pretty())]
    #[serde(rename = "subresources_too_deep")]
    MaxSubresourceDepth { max: usize },
    #[error("custom XML entity declaration detected (potential XML bomb)")]
    #[serde(rename = "xml_entity_declaration")]
    XmlEntityDeclaration,
    #[error("embedded active content ({original}) detected")]
    #[serde(rename = "active_content")]
    ActiveContent { original: String },
    #[error("Unknown resource type {mime:?}, {path}")]
    UnknownResourceType { mime: Option<String>, path: String },
    #[error(
        "{inner}{}",
        match replacement {
            Some(x) => format!(" {} `{}`", "->".bright_yellow(), x.pretty()),
            None => "".to_owned(),
        },
    )]
    #[serde(untagged)]
    Replace {
        #[serde(flatten)]
        inner: RuleReplaceError,
        replacement: Option<String>,
    },
}

#[derive(Debug, Clone, Error, Deserialize, Serialize, PartialEq)]
#[error(transparent)]
#[serde(tag = "type")]
pub enum RuleReplaceError {
    #[error("event handler{}: `{}`", format_option_range(offset), original.pretty())]
    #[serde(rename = "event_handlers")]
    EventHandler {
        original: String,
        offset: Option<Range<usize>>,
    },
    #[error("dangerous domain {}: `{}`", format_range(offset), original.pretty())]
    #[serde(rename = "dangerous_domain")]
    DangerousDomain {
        original: Host,
        offset: Range<usize>,
    },
    #[error("dangerous URI{}: `{}`", format_option_range(offset), original.pretty())]
    #[serde(rename = "dangerous_uris")]
    DangerousUri {
        original: String,
        offset: Option<Range<usize>>,
    },
    #[error("IDN url: `{}`", original.pretty())]
    #[serde(rename = "idn")]
    Idn { original: String },
    #[error("Dangerous construct detected in JS: `{}`", original.pretty())]
    #[serde(rename = "dangerous_js")]
    DangerousJsConstruct { original: String },
    #[error(
        "Dangerous construct detected in CSS @ {}: `{}`",
        offset.to_string().bright_magenta(),
        original.pretty(),
    )]
    #[serde(rename = "dangerous_css")]
    DangerousCssConstruct { original: String, offset: usize },
}

/// An error that the sanitizer can produce
#[derive(Debug, Error)]
#[error(transparent)]
pub enum SanitizerError {
    #[error("Failed to create HTTP client: {0}")]
    CreateHttpClient(Box<dyn std::error::Error + Send + Sync>),
    #[error("DNS resolution timed out for host: {0}")]
    Timeout(String),
    #[error("DNS lookup failed for host {0}: {1}")]
    DnsLookup(String, NetError),
    #[error("Only HTTPS URLs are permitted")]
    NonHttpsUrl,
    #[error("Server returned error status: {0}")]
    ServerStatus(reqwest::StatusCode),
    #[error("Failed to fetch {} {}: {}", if *.2 { "sub-resource" } else { "url" }, .0, .1)]
    UrlFetch(Url, Box<Self>, bool),
    #[error("Rewriting error: {0}")]
    Rewriting(#[source] RewritingError),
    #[error("Failed to open file: {0} ({1})")]
    OpenFile(PathBuf, std::io::Error),
    #[error("Failed to create file: {0} ({1})")]
    CreateFile(PathBuf, std::io::Error),
    #[error("Failed to read file: {0} ({1})")]
    ReadFile(PathBuf, std::io::Error),
    #[error("Failed to write to file: {0} ({1})")]
    WriteFile(PathBuf, std::io::Error),
    #[error("Error while streaming body: {0}")]
    Streaming(reqwest::Error),
    #[error("Request failed for URL {0}: {1}")]
    Request(Url, reqwest::Error),
    #[error("{0}")]
    Rule(#[source] RuleError),
    Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// A message that the sanitizer can produce
#[derive(Debug)]
pub enum SanitizerMessage {
    Error(SanitizerError),
    CrawlingSubresource { depth: usize, url: Url },
}

impl Display for SanitizerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error(e) => write!(f, "{e}"),
            Self::CrawlingSubresource { depth, url } => {
                write!(
                    f,
                    "Crawling sub-resource (depth {}): {}",
                    depth,
                    url.to_string().bright_blue()
                )
            }
        }
    }
}

impl<T: Into<SanitizerError>> From<T> for SanitizerMessage {
    fn from(value: T) -> Self {
        Self::Error(value.into())
    }
}

impl From<RewritingError> for SanitizerError {
    fn from(value: RewritingError) -> Self {
        match value {
            RewritingError::ContentHandlerError(e) => {
                // Extract the error returned inside the `element!()` macro
                match e.downcast::<Self>() {
                    Ok(e) => *e,
                    Err(e) => Self::Other(e),
                }
            }
            RewritingError::MemoryLimitExceeded(e) => Self::Other(Box::new(e)),
            RewritingError::ParsingAmbiguity(e) => Self::Other(Box::new(e)),
        }
    }
}

impl From<RuleError> for SanitizerError {
    fn from(value: RuleError) -> Self {
        Self::Rule(value)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct SanitizationReport {
    pub input: String,
    pub actions: Vec<RuleError>,
}
