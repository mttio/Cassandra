use std::{fmt::Display, ops::Range, path::PathBuf};

use colored::Colorize;
use hickory_resolver::net::NetError;
use lol_html::errors::RewritingError;
use thiserror::Error;
use url::{Host, Url};
use serde::{Deserialize, Serialize};

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
    #[error("too many redirects (max = {})", .0.to_string().bright_cyan())]
    TooManyRedirects(usize),
    #[error("Only HTTPS URLs are permitted")]
    NonHttpsUrl,
    #[error("Server returned error status: {0}")]
    ServerStatus(reqwest::StatusCode),
    #[error("dangerous domain ({})", .0.to_string().bright_cyan())]
    DangerousDomain(Host),
    #[error(
        "dangerous domain ({}) @ {}..{}",
        .0.to_string().bright_cyan(),
        .1.start.to_string().bright_magenta(),
        .1.end.to_string().bright_magenta(),
    )]
    DangerousDomainInHtml(Host, Range<usize>),
    #[error(
        "event handler ({}){}",
        .0.bright_cyan(),
        match .1 {
            Some(x) => format!(" @ {}..{}", x.start.to_string().bright_magenta(), x.end.to_string().bright_magenta()),
            None => "".to_owned(),
        }        
    )]
    EventHandler(String, Option<Range<usize>>),
    #[error(
        "dangerous URI ({}){}",
        .0.bright_cyan(),
        match .1 {
            Some(x) => format!(" @ {}..{}", x.start.to_string().bright_magenta(), x.end.to_string().bright_magenta()),
            None => "".to_owned(),
        }
    )]
    DangerousUri(String, Option<Range<usize>>),
    #[error("IDN url ({})", .0)]
    Idn(String),
    #[error(
        "blocked script (source = {}) @ {}..{}",
        .0.bright_cyan(),
        .1.start.to_string().bright_magenta(),
        .1.end.to_string().bright_magenta(),
    )]
    BlockedScript(String, Range<usize>),
    #[error(
        "blocked origin (tag = {}, source = {}) @ {}..{}",
        .0.bright_cyan(),
        .1.bright_cyan(),
        .2.start.to_string().bright_magenta(),
        .2.end.to_string().bright_magenta(),
    )]
    BlockedOrigin(String, String, Range<usize>),
    #[error(
        "blocked meta refresh (content = {}) @ {}..{}",
        .0.bright_cyan(),
        .1.start.to_string().bright_magenta(),
        .1.end.to_string().bright_magenta(),
    )]
    BlockedMetaRefresh(String, Range<usize>),
    #[error(
        "response body exceeds maximum size ({} bytes)",
        .0.to_string().bright_cyan(),        
    )]
    ContentTooLong(usize),
    #[error(
        "MIME mismatch (expected = {}, actual = {})",
        .0.as_deref().unwrap_or("<none>"),
        .1.as_deref().unwrap_or("<none>"),
    )]
    MimeMismatch(Option<String>, Option<String>),
    #[error("Sub-resource crawl limit reached: max_requests = {}", .0)]
    MaxSubresources(usize),
    #[error("Sub-resource crawl depth limit reached: max_requests = {}", .0)]
    MaxSubresourceDepth(usize),
    #[error("Failed to fetch {} {}: {}", if *.2 { "sub-resource" } else { "url" }, .0, .1)]
    UrlFetch(Url, Box<Self>, bool),
    #[error("Unknown resource type")]
    UnknownResourceType,
    #[error("Rewriting error: {0}")]
    Rewriting(#[source] RewritingError),
    #[error("custom XML entity declaration detected (potential XML bomb)")]
    XmlEntityDeclaration,
    #[error("embedded active content ({0}) detected")]
    ActiveContent(String),
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
    #[error("Dangerous construct `{0}` detected in JS")]
    DangerousJsConstruct(String),
    #[error(
        "Dangerous construct detected in CSS: `{}`{} @ {}",
        from.bright_yellow(),
        match .to {
            Some(x) => format!(" {} `{}`", "->".bright_cyan(), x.bright_yellow()),
            None => "".to_owned(),
        },
        .offset.to_string().bright_magenta(),
    )]
    DangerousCssConstruct {
        from: String,
        to: Option<String>,
        offset: usize,
    },
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
                    Err(e) => Self::Other(e)
                }
            }
            RewritingError::MemoryLimitExceeded(e) => Self::Other(Box::new(e)),
            RewritingError::ParsingAmbiguity(e) => Self::Other(Box::new(e)),
        }
    }
}

impl SanitizerError {
    pub fn to_event(&self) -> Option<SanitizationEvent> {
        match self {
            Self::DangerousCssConstruct { from, to, offset } => Some(SanitizationEvent {
                rule: "dangerous_css".to_owned(),
                tag: "style".to_owned(),
                offset: Some(*offset..*offset + from.len()),
                original: from.clone(),
                replacement: to.clone(),
            }),
            Self::BlockedScript(source, location) => Some(SanitizationEvent {
                rule: "allow_scripts".to_owned(),
                tag: "script".to_owned(),
                offset: Some(location.clone()),
                original: source.clone(),
                replacement: None,
            }),
            Self::BlockedOrigin(tag, source, location) => Some(SanitizationEvent {
                rule: "allow_origins".to_owned(),
                tag: tag.clone(),
                offset: Some(location.clone()),
                original: source.clone(),
                replacement: None,
            }),
            Self::BlockedMetaRefresh(content, location) => Some(SanitizationEvent {
                rule: "meta_refresh".to_owned(),
                tag: "meta".to_owned(),
                offset: Some(location.clone()),
                original: content.clone(),
                replacement: None,
            }),
            Self::EventHandler(name, location) => Some(SanitizationEvent {
                rule: "event_handlers".to_owned(),
                tag: "attribute".to_owned(),
                offset: location.clone(),
                original: name.clone(),
                replacement: None,
            }),
            Self::DangerousUri(value, location) => Some(SanitizationEvent {
                rule: "dangerous_uris".to_owned(),
                tag: "attribute".to_owned(),
                offset: location.clone(),
                original: value.clone(),
                replacement: None,
            }),
            Self::Idn(original) => Some(SanitizationEvent {
                rule: "idn".to_owned(),
                tag: "url".to_owned(),
                offset: None,
                original: original.clone(),
                replacement: None,
            }),
            Self::DangerousDomain(host) => Some(SanitizationEvent {
                rule: "dangerous_domain".to_owned(),
                tag: "domain".to_owned(),
                offset: None,
                original: host.to_string(),
                replacement: None,
            }),
            Self::DangerousDomainInHtml(host, location) => Some(SanitizationEvent {
                rule: "dangerous_domain".to_owned(),
                tag: "domain".to_owned(),
                offset: Some(location.clone()),
                original: host.to_string(),
                replacement: None,
            }),
            Self::ActiveContent(content) => Some(SanitizationEvent {
                rule: "active_content".to_owned(),
                tag: "pdf".to_owned(),
                offset: None,
                original: content.clone(),
                replacement: None,
            }),
            Self::XmlEntityDeclaration => Some(SanitizationEvent {
                rule: "xml_entity_declaration".to_owned(),
                tag: "xml".to_owned(),
                offset: None,
                original: "<!ENTITY".to_owned(),
                replacement: None,
            }),
            Self::MimeMismatch(expected, actual) => Some(SanitizationEvent {
                rule: "mime_mismatch".to_owned(),
                tag: "header".to_owned(),
                offset: None,
                original: format!("expected: {:?}, actual: {:?}", expected, actual),
                replacement: None,
            }),
            Self::ContentTooLong(max_size) => Some(SanitizationEvent {
                rule: "content_too_long".to_owned(),
                tag: "resource".to_owned(),
                offset: None,
                original: format!("exceeds {} bytes", max_size),
                replacement: None,
            }),
            Self::TooManyRedirects(max_redirects) => Some(SanitizationEvent {
                rule: "too_many_redirects".to_owned(),
                tag: "connection".to_owned(),
                offset: None,
                original: format!("exceeds {} redirects", max_redirects),
                replacement: None,
            }),
            _ => None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SanitizationEvent {
    pub rule: String,
    pub tag: String,
    pub offset: Option<Range<usize>>,
    pub original: String,
    pub replacement: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SanitizationReport {
    pub input: String,
    pub actions: Vec<SanitizationEvent>,
}
