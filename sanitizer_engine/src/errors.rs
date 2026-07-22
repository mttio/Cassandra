use std::{error::Error, fmt::Display, ops::Range, path::PathBuf};

use colored::{ColoredString, Colorize};
use hickory_resolver::net::NetError;
use lol_html::errors::RewritingError;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Host;

use crate::InputSource;

fn arrow() -> ColoredString {
    "->".yellow()
}

// https://gist.github.com/dginev/f6da5e94335d545e0a7b
fn truncate(mut input: String, maxsize: usize) -> (String, bool) {
    let mut utf8_maxsize = input.len();
    if utf8_maxsize >= maxsize {
        {
            let mut char_iter = input.char_indices();
            while utf8_maxsize >= maxsize {
                utf8_maxsize = match char_iter.next_back() {
                    Some((index, _)) => index,
                    _ => 0,
                };
            }
        } // Extra {} wrap to limit the immutable borrow of char_indices()
        input.truncate(utf8_maxsize);
        (input, true)
    } else {
        (input, false)
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
    fn pretty(&self) -> String;
}

impl<T: ToString> Pretty for T {
    fn pretty(&self) -> String {
        let (string, truncated) = truncate(self.to_string(), 128);

        if truncated {
            format!("{}{}", string.bright_cyan(), "...".bright_cyan().dimmed())
        } else {
            string.bright_cyan().to_string()
        }
    }
}

/// An error type containing all possible policy rule violations
#[derive(Debug, Clone, Error, Deserialize, Serialize, PartialEq)]
#[error(transparent)]
#[serde(tag = "type")]
pub enum RuleError {
    #[error("Too many redirects (max = {})", max.pretty())]
    #[serde(rename = "max_redirects")]
    TooManyRedirects { max: usize },
    #[error(
        "Connecting to IDN host: `{}` {} `{}`",
        original.pretty(),
        arrow(),
        converted.pretty(),
    )]
    #[serde(rename = "idn_connection")]
    IdnConnection { original: String, converted: String },
    #[error("Connecting to dangerous domain ({})", original.pretty())]
    #[serde(rename = "dangerous_connection")]
    DangerousDomainConnection { original: Host },
    #[error(
        "MIME mismatch (expected = {}, actual = {})",
        expected.as_deref().unwrap_or("<none>").pretty(),
        actual.as_deref().unwrap_or("<none>").pretty(),
    )]
    #[serde(rename = "mismatched_mime")]
    MimeMismatch {
        expected: Option<String>,
        actual: Option<String>,
    },
    #[error("Response body exceeds maximum size ({} bytes)", max.pretty())]
    #[serde(rename = "max_bytes")]
    ContentTooLong { max: usize },
    #[error("Sub-resource amount limit reached: max_requests = {}", max.pretty())]
    #[serde(rename = "max_subresources")]
    MaxSubresources { max: usize },
    #[error("Sub-resource depth limit reached: max_requests = {}", max.pretty())]
    #[serde(rename = "max_resource_depth")]
    MaxSubresourceDepth { max: usize },
    #[error("Pdf active content: `{}` {}", original.pretty(), format_range(location))]
    #[serde(rename = "pdf_active_content")]
    PdfActiveContent {
        original: String,
        location: Range<usize>,
    },
    #[error("Unknown resource type: `{}`", match mime {
        Some(x) => x.pretty(),
        None => "<none>".pretty(),
    })]
    #[serde(rename = "unknown_resource")]
    UnknownResourceType { mime: Option<String> },
    #[error(
        "{inner}: `{}`{} {}",
        original.pretty(),
        match replacement {
            Some(x) => format!(" {} `{}`", arrow(), x.pretty()),
            None => "".to_owned(),
        },
        format_range(location),
    )]
    #[serde(untagged)]
    Replace {
        #[serde(flatten)]
        inner: ReplacementKind,
        original: String,
        replacement: Option<String>,
        location: Range<usize>,
    },
}

#[derive(Debug, Clone, Error, Deserialize, Serialize, PartialEq)]
#[error(transparent)]
#[serde(tag = "type")]
pub enum ReplacementKind {
    #[error("Event handler")]
    #[serde(rename = "event_handlers")]
    EventHandler,
    #[error("Meta refresh")]
    #[serde(rename = "meta_refresh")]
    MetaRefresh,
    #[error("Dangerous script")]
    #[serde(rename = "dangerous_scripts")]
    DangerousScript,
    #[error("Dangerous origin")]
    #[serde(rename = "dangerous_origins")]
    DangerousOrigin,
    #[error("Dangerous domain")]
    #[serde(rename = "dangerous_domains")]
    DangerousDomain,
    #[error("Dangerous URI")]
    #[serde(rename = "dangerous_uris")]
    DangerousUri,
    #[error("Custom XML entity declaration (potential XML bomb)")]
    #[serde(rename = "xml_entities")]
    XmlEntityDeclaration,
    #[error("IDN host")]
    #[serde(rename = "idn")]
    Idn,
    #[error("Dangerous JS construct")]
    #[serde(rename = "dangerous_js")]
    DangerousJsConstruct,
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
    #[error("Http request failed: {0}")]
    Request(reqwest::Error),
    #[error("{0}")]
    Rule(#[source] RuleError),
    Other(#[from] Box<dyn std::error::Error + Send + Sync + 'static>),
}

/// A message that the sanitizer can produce
#[derive(Debug)]
pub enum SanitizerMessage {
    Error(SanitizerError),
    CrawlingSubresource {
        depth: usize,
        remote: InputSource,
        local: String,
    },
    ResourceCompleted,
}

impl Display for SanitizerMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error(e) => write!(f, "{e}"),
            Self::CrawlingSubresource {
                depth,
                remote,
                local,
            } => {
                write!(
                    f,
                    "Crawling sub-resource (depth {}): {} {} {}",
                    depth.pretty(),
                    match remote {
                        InputSource::File(remote) => remote.to_string_lossy().bright_cyan(),
                        InputSource::Url(remote) => remote.to_string().bright_blue(),
                    },
                    arrow(),
                    local.bright_cyan(),
                )
            }
            SanitizerMessage::ResourceCompleted => write!(f, "Resource completed!"),
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
                match e.downcast::<RuleError>() {
                    Ok(e) => Self::Rule(*e),
                    Err(e) => Self::Other(e),
                }
            }
            RewritingError::MemoryLimitExceeded(e) => Self::Other(Box::new(e)),
            RewritingError::ParsingAmbiguity(e) => Self::Other(Box::new(e)),
        }
    }
}

impl From<reqwest::Error> for SanitizerError {
    fn from(value: reqwest::Error) -> Self {
        match value.source().and_then(|x| x.downcast_ref::<RuleError>()) {
            Some(x) => Self::Rule(x.clone()),
            None => Self::Request(value),
        }
    }
}

impl From<RuleError> for SanitizerError {
    fn from(value: RuleError) -> Self {
        Self::Rule(value)
    }
}
