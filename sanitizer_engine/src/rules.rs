use std::{ops::Deref, ops::Range};

use nutype::nutype;
use serde::{Deserialize, Serialize};
use url::{Host, Url};

use crate::{
    errors::{RuleError, RuleReplaceError},
    log::{Log, LogLevel},
    policy::PolicyHost,
    url::host_matches,
};

#[nutype(
    derive(Debug, AsRef, Deref, Serialize, Deserialize, Default, PartialEq),
    default = "/* Blocked by Web Sanitizer: dangerous keywords found */"
)]
pub(crate) struct JsReplace(String);

impl Verify for JsReplace {
    type Input<'a> = &'a str;
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError> {
        crate::resources::javascript::sanitize(value)
            .err()
            .map(|x| RuleReplaceError::DangerousJsConstruct { original: x })
    }
}

/// A generic rule where a `replacement` value can be specified
///
/// Can be specified in the config in different ways:
/// ```toml
/// rule = "level"                          # only log level, replaces with default value
/// rule = true                             # same as "warn"
/// rule = false                            # doesn't replace, log level is "warn"
/// rule = value                            # replacement value, log level is "warn"
/// rule = { replace = ..., level = ... }   # both replacement value and log level
/// rule = { replace = true, level = ... }  # replaces with default value
/// rule = { replace = false, level = ... } # doesn't replace
/// ```
#[derive(Clone, Copy, Debug, Serialize, PartialEq)]
pub struct ReplaceRule<R> {
    /// What to replace the undesired value with. If `None`, it is not replaced
    replace: Option<R>,
    /// The log level associated with this rule. If `Error`, the sanitization should stop
    level: LogLevel,
}

pub trait Verify {
    /// The type of the value to be verified
    type Input<'a>
    where
        Self: 'a;
    /// The type of the replacement value
    type Output: ToString;

    /// Verifies that the specified value is allowed.
    /// Returns `Some(...)` if not allowed.
    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError>;

    /// Convert `self` to the replacement value
    fn to_output(&self) -> Self::Output;
}

pub trait Verify2 {
    type Input<'a>
    where
        Self: 'a;

    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError>;
}

#[nutype(
    derive(Debug, Deref, Serialize, Deserialize, Default, PartialEq),
    default = ""
)]
pub struct CssUrl(String);

impl Verify for CssUrl {
    type Input<'a> = (&'a str, usize);
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.deref().to_owned()
    }

    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError> {
        let &(url, offset) = value;
        if url.starts_with("data:") || url.starts_with("javascript:") {
            Some(RuleReplaceError::DangerousCssConstruct {
                original: url.to_owned(),
                offset,
            })
        } else {
            None
        }
    }
}

impl<R: Default> ReplaceRule<R> {
    pub fn new(replace: impl Into<R>, level: LogLevel) -> Self {
        Self {
            replace: Some(replace.into()),
            level,
        }
    }

    pub fn keep(level: LogLevel) -> Self {
        Self {
            replace: None,
            level,
        }
    }

    pub fn with_default(level: LogLevel) -> Self {
        Self::new(R::default(), level)
    }
}

impl<R: Default + Verify> ReplaceRule<R> {
    pub fn check(
        &self,
        value: R::Input<'_>,
        logger: &impl Log,
    ) -> Result<Option<R::Output>, RuleError> {
        match R::verify(&value) {
            None => Ok(None),
            Some(e) => {
                let e = RuleError::Replace {
                    inner: e,
                    replacement: self.replace.as_ref().map(|x| x.to_output().to_string()),
                };
                self.level
                    .handle(logger, e)
                    .map(|_| self.replace.as_ref().map(R::to_output))
            }
        }
    }
}

impl<'de, R: Default + Deserialize<'de>> Deserialize<'de> for ReplaceRule<R> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<R> {
            Level(LogLevel),
            Bool(bool),
            Value { replace: R },
            ValueLevel { replace: R, level: LogLevel },
            BoolLevel { replace: bool, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Level(level) => Self {
                replace: Some(R::default()),
                level,
            },
            Inner::Bool(replace) => Self {
                replace: replace.then(R::default),
                level: LogLevel::Warn,
            },
            Inner::Value { replace } => Self {
                replace,
                level: LogLevel::Warn,
            },
            Inner::ValueLevel { replace, level } => Self { replace, level },
            Inner::BoolLevel { replace, level } => Self {
                replace: replace.then(R::default),
                level,
            },
        })
    }
}

#[derive(Copy, Clone, Debug, Serialize, PartialEq)]
pub struct RuleWithValue<T: 'static> {
    pub value: T,
    pub level: LogLevel,
}

impl<T> RuleWithValue<T> {
    pub fn new(value: T, level: LogLevel) -> Self {
        Self { value, level }
    }
}

impl<T: Default> RuleWithValue<T> {
    pub fn with_default(level: LogLevel) -> Self {
        Self::new(T::default(), level)
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 1
)]
pub struct MaxSubresourceDepth(usize);

impl Verify2 for MaxSubresourceDepth {
    type Input<'a> = usize;

    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError> {
        if value > self.as_ref() {
            Some(RuleError::MaxSubresourceDepth {
                max: *self.as_ref(),
            })
        } else {
            None
        }
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 5
)]
pub struct MaxSubresources(usize);

impl Verify2 for MaxSubresources {
    type Input<'a> = usize;

    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError> {
        // Log only the first time we hit the limit
        if *value == self.as_ref() + 1 {
            Some(RuleError::MaxSubresources {
                max: *self.as_ref(),
            })
        } else {
            None
        }
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 1024 * 1024
)]
pub struct MaxBytes(usize);

impl Verify2 for MaxBytes {
    type Input<'a> = usize;

    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError> {
        // Log only the first time we hit the limit
        if value > self.as_ref() {
            Some(RuleError::ContentTooLong {
                max: *self.as_ref(),
            })
        } else {
            None
        }
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 2
)]
pub struct MaxRedirects(usize);

impl Verify2 for MaxRedirects {
    type Input<'a> = usize;

    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError> {
        // Log only the first time we hit the limit
        if value > self.as_ref() {
            Some(RuleError::ContentTooLong {
                max: *self.as_ref(),
            })
        } else {
            None
        }
    }
}

impl<R: Default + Verify2> RuleWithValue<R> {
    pub fn check(&self, value: R::Input<'_>, logger: &impl Log) -> Result<bool, RuleError> {
        match R::verify(&self.value, &value) {
            None => Ok(true),
            Some(e) => self.level.handle(logger, e).map(|_| false),
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for RuleWithValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            Value(T),
            Tuple(T, LogLevel),
            Table { value: T, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Value(value) => Self {
                value,
                level: LogLevel::Error,
            },
            Inner::Tuple(value, level) => Self { value, level },
            Inner::Table { value, level } => Self { value, level },
        })
    }
}

/// Remove invalid characters in HTML url attributes.
pub fn sanitize_attribute(s: &str) -> String {
    s.replace([' ', '\n', '\r', '\t', '\x0C', '/', '>', '='], "")
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct Idn(String);

impl Verify for Idn {
    type Input<'a> = &'a Url;
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError> {
        crate::url::check_domain(value).map(|x| RuleReplaceError::Idn {
            original: x.to_string(),
        })
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = ""
)]
pub struct EventHandlers(String);

impl Verify for EventHandlers {
    type Input<'a> = &'a lol_html::html_content::Attribute<'a>;
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError> {
        let name = value.name().to_lowercase();

        if name.starts_with("on") {
            let location = value
                .value_source_location()
                .or_else(|| value.name_source_location())
                .map(|x| x.bytes());

            Some(RuleReplaceError::EventHandler {
                original: name,
                offset: location,
            })
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
pub struct DangerousUris(String);

impl Verify for DangerousUris {
    type Input<'a> = &'a lol_html::html_content::Attribute<'a>;
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(value: &Self::Input<'_>) -> Option<RuleReplaceError> {
        let attr_value = value.value().trim().to_lowercase();

        if attr_value.starts_with("javascript:") || attr_value.starts_with("data:") {
            let location = value.value_source_location().map(|x| x.bytes());

            Some(RuleReplaceError::DangerousUri {
                original: attr_value,
                offset: location,
            })
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct DangerousDomain;

impl Verify2 for DangerousDomain {
    type Input<'a> = (&'a Host, &'a [PolicyHost]);

    fn verify(&self, &(host, domains): &Self::Input<'_>) -> Option<RuleError> {
        if domains.iter().any(|x| host_matches(host, &x.0)) {
            Some(RuleError::DangerousDomainConnection {
                original: host.to_owned(),
            })
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
    type Input<'a> = (&'a Host, &'a [PolicyHost], Range<usize>);
    type Output = String;

    fn to_output(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn verify(&(host, domains, ref location): &Self::Input<'_>) -> Option<RuleReplaceError> {
        if domains.iter().any(|x| host_matches(host, &x.0)) {
            Some(RuleReplaceError::DangerousDomain {
                original: host.to_owned(),
                offset: location.clone(),
            })
        } else {
            None
        }
    }
}
