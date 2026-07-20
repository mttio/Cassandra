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

impl Replaceable for JsReplace {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousJsConstruct { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
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

/// A trait used by rules to describe replacement inside files and error conversion
pub trait Replaceable {
    /// The type of value to convert to the corresponding error
    type Input;
    /// The type of the replacement value
    type Output: ToString;

    /// Converts the provided value to a `RuleReplaceError`
    fn to_error(value: Self::Input) -> RuleReplaceError;

    /// Convert `self` to the replacement value
    fn to_replacement(&self) -> Self::Output;
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

impl Replaceable for CssUrl {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousCssConstruct { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.deref().to_owned()
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

    pub fn forbid() -> Self {
        Self::keep(LogLevel::Error)
    }

    pub fn with_default(level: LogLevel) -> Self {
        Self::new(R::default(), level)
    }
}

impl<R: Default + Replaceable> ReplaceRule<R> {
    pub fn handle(
        &self,
        value: R::Input,
        offset: Range<usize>,
        logger: &impl Log,
    ) -> Result<Option<R::Output>, RuleError> {
        let e = R::to_error(value);

        if self.level == LogLevel::Error {
            Err(RuleError::Replace {
                inner: e,
                replacement: None,
                offset,
            })
        } else {
            let replacement = self.replace.as_ref().map(R::to_replacement);
            logger.log(
                self.level,
                RuleError::Replace {
                    inner: e,
                    replacement: replacement.as_ref().map(|x| x.to_string()),
                    offset,
                },
            );
            Ok(replacement)
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
            Some(RuleError::TooManyRedirects {
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

impl<'de, T: Default + Deserialize<'de>> Deserialize<'de> for RuleWithValue<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Inner<T> {
            Value(T),
            Level(LogLevel),
            Tuple(T, LogLevel),
            Table { value: T, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Value(value) => Self {
                value,
                level: LogLevel::Error,
            },
            Inner::Level(level) => Self {
                value: T::default(),
                level,
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

impl Replaceable for Idn {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::Idn { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = ""
)]
pub struct EventHandlers(String);

impl Replaceable for EventHandlers {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::EventHandler { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    default = "<!-- Blocked by Web Sanitizer: XML entity found -->"
)]
pub struct XmlEntities(String);

impl Replaceable for XmlEntities {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::XmlEntityDeclaration { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousUris(String);

impl Replaceable for DangerousUris {
    type Input = String;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousUri { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
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

impl Replaceable for DangerousDomain2 {
    type Input = Host;
    type Output = String;

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousDomain { original: value }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousScripts(String);

impl Replaceable for DangerousScripts {
    type Input = String;
    type Output = String;

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }

    fn to_error(value: Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousScript {
            original: Some(value),
        }
    }
}

#[nutype(
    derive(Debug, Default, AsRef, Deserialize, Serialize, PartialEq),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousOrigins(String);

impl Replaceable for DangerousOrigins {
    type Input = (Url, String);
    type Output = String;

    fn to_error((url, tag): Self::Input) -> RuleReplaceError {
        RuleReplaceError::DangerousOrigin {
            tag,
            original: url.to_string(),
        }
    }

    fn to_replacement(&self) -> Self::Output {
        self.as_ref().to_owned()
    }
}
