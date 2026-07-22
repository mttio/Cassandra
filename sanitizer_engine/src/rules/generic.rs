use std::ops::Range;

use serde::{Deserialize, Serialize};

use crate::{
    errors::{ReplacementKind, RuleError},
    log::{Log, LogLevel},
};

/// A trait used by rules to describe replacement inside files and error conversion
pub trait Replaceable: ToString {
    /// Returns the associated replacement kind
    fn to_error() -> ReplacementKind;
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

impl<R: Default> ReplaceRule<R> {
    pub fn new(replace: impl Into<R>, level: LogLevel) -> Self {
        Self {
            replace: (level != LogLevel::Error).then_some(replace.into()),
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

impl<R: Default + Replaceable> ReplaceRule<R> {
    /// Handles a rule violation, with optional replacement.
    /// Uses the rule's corresponding `ReplacementKind`
    ///
    /// # Inputs
    /// - `value` - the offending value
    /// - `location` - the location of the value inside the file
    /// - `logger` - the logging instance to use
    ///
    /// # Returns
    /// - `Err(...)` - if this rule's severity level is `Error`, wrapping the corresponding error value
    /// - `Ok(...)` - otherwise, wrapping the optional replacement value
    pub fn handle(
        &self,
        value: impl ToString,
        location: Range<usize>,
        logger: &impl Log,
    ) -> Result<Option<String>, RuleError> {
        if self.level == LogLevel::Error {
            Err(RuleError::Replace {
                inner: R::to_error(),
                original: value.to_string(),
                replacement: None,
                location,
            })
        } else {
            let replacement = self.replace.as_ref().map(R::to_string);
            logger.log(
                self.level,
                RuleError::Replace {
                    inner: R::to_error(),
                    original: value.to_string(),
                    replacement: replacement.as_ref().map(|x| x.to_string()),
                    location,
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
            Value(R),
            ValueLevel { replace: R, level: LogLevel },
            BoolLevel { replace: bool, level: LogLevel },
        }

        Ok(match Inner::deserialize(deserializer)? {
            Inner::Level(level) => Self::with_default(level),
            Inner::Bool(replace) => Self {
                replace: replace.then(R::default),
                level: LogLevel::Warn,
            },
            Inner::Value(replace) => Self {
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

/// A trait for verifying that a value satisfies a rule
pub trait Verify {
    type Input<'a>
    where
        Self: 'a;

    /// Verifies the given value
    ///
    /// # Returns
    /// - `None` - if the value is allowed
    /// - `Some(...)` - if the value is forbidden, wrapping the actual error type
    fn verify(&self, value: &Self::Input<'_>) -> Option<RuleError>;
}

/// A generic rule where a value to check against can be specified
///
/// Can be specified in the config in different ways:
/// ```toml
/// rule = value                       # only value, log level is "error"
/// rule = "level"                     # only log level, value uses the default
/// Table { value = ..., level = ... } # both replacement value and log level
/// ```
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

impl<R: Default + Verify> RuleWithValue<R> {
    /// Checks the given value against this rule,
    /// sending a message (and possibly returning an error) if the value is not allowed
    ///
    /// # Inputs
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
