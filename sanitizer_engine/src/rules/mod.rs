mod generic;
pub use generic::*;

use nutype::nutype;
use serde::{Deserialize, Serialize};
use url::Host;

use crate::{
    errors::{ReplacementKind, RuleError},
    policy::PolicyHost,
    url::host_matches,
};

/// Remove invalid characters in HTML url attributes.
pub fn sanitize_attribute(s: &str) -> String {
    s.replace([' ', '\n', '\r', '\t', '\x0C', '/', '>', '='], "")
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = ""
)]
pub struct EventHandlers(String);

impl Replaceable for EventHandlers {
    fn to_error() -> ReplacementKind {
        ReplacementKind::EventHandler
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    default = "<!-- Blocked by Web Sanitizer: XML entity found -->"
)]
pub struct XmlEntities(String);

impl Replaceable for XmlEntities {
    fn to_error() -> ReplacementKind {
        ReplacementKind::XmlEntityDeclaration
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    default = ""
)]
pub struct MetaRefresh(String);

impl Replaceable for MetaRefresh {
    fn to_error() -> ReplacementKind {
        ReplacementKind::MetaRefresh
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousScripts(String);

impl Replaceable for DangerousScripts {
    fn to_error() -> ReplacementKind {
        ReplacementKind::DangerousScript
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousOrigins(String);

impl Replaceable for DangerousOrigins {
    fn to_error() -> ReplacementKind {
        ReplacementKind::DangerousOrigin
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct DangerousDomains(String);

impl Replaceable for DangerousDomains {
    fn to_error() -> ReplacementKind {
        ReplacementKind::DangerousDomain
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    default = "#"
)]
pub struct DangerousUris(String);

impl Replaceable for DangerousUris {
    fn to_error() -> ReplacementKind {
        ReplacementKind::DangerousUri
    }
}

#[nutype(
    derive(Debug, Default, Deserialize, Serialize, PartialEq, Display),
    sanitize(with = |x| sanitize_attribute(&x)),
    default = "#"
)]
pub struct Idn(String);

impl Replaceable for Idn {
    fn to_error() -> ReplacementKind {
        ReplacementKind::Idn
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 5
)]
pub struct MaxSubresources(usize);

impl Verify for MaxSubresources {
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
    default = 1
)]
pub struct MaxResourceDepth(usize);

impl Verify for MaxResourceDepth {
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
    default = 1024 * 1024
)]
pub struct MaxBytes(usize);

impl Verify for MaxBytes {
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
    derive(Debug, Serialize, Deserialize, Default, PartialEq, Display, From),
    default = "/* Blocked by Web Sanitizer: dangerous keywords found */"
)]
pub(crate) struct DangerousJs(String);

impl Replaceable for DangerousJs {
    fn to_error() -> ReplacementKind {
        ReplacementKind::DangerousJsConstruct
    }
}

#[nutype(
    derive(Debug, AsRef, Serialize, Deserialize, Default, PartialEq),
    default = 2
)]
pub struct MaxRedirects(usize);

impl Verify for MaxRedirects {
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

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, PartialEq)]
pub struct DangerousConnection;

impl Verify for DangerousConnection {
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
