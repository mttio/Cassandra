use crate::resources::space_around;
use std::{borrow::Cow, ops::Range};

use url::Url;
use winnow::{
    LocatingSlice, Parser, Partial,
    ascii::{escaped, multispace0, multispace1},
    combinator::{alt, delimited, repeat_till},
    error::{EmptyError, ParserError},
    token::{any, take_while},
};

use crate::{
    errors::RuleError,
    log::Log,
    policy::Policy,
    url::{detect_idn, is_dangerous_uri},
};

fn url_parser<'a, Error>(
    input: &mut Partial<LocatingSlice<&'a str>>,
) -> Result<(String, Range<usize>), Error>
where
    Error: ParserError<Partial<LocatingSlice<&'a str>>>,
{
    alt((
        delimited(
            '"',
            escaped(take_while(1.., |x| x != '\\' && x != '"'), '\\', any),
            '"',
        )
        .with_span(),
        delimited(
            '\'',
            escaped(take_while(1.., |x| x != '\\' && x != '\''), '\\', any),
            '\'',
        )
        .with_span(),
        escaped(
            take_while(1.., |x| x != '\\' && x != ';' && x != ')'),
            '\\',
            any,
        )
        .with_span(),
    ))
    .parse_next(input)
}

/// Scans CSS content for @import and url(...) references, validates/rewrites them, and extracts them.
///
/// # Inputs
/// * `css` - A string slice containing the CSS source code.
/// * `base_url` - The base URL of the CSS file used to resolve relative imports/links.
///
/// # Returns
/// * `(String, Vec<(Url, String)>)` - A tuple containing:
///   1. The rewritten CSS string with references updated to local filenames.
///   2. A vector of tuples pairing the fully resolved absolute URLs of discovered sub-resources with their generated local filenames.
pub fn sanitize<'a>(
    input: &'a str,
    base_url: &Url,
    logger: &impl Log,
    policy: &Policy,
) -> Result<(Cow<'a, str>, Vec<(Url, String)>), RuleError> {
    let mut replacements = Vec::new();
    let mut extracted = Vec::new();
    let mut content = Partial::new(LocatingSlice::new(input));

    let mut parser = repeat_till(
        0..,
        any.map(drop),
        alt((
            delimited(("@import", multispace1), url_parser, (multispace0, ';')),
            delimited(("url", space_around('(')), url_parser, (multispace0, ')')),
        )),
    )
    .map(|x: (Vec<_>, _)| x.1);

    while let Ok::<_, EmptyError>((url, location)) = parser.parse_next(&mut content) {
        let clean = url.trim();

        let processed = if is_dangerous_uri(clean) {
            if let Some(replace) =
                policy
                    .html
                    .dangerous_uris
                    .handle(&url, location.clone(), logger)?
            {
                replace
            } else {
                url.to_owned()
            }
        } else if let Ok(resolved_url) = base_url.join(clean) {
            if detect_idn(&resolved_url).is_some()
                && let Some(replace) = policy.urls.idn.handle(&url, location.clone(), logger)?
            {
                replace
            } else {
                let ext = clean
                    .rsplit('.')
                    .next()
                    .unwrap_or("bin")
                    .split('?')
                    .next()
                    .unwrap_or("bin");
                let local_name = super::generate_local_filename(&resolved_url, ext);
                extracted.push((resolved_url, local_name.clone()));
                local_name
            }
        } else {
            "".to_owned()
        };

        replacements.push((location, format!("\"{processed}\"")));
    }

    if replacements.is_empty() {
        return Ok((Cow::from(input), extracted));
    }

    let mut output = input.to_owned();
    for (location, replacement) in replacements.into_iter().rev() {
        output.replace_range(location, &replacement);
    }

    Ok((Cow::from(output), extracted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        log::{LogLevel, NullLogger},
        rules::ReplaceRule,
    };

    #[test]
    fn test_sanitize() {
        let mut policy = Policy::default();
        policy.html.dangerous_domain = ReplaceRule::with_default(LogLevel::Warn);

        let base_url = Url::parse("https://example.com/dir/style.css").unwrap();
        let css = "body { background: url('img.png'); } @import 'common.css';";
        let (rewritten, extracted) = sanitize(css, &base_url, &NullLogger, &policy).unwrap();

        assert!(rewritten.contains("url(\"sub_"));
        assert!(rewritten.contains("@import \"sub_"));
        assert_eq!(extracted.len(), 2);
        assert_eq!(
            extracted[0].0,
            Url::parse("https://example.com/dir/img.png").unwrap()
        );
        assert_eq!(
            extracted[1].0,
            Url::parse("https://example.com/dir/common.css").unwrap()
        );
    }

    #[test]
    fn test_sanitize_dangerous_uris() {
        let mut policy = Policy::default();
        policy.html.dangerous_domain = ReplaceRule::with_default(LogLevel::Warn);

        let base_url = Url::parse("https://example.com/style.css").unwrap();
        let css = "\
            body {\
                background: url('data:image/png;base64,1234');\
                font: url('javascript:alert(1)');\
            }";
        let (rewritten, extracted) = sanitize(css, &base_url, &NullLogger, &policy).unwrap();
        assert!(rewritten.contains("url(\"#\")"));
        assert_eq!(extracted.len(), 0);
    }
}
