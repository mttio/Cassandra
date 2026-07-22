use std::borrow::Cow;

use crate::resources::space_around;
use winnow::{
    LocatingSlice, Parser,
    ascii::multispace0,
    combinator::{alt, repeat_till},
    error::EmptyError,
    token::any,
};

use crate::{
    errors::SanitizerError,
    log::Log,
    rules::{JsReplace, ReplaceRule},
};

/// Scans JS file for dangerous constructs (eval, document.write).
///
/// # Inputs
/// * `content` - A string slice containing the JavaScript source code.
///
/// # Returns
/// * `Result<(), SanitizationError>` - `Ok` if no dangerous keywords are found, otherwise an `Err` indicating what was found.
pub fn sanitize<'a>(
    input: &'a str,
    logger: &impl Log,
    rule: &ReplaceRule<JsReplace>,
) -> Result<Cow<'a, str>, SanitizerError> {
    let mut content = LocatingSlice::new(input);

    let mut parser = repeat_till(
        0..,
        any.map(drop),
        (
            alt((
                "eval",
                "alert",
                ("document", space_around('.'), "write").take(),
            )),
            multispace0,
            '(',
        )
            .take()
            .with_span(),
    )
    .map(|x: (Vec<_>, _)| x.1);

    while let Ok::<_, EmptyError>((value, location)) = parser.parse_next(&mut content) {
        if let Some(replace) = rule.handle(format!("{value}..)"), location, logger)? {
            return Ok(Cow::from(replace));
        }
    }

    Ok(Cow::from(input))
}

#[cfg(test)]
mod tests {
    use crate::log::NullLogger;

    use super::*;

    #[test]
    fn test_sanitize() {
        let rule = ReplaceRule::forbid();
        let logger = NullLogger;

        assert!(sanitize("console.log('hello');", &logger, &rule).is_ok());
        assert!(sanitize("eval('1 + 1');", &logger, &rule).is_err());
        assert!(sanitize("document.write('xss');", &logger, &rule).is_err());
    }

    #[test]
    fn test_sanitize_spaces() {
        let rule = ReplaceRule::forbid();
        let logger = NullLogger;

        assert!(sanitize("eval    (  '1+1'  ) eval()", &logger, &rule).is_err());
        assert!(sanitize("let evaluator = 1;", &logger, &rule).is_ok());
        assert!(sanitize("document   . write ()", &logger, &rule).is_err());
    }
}
