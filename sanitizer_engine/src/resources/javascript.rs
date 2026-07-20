use itertools::Itertools;

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
pub fn sanitize(
    content: &str,
    logger: &impl Log,
    rule: &ReplaceRule<JsReplace>,
) -> Result<String, SanitizerError> {
    let mut chars = content.chars().peekable();
    while let Some(c) = chars.next() {
        if c == 'e' {
            let mut temp = chars.clone();
            if temp.next_array() == Some(['v', 'a', 'l']) {
                while let Some(&next_c) = temp.peek() {
                    if next_c.is_whitespace() {
                        temp.next();
                    } else {
                        break;
                    }
                }
                if temp.peek() == Some(&'(') {
                    if let Some(replace) =
                        rule.handle("eval(...)".to_owned(), 0..content.len(), logger)?
                    {
                        return Ok(replace);
                    }
                }
            }
        }
        if c == 'd' {
            let mut temp = chars.clone();
            if temp.next_array() == Some(['o', 'c', 'u', 'm', 'e', 'n', 't']) {
                let mut temp = temp.skip_while(|c| c.is_whitespace());
                if temp.next() == Some('.') {
                    let mut temp = temp.skip_while(|c| c.is_whitespace());
                    if temp.next_array() == Some(['w', 'r', 'i', 't', 'e']) {
                        if let Some(replace) =
                            rule.handle("document.write(...)".to_owned(), 0..content.len(), logger)?
                        {
                            return Ok(replace);
                        }
                    }
                }
            }
        }
    }

    Ok(content.to_owned())
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

        assert!(sanitize("eval    (  '1+1'  )", &logger, &rule).is_err());
        assert!(sanitize("let evaluator = 1;", &logger, &rule).is_ok());
        assert!(sanitize("document.write()", &logger, &rule).is_err());
    }
}
