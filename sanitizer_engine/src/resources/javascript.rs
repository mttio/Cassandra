use tree_sitter::Parser;

use crate::{
    errors::SanitizerError,
    log::Log,
    resources::traverse,
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
    content: &'a [u8],
    logger: &impl Log,
    rule: &ReplaceRule<JsReplace>,
) -> Result<Option<Vec<u8>>, SanitizerError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_javascript::LANGUAGE.into())
        .expect("Error loading grammar");

    let tree = parser.parse(content, None).unwrap();
    // traverse(0, content, cursor.node(), None, &mut cursor);

    let mut replace_all = None;

    traverse(tree.root_node(), &mut |node| {
        if node.kind() == "call_expression"
            && let Some(function) = node.child_by_field_name("function")
        {
            let dangerous =
                if function.kind() == "identifier" && &content[function.byte_range()] == b"eval" {
                    true
                } else if function.kind() == "member_expression"
                    && let Some(object) = function.child_by_field_name("object")
                    && object.kind() == "identifier"
                    && &content[object.byte_range()] == b"document"
                    && let Some(property) = function.child_by_field_name("property")
                    && property.kind() == "property_identifier"
                    && &content[property.byte_range()] == b"write"
                {
                    true
                } else {
                    false
                };

            if dangerous
                && let Some(replace) = rule.check(
                    &String::from_utf8_lossy(&content[node.byte_range()]),
                    node.byte_range(),
                    logger,
                )?
            {
                replace_all = Some(replace.into_bytes());
            }
        }

        Ok::<_, SanitizerError>(())
    })?;

    Ok(replace_all)
}

#[cfg(test)]
mod tests {
    use crate::log::{LogLevel, NullLogger};

    use super::*;

    #[test]
    fn test_sanitize() {
        let logger = NullLogger;
        let rule = ReplaceRule::keep(LogLevel::Error);

        assert!(sanitize(b"console.log('hello');", &logger, &rule).is_ok());
        assert!(sanitize(b"eval('1 + 1');", &logger, &rule).is_err());
        assert!(sanitize(b"document.write('xss');", &logger, &rule).is_err());
    }

    #[test]
    fn test_sanitize_spaces() {
        let logger = NullLogger;
        let rule = ReplaceRule::keep(LogLevel::Error);

        assert!(sanitize(b"eval    (  '1+1'  )", &logger, &rule).is_err());
        assert!(sanitize(b"let evaluator = 1;", &logger, &rule).is_ok());
        assert!(sanitize(b"document.write()", &logger, &rule).is_err());
    }
}
