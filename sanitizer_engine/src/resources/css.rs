use tree_sitter::Parser;
use url::Url;

use crate::{
    errors::SanitizerError,
    log::Log,
    resources::traverse,
    rules::{CssUrl, ReplaceRule},
};

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
pub fn sanitize(
    content: &str,
    base_url: &Url,
    logger: &impl Log,
    rule: &ReplaceRule<CssUrl>,
) -> Result<(String, Vec<(Url, String)>), SanitizerError> {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_css::LANGUAGE.into())
        .expect("Error loading grammar");

    let tree = parser.parse(content, None).unwrap();

    let mut extracted = Vec::new();
    let mut replacements = Vec::new();

    traverse(tree.root_node(), &mut |node| {
        if node.kind() == "call_expression"
            && let Some(function_name) = node.child(0)
            && function_name.kind() == "function_name"
            && &content[function_name.byte_range()] == "url"
            && let Some(arguments) = node.child(1)
            && arguments.kind() == "arguments"
            && let Some(first) = arguments.child(1)
        {
            let value = if first.kind() == "string_value"
                && let Some(string_content) = first.child(1)
                && string_content.kind() == "string_content"
            {
                Some(string_content)
            } else if first.kind() == "plain_value" {
                Some(first)
            } else {
                None
            };

            if let Some(value) = value {
                let url = content[value.byte_range()].trim();

                if let Some(replace) = rule.check(url, value.byte_range(), logger)? {
                    replacements.push((value.byte_range(), replace));
                } else if let Ok(resolved) = base_url.join(url) {
                    let ext = url
                        .rsplit('.')
                        .next()
                        .unwrap_or("bin")
                        .split('?')
                        .next()
                        .unwrap_or("bin");
                    let local_name = super::generate_local_filename(&resolved, ext);
                    replacements.push((value.byte_range(), local_name.clone()));
                    extracted.push((resolved, local_name));
                } else {
                    replacements.push((value.byte_range(), String::new()));
                }
            }
        }

        if node.kind() == "import_statement"
            && let Some(value) = node.child(1)
        {
            let value = if value.kind() == "string_value"
                && let Some(string_content) = value.child(1)
                && string_content.kind() == "string_content"
            {
                Some(string_content)
            } else if value.kind() == "plain_value" {
                Some(value)
            } else {
                None
            };

            if let Some(value) = value {
                let url = content[value.byte_range()].trim();

                if !url.is_empty()
                    && let Ok(resolved) = base_url.join(url)
                {
                    let local_name = super::generate_local_filename(&resolved, "css");
                    replacements.push((value.byte_range(), local_name.clone()));
                    extracted.push((resolved, local_name));
                }
            }
        }

        Ok::<_, SanitizerError>(())
    })?;

    let mut output = content.to_owned();
    for (range, replacement) in replacements.into_iter().rev() {
        output.replace_range(range, &replacement);
    }

    Ok((output, extracted))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log::{LogLevel, NullLogger};

    #[test]
    fn test_sanitize() {
        let base_url = Url::parse("https://example.com/dir/style.css").unwrap();
        let css = "body { background: url('img.png'); } @import 'common.css';";
        let (rewritten, extracted) = sanitize(
            css,
            &base_url,
            &NullLogger,
            &ReplaceRule::with_default(LogLevel::Warn),
        )
        .unwrap();

        assert!(rewritten.contains("url('sub_"));
        assert!(rewritten.contains("@import 'sub_"));
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
        let base_url = Url::parse("https://example.com/style.css").unwrap();
        let css = "body { background: url('data:image/png;base64,1234'); font: url('javascript:alert(1)'); }";
        let (rewritten, extracted) = sanitize(
            css,
            &base_url,
            &NullLogger,
            &ReplaceRule::with_default(LogLevel::Warn),
        )
        .unwrap();
        assert!(rewritten.contains("url('')"));
        assert_eq!(extracted.len(), 0);
    }
}
