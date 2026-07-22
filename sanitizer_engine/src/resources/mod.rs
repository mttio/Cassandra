pub mod css;
pub mod entities;
pub mod images;
pub mod javascript;
pub mod mime;
pub mod pdf;
pub mod xml;

pub use entities::EntityScanner;
pub use images::{strip_jpeg_metadata, strip_png_metadata};

use url::Url;
use winnow::{
    Parser,
    ascii::multispace0,
    combinator::delimited,
    error::ParserError,
    stream::{AsChar, Stream, StreamIsPartial},
};

/// A combinator that takes a parser `inner` and produces a parser that also consumes both leading and
/// trailing whitespace, returning the output of `inner`.
// https://github.com/winnow-rs/winnow/discussions/563
pub fn space_around<I, O, E>(parser: impl Parser<I, O, E>) -> impl Parser<I, O, E>
where
    I: StreamIsPartial + Stream,
    E: ParserError<I>,
    I::Token: AsChar + Clone,
{
    delimited(multispace0, parser, multispace0)
}

/// Helper to generate a unique local filename deterministic for a URL.
///
/// # Inputs
/// * `url` - The URL reference for which to generate the filename.
/// * `default_ext` - The fallback extension string slice if no extension is parsed from the URL.
///
/// # Returns
/// * `String` - A deterministic, unique local filename (e.g. `sub_0123456789abcdef.css`).
pub fn generate_local_filename(url: &Url, default_ext: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    url.hash(&mut hasher);
    let hash_val = hasher.finish();

    // Try to extract clean extension from path
    let last_segment = url.path().split('/').next_back().unwrap_or("");
    let ext = last_segment
        .rsplit_once('.')
        .map(|(_, x)| x)
        .unwrap_or(default_ext);
    let ext = ext
        .chars()
        .filter(|c| c.is_alphanumeric())
        .collect::<String>();

    let ext = if ext.is_empty() { default_ext } else { &ext };

    format!("sub_{:016x}.{}", hash_val, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_local_filename() {
        let url1 = Url::parse("https://example.com/asset.js?v=2").unwrap();
        let name1 = generate_local_filename(&url1, "bin");
        assert!(name1.starts_with("sub_"));
        assert!(name1.ends_with(".js"));

        let url2 = Url::parse("https://example.com/no-ext").unwrap();
        let name2 = generate_local_filename(&url2, "png");
        assert!(name2.ends_with(".png"));

        // Path traversal mitigation check
        let url3 = Url::parse("https://example.com/../../../etc/passwd").unwrap();
        let name3 = generate_local_filename(&url3, "txt");
        assert!(!name3.contains(".."));
        assert!(!name3.contains('/'));
        assert!(!name3.contains('\\'));
    }
}
