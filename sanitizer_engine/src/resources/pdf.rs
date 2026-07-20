use crate::{
    errors::{RuleError, SanitizerError},
    log::{Log, LogLevel},
};

pub fn sanitize(data: &[u8], logger: &impl Log, rule: LogLevel) -> Result<(), SanitizerError> {
    let mut i = 0;
    while i < data.len() {
        // Check for stream block start
        if i + 6 <= data.len()
            && &data[i..i + 6] == b"stream"
            && (i == 0 || data[i - 1].is_ascii_whitespace() || data[i - 1] == b'>')
        {
            i += 6;
            // Find "endstream"
            let mut found_end = false;
            while i + 9 <= data.len() {
                if &data[i..i + 9] == b"endstream" {
                    i += 9;
                    found_end = true;
                    break;
                }
                i += 1;
            }
            if !found_end {
                break;
            }
            continue;
        }

        // Check for name keys outside stream blocks
        if data[i] == b'/' {
            if i + 3 <= data.len() && &data[i..i + 3] == b"/JS" {
                let next_char = if i + 3 < data.len() { data[i + 3] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    rule.handle(
                        logger,
                        RuleError::ActiveContent {
                            original: "JavaScript (/JS)".to_owned(),
                        },
                    )?;
                }
            }
            if i + 11 <= data.len() && &data[i..i + 11] == b"/JavaScript" {
                let next_char = if i + 11 < data.len() { data[i + 11] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    rule.handle(
                        logger,
                        RuleError::ActiveContent {
                            original: "JavaScript".to_owned(),
                        },
                    )?;
                }
            }
            if i + 3 <= data.len() && &data[i..i + 3] == b"/AA" {
                let next_char = if i + 3 < data.len() { data[i + 3] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    rule.handle(
                        logger,
                        RuleError::ActiveContent {
                            original: "Additional Action (/AA)".to_owned(),
                        },
                    )?;
                }
            }
            if i + 11 <= data.len() && &data[i..i + 11] == b"/OpenAction" {
                let next_char = if i + 11 < data.len() { data[i + 11] } else { 0 };
                if is_pdf_delimiter(next_char) {
                    rule.handle(
                        logger,
                        RuleError::ActiveContent {
                            original: "OpenAction".to_owned(),
                        },
                    )?;
                }
            }
        }

        i += 1;
    }
    Ok(())
}

fn is_pdf_delimiter(b: u8) -> bool {
    b == 0
        || b.is_ascii_whitespace()
        || b == b'['
        || b == b']'
        || b == b'<'
        || b == b'>'
        || b == b'('
        || b == b')'
        || b == b'{'
        || b == b'}'
        || b == b'/'
        || b == b'%'
}

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::{log::NullLogger, rules::ReplaceRule};

    use super::*;

    #[test]
    fn test_sanitize() {
        let logger = NullLogger;
        let rule = LogLevel::Error;

        // Clean PDF
        let clean_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";
        assert!(sanitize(clean_pdf, &logger, rule).is_ok());

        // Malicious PDF with /JS key
        let malicious_js = b"%PDF-1.4\n1 0 obj\n<< /Type /Action /JS (app.alert(1)) >>\nendobj\n";
        assert!(sanitize(malicious_js, &logger, rule).is_err());

        // Malicious PDF with /OpenAction key
        let malicious_open = b"%PDF-1.4\n1 0 obj\n<< /OpenAction 2 0 R >>\nendobj\n";
        assert!(sanitize(malicious_open, &logger, rule).is_err());

        // PDF containing /JS inside a binary stream block (should pass)
        let stream_pdf =
            b"%PDF-1.4\n1 0 obj\n<< /Length 20 >>\nstream\nrandom/JSdata\nendstream\nendobj\n";
        assert!(sanitize(stream_pdf, &logger, rule).is_ok());

        // Boundary checks and fake stream check
        let fake_stream = b"randomstream/JS";
        assert!(sanitize(fake_stream, &logger, rule).is_err());

        // Files on disk
        let clean_file_data = std::fs::read("../input_test_files/benign/clean_doc.pdf").unwrap();
        assert!(sanitize(&clean_file_data, &logger, rule).is_ok());

        let malicious_file_data =
            std::fs::read("../input_test_files/malicious/pdf_js_bomb.pdf").unwrap();
        assert!(sanitize(&malicious_file_data, &logger, rule).is_err());

        // CSS and JS disk file validation checks
        let css_file_data =
            std::fs::read_to_string("../input_test_files/malicious/dangerous_styles.css").unwrap();
        let (clean_css, _) = crate::resources::css::sanitize(
            &css_file_data,
            &Url::parse("https://localhost").unwrap(),
            &NullLogger,
            &ReplaceRule::with_default(LogLevel::Warn),
        )
        .unwrap();
        assert!(clean_css.contains("url(\"\")"));

        let js_file_data =
            std::fs::read_to_string("../input_test_files/malicious/dangerous_script.js").unwrap();
        assert!(
            crate::resources::javascript::sanitize(
                &js_file_data,
                &NullLogger,
                &ReplaceRule::forbid()
            )
            .is_err()
        );
    }
}
