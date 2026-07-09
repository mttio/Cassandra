use lol_html::{
    element,
    html_content::ContentType,
    send::{HtmlRewriter, Settings},
    text,
};
use parking_lot::Mutex;
use std::{io::Write, ops::Range, sync::Arc};
use url::Url;

use crate::{errors::SanitizerError, log::Log, policy::Policy};

fn handle_dangerous_link_2(
    value: &str,
    location: Range<usize>,
    base_url: &Url,
    policy: &Policy,
    logger: &impl Log,
    mut replace: impl FnMut(&str),
) -> Result<Option<Url>, SanitizerError> {
    use unicode_normalization::UnicodeNormalization;
    let value = value.nfc().collect::<String>();

    let resolved = base_url.join(&value);
    if let Ok(mut resolved) = resolved
    // && resolved.scheme() == "https"
    {
        if let Some(host) = resolved.host() {
            // Check IDN
            match policy.urls.idn.check(&resolved, logger) {
                Ok(Some(r)) => {
                    replace(&r);
                }
                Ok(None) => {}
                Err(e) => {
                    logger.error(e);
                    replace("");
                    return Ok(None);
                }
            }

            let host = host.to_owned();

            match policy
                .html
                .dangerous_domain
                .check((&host, &policy.urls.dangerous_domains, location), logger)
            {
                Ok(Some(x)) => {
                    let new = match resolved.set_host(Some(x.as_ref())) {
                        // If policy value is a valid host, replace the host of the old url
                        Ok(_) => resolved.as_ref(),
                        // Otherwise replace the whole url with the policy value
                        Err(_) => &x,
                    };

                    replace(new)
                }
                Ok(None) => {}
                Err(e) => {
                    logger.error(e);
                    replace("");
                    return Ok(None);
                }
            }
        }

        Ok(Some(resolved))
    } else {
        Ok(None)
    }
}

/// Helper function to inspect an element's URL attribute for dangerous domains and rewrite it if necessary.
///
/// # Inputs
/// * `el` - A mutable reference to the HTML element.
/// * `attr_name` - The name of the attribute containing the URL (e.g. `"href"`, `"src"`).
/// * `base_url` - The shared thread-safe base URL of the document.
/// * `policy` - The security policy configuration.
/// * `logger` - The logging interface.
///
/// # Returns
/// * `Result<(), LoggerError>` - `Ok(())` if processing succeeded (or was handled by policies), otherwise an error.
fn handle_dangerous_link(
    el: &mut lol_html::html_content::Element<'_, '_, lol_html::send::SendHandlerTypes>,
    attr_name: &str,
    base_url: &Url,
    policy: &Policy,
    logger: &impl Log,
) -> Result<Option<Url>, SanitizerError> {
    if let Some(attribute) = el.attributes().iter().find(|x| x.name() == attr_name) {
        let location = attribute
            .value_source_location()
            .unwrap_or(el.source_location())
            .bytes();

        Ok(handle_dangerous_link_2(
            &attribute.value(),
            location,
            base_url,
            policy,
            logger,
            |x| replace_attribute(&crate::policy::sanitize_attribute(x), attr_name, el),
        )?)
    } else {
        Ok(None)
    }
}

pub struct CrawlerState {
    /// The base URL of the document
    pub base: Url,
    /// The resources discovered in the document
    pub subresources: Vec<(Url, String)>,
}

fn replace_attribute(
    value: &str,
    name: &str,
    element: &mut lol_html::html_content::Element<impl lol_html::HandlerTypes>,
) {
    if value.is_empty() {
        element.remove_attribute(name)
    } else {
        // SAFETY: we removed all invalid characters
        let _ = element.set_attribute(name, value);
    }
}

/// Creates an `HtmlRewriter` to inspect and rewrite HTML contents.
///
/// If `policy.resources.fetch_sub_resources` is `true` and a `crawler_state` is provided,
/// the rewriter will rewrite relative paths for scripts, styles, and other resources to local paths,
/// and enqueue them to be crawled. Otherwise, it will only inspect and clean standard anchors and links.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `state` - Optional tuple containing the document's thread-safe base URL and discovered resources accumulator.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * `HtmlRewriter<'a, impl FnMut(&[u8])>` - The configured rewriter instance.
pub fn create_rewriter<'a, W: Write>(
    logger: &'a impl Log,
    policy: &'a Policy,
    state: &'a mut CrawlerState,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    let mut handlers = Vec::new();

    // Since the both the `element!` closure and the `text!` closures modify the state, we need to use an `Arc<Mutex>` here, even though the closures are executed sequentially
    let state_1 = Arc::new(Mutex::new(state));
    let state_2 = Arc::clone(&state_1);

    handlers.push(element!("*", move |el| {
        let mut state = state_1.lock();

        let mut to_replace = Vec::new();

        for attr in el.attributes() {
            if let Some(x) = policy.html.event_handlers.check(attr, logger)? {
                to_replace.push((attr.name(), x));
            } else if let Some(x) = policy.html.dangerous_uris.check(attr, logger)? {
                to_replace.push((attr.name(), x));
            }
        }

        for (name, value) in to_replace {
            replace_attribute(&value, &name, el);
        }

        match el.tag_name().as_str() {
            "base" => {
                if let Some(href) = el.get_attribute("href")
                    && let Ok(new_base) = state.base.join(&href)
                {
                    state.base = new_base;
                }
            }
            "a" => {
                handle_dangerous_link(el, "href", &state.base, policy, logger)?;
            }
            "link" => {
                let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
                if !rel.contains("stylesheet") {
                    handle_dangerous_link(el, "href", &state.base, policy, logger)?;
                    return Ok(());
                }

                if let Some(resolved) =
                    handle_dangerous_link(el, "href", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "css");

                    el.set_attribute("href", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "img" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");

                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "image" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "href", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");

                    el.set_attribute("href", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "source" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "js");

                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "form" => {
                handle_dangerous_link(el, "action", &state.base, policy, logger)?;
            }
            "area" => {
                handle_dangerous_link(el, "href", &state.base, policy, logger)?;
            }
            "audio" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "mp3");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "video" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "mp4");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "embed" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "bin");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "track" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "vtt");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "input" => {
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "script" => {
                let location = el.source_location();

                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                {
                    let host_matched = if let Some(host) = resolved.host() {
                        let host = host.to_string();
                        policy.html.allow_scripts.iter().any(|allowed| {
                            allowed == &host || resolved.as_str().starts_with(allowed)
                        })
                    } else {
                        false
                    };

                    if !host_matched {
                        logger.error(SanitizerError::BlockedScript(
                            resolved.to_string(),
                            location.bytes(),
                        ));
                        el.remove();
                        return Ok(());
                    }

                    if policy.resources.fetch_sub_resources {
                        let local_name = crate::resources::generate_local_filename(&resolved, "js");

                        el.set_attribute("src", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                } else {
                    if let Some(src) = el.get_attribute("src") {
                        logger.error(SanitizerError::BlockedScript(src.clone(), location.bytes()));
                        el.remove();
                    }
                }
            }
            "iframe" => {
                let location = el.source_location().bytes();
                if let Some(resolved) =
                    handle_dangerous_link(el, "src", &state.base, policy, logger)?
                {
                    use crate::url::RuleMatch;
                    let host_matched = if let Some(host) = resolved.host().map(|x| x.to_owned()) {
                        policy.html.allow_origins.iter().any(|allowed| {
                            host.matches(&allowed.0)
                        })
                    } else {
                        false
                    };

                    if !host_matched {
                        logger.error(SanitizerError::BlockedOrigin(
                            "iframe".to_owned(),
                            resolved.to_string(),
                            location,
                        ));
                        el.remove();
                        return Ok(());
                    }
                }
            }
            "object" => {
                let location = el.source_location().bytes();
                if let Some(resolved) =
                    handle_dangerous_link(el, "data", &state.base, policy, logger)?
                {
                    use crate::url::RuleMatch;
                    let host_matched = if let Some(host) = resolved.host().map(|x| x.to_owned()) {
                        policy.html.allow_origins.iter().any(|allowed| {
                            host.matches(&allowed.0)
                        })
                    } else {
                        false
                    };

                    if !host_matched {
                        logger.error(SanitizerError::BlockedOrigin(
                            "object".to_owned(),
                            resolved.to_string(),
                            location,
                        ));
                        el.remove();
                        return Ok(());
                    }
                }
            }
            "meta" => {
                if let Some(http_equiv) = el.get_attribute("http-equiv")
                    && http_equiv.to_lowercase() == "refresh"
                {
                    let content = el.get_attribute("content").unwrap_or_default();
                    let location = el.source_location().bytes();
                    logger.error(SanitizerError::BlockedMetaRefresh(content, location));
                    el.remove();
                }
            }
            _ => {}
        }

        Ok(())
    }));

    let mut inline_script = String::new();
    let mut inline_script_location = None;
    handlers.push(text!("script", move |t| {
        use base64::{Engine, prelude::BASE64_STANDARD};
        use sha2::{Digest, Sha256};

        inline_script.push_str(t.as_str());
        t.remove();

        if inline_script_location.is_none() {
            inline_script_location = Some(t.source_location().bytes().start);
        }

        if t.last_in_text_node() {
            let mut hasher = Sha256::new();
            hasher.update(inline_script.as_bytes());
            let hash_result = hasher.finalize();
            let b64_hash = BASE64_STANDARD.encode(hash_result);
            let csp_hash = format!("sha256-{}", b64_hash);

            let is_allowed = policy
                .html
                .allow_scripts
                .iter()
                .any(|allowed| allowed == &csp_hash);
            if is_allowed {
                t.replace(&inline_script, ContentType::Text);
            } else {
                let start = inline_script_location.unwrap_or(0);
                let end = t.source_location().bytes().end;

                logger.error(SanitizerError::BlockedScript(
                    "<inline>".to_owned(),
                    start..end,
                ));
            }
            inline_script.clear();
            inline_script_location = None;
        }
        Ok(())
    }));

    let mut inline_style = String::new();
    handlers.push(text!("style", move |t| {
        let mut state = state_2.lock();

        inline_style.push_str(t.as_str());
        t.remove();

        if t.last_in_text_node() {
            let (css, mut subresources) = crate::resources::css::sanitize(
                &inline_style,
                &state.base,
                logger,
                &policy.resources.dangerous_css,
            )?;
            t.replace(&css, ContentType::Text);
            state.subresources.append(&mut subresources);
            inline_style.clear();
        }
        Ok(())
    }));

    HtmlRewriter::new(
        Settings {
            element_content_handlers: handlers,
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            output.write_all(c).unwrap();
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        log::{LogLevel, NullLogger},
        policy::{DangerousUriRule, EventHandlerRule},
        rules::RuleWithReplace,
    };

    #[test]
    fn test_event_handler_stripping() {
        let policy = Policy::default();

        let input_html = b"<button onclick=\"alert(1)\" class=\"btn\" ONLOAD=\"doSomething()\">Click me</button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("onclick"));
        assert!(!result.contains("ONLOAD"));
        assert!(result.contains("class=\"btn\""));
        assert!(result.contains("Click me"));
    }

    #[test]
    fn test_event_handler_replacement() {
        let mut policy = Policy::default();
        policy.html.event_handlers =
            RuleWithReplace::new(EventHandlerRule::new("alert('blocked')"), LogLevel::Info);

        let input_html = b"<button onclick=\"alert(1)\"></button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("onclick=\"alert('blocked')\""));
    }

    #[test]
    fn test_event_handler_ignore() {
        let mut policy = Policy::default();
        policy.html.event_handlers = RuleWithReplace::keep(LogLevel::Trace);

        let input_html = b"<button onclick=\"alert(1)\"></button>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("onclick=\"alert(1)\""));
    }

    #[test]
    fn test_script_src_allowed() {
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["trusted.com".to_owned()];

        let input_html = b"<script src=\"https://trusted.com/lib.js\"></script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("<script src=\"sub_"));
    }

    #[test]
    fn test_script_src_blocked() {
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["trusted.com".to_owned()];

        let input_html = b"<script src=\"https://untrusted.com/lib.js\"></script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("untrusted.com"));
        assert!(!result.contains("<script"));
    }

    #[test]
    fn test_script_inline_allowed() {
        let mut policy = Policy::default();
        policy.html.allow_scripts =
            vec!["sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI=".to_owned()];

        let input_html = b"<script>alert(1)</script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("alert(1)"));
    }

    #[test]
    fn test_script_inline_blocked() {
        let policy = Policy::default();

        let input_html = b"<script>alert(1)</script>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("alert(1)"));
    }

    #[test]
    fn test_dangerous_uris_sanitization() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris = RuleWithReplace::with_default(LogLevel::Info);

        let input_html = b"<a href=\"javascript:alert(1)\" src=\"  data:text/html,malicious  \" data-url=\"other\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("href=\"#\""));
        assert!(result.contains("src=\"#\""));
        assert!(result.contains("data-url=\"other\""));
    }

    #[test]
    fn test_dangerous_uris_bypass_whitespace() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris =
            RuleWithReplace::new(DangerousUriRule::new(""), LogLevel::Info);

        let input_html = b"<a href=\"\n\t javascript:alert(1)\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(!result.contains("javascript"));
        assert!(!result.contains("href="));
    }

    #[test]
    fn test_dangerous_uris_ignore() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris = RuleWithReplace::keep(LogLevel::Trace);

        let input_html = b"<a href=\"javascript:alert(1)\">link</a>";
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("href=\"javascript:alert(1)\""));
    }

    #[test]
    fn test_idn_rewriting() {
        // Case 1: IDN is Warn. It should preserve the link.
        let mut policy = Policy::default();
        policy.urls.idn = RuleWithReplace::keep(LogLevel::Warn);
        policy.resources.fetch_sub_resources = false;

        let mut crawler_state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: vec![],
        };

        let mut output = Vec::new();
        {
            let mut rewriter =
                create_rewriter(&NullLogger, &policy, &mut crawler_state, &mut output);
            rewriter
                .write(b"<a href=\"http://googl\xC3\xA9.com\">Link</a>")
                .unwrap();
            rewriter.end().unwrap();
        }
        let out_str = String::from_utf8(output).unwrap();
        assert!(
            out_str.contains("http://googl\u{00E9}.com")
                || out_str.contains("http://xn--googl-fsa.com")
        );

        // Case 2: IDN is Warn with rewriting enabled. It should rewrite to "#".
        policy.urls.idn = RuleWithReplace::with_default(LogLevel::Warn);
        let mut output2 = Vec::new();
        {
            let mut rewriter =
                create_rewriter(&NullLogger, &policy, &mut crawler_state, &mut output2);
            rewriter
                .write(b"<a href=\"http://googl\xC3\xA9.com\">Link</a>")
                .unwrap();
            rewriter.end().unwrap();
        }
        let out_str2 = String::from_utf8(output2).unwrap();
        assert!(out_str2.contains("href=\"#\""));
    }

    #[test]
    fn test_iframe_object_origin_filtering() {
        let mut policy = Policy::default();
        // policy.html.allow_origins defaults to ["trusted.com"]
        policy.resources.fetch_sub_resources = false;

        let input_html = b"<div>\
            <iframe src=\"https://trusted.com/page.html\"></iframe>\
            <iframe src=\"https://untrusted.com/page.html\"></iframe>\
            <object data=\"https://trusted.com/data.bin\"></object>\
            <object data=\"https://untrusted.com/data.bin\"></object>\
        </div>";

        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("src=\"https://trusted.com/page.html\""));
        assert!(!result.contains("src=\"https://untrusted.com/page.html\""));
        assert!(!result.contains("<iframe src=\"https://untrusted.com"));
        assert!(result.contains("data=\"https://trusted.com/data.bin\""));
        assert!(!result.contains("data=\"https://untrusted.com/data.bin\""));
        assert!(!result.contains("<object data=\"https://untrusted.com"));
    }

    #[test]
    fn test_meta_refresh_removal() {
        let policy = Policy::default();
        let input_html = b"<html>\
            <head>\
                <meta charset=\"utf-8\">\
                <meta http-equiv=\"refresh\" content=\"5;url=https://trusted.com\">\
            </head>\
        </html>";

        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("charset=\"utf-8\""));
        assert!(!result.contains("http-equiv=\"refresh\""));
    }

    #[test]
    fn test_broadened_url_extraction() {
        let mut policy = Policy::default();
        policy.resources.fetch_sub_resources = true;

        let input_html = b"<div>\
            <form action=\"https://trusted.com/submit\"></form>\
            <area href=\"https://trusted.com/map\"></area>\
            <audio src=\"https://trusted.com/song.mp3\"></audio>\
            <video src=\"https://trusted.com/movie.mp4\"></video>\
            <embed src=\"https://trusted.com/app.swf\"></embed>\
            <track src=\"https://trusted.com/sub.vtt\"></track>\
            <input src=\"https://trusted.com/btn.png\"></input>\
        </div>";

        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        // form and area are NOT sub-resources, so they should keep their original/resolved URLs
        assert!(result.contains("action=\"https://trusted.com/submit\""));
        assert!(result.contains("href=\"https://trusted.com/map\""));

        // audio, video, embed, track, input ARE sub-resources, so they should be rewritten to local names
        assert!(result.contains("src=\"sub_"));
        assert_eq!(state.subresources.len(), 5);
    }

    #[test]
    fn test_flexible_action_handling_deny_remove() {
        let policy = Policy::default();
        // default dangerous_domain is Error, which should trigger Deny/Remove
        // allow_origins contains trusted.com
        let input_html = b"<div>\
            <a href=\"https://evil.com/malicious\">Link</a>\
            <form action=\"https://evil.com/submit\"></form>\
        </div>";

        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, &policy, &mut state, &mut output);
        rewriter.write(input_html).unwrap();
        rewriter.end().unwrap();

        let result = String::from_utf8(output).unwrap();
        // Both the anchor href and form action point to a dangerous domain.
        // Under Error level, flexible action handling should strip/blank these attributes rather than aborting.
        assert!(!result.contains("evil.com"));
        assert!(!result.contains("href="));
        assert!(!result.contains("action="));
    }
}
