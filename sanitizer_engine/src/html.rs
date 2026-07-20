use lol_html::{
    element,
    html_content::ContentType,
    send::{HtmlRewriter, Settings},
    text,
};
use parking_lot::Mutex;
use std::{io::Write, ops::Range, sync::Arc};
use url::Url;

use crate::{
    errors::RuleError,
    log::Log,
    policy::{AllowedScript, Policy},
    rules::sanitize_attribute,
    url::{detect_idn, host_matches, is_dangerous_uri},
};

fn sanitize_url(
    value: &str,
    location: Range<usize>,
    base_url: &Url,
    policy: &Policy,
    logger: &impl Log,
) -> Result<Option<(Url, Option<String>)>, RuleError> {
    use unicode_normalization::UnicodeNormalization;
    let value = value.nfc().collect::<String>();

    if let Ok(mut url) = base_url.join(&value)
    // && resolved.scheme() == "https"
    {
        let mut replacement = None;

        // Check IDN
        if let Some((original, _)) = detect_idn(&url)
            && let Some(r) =
                policy
                    .urls
                    .idn
                    .handle(original.to_owned(), location.clone(), logger)?
        {
            replacement = Some(r);
        }

        if let Some(host) = url.host() {
            let host = host.to_owned();

            if policy
                .urls
                .dangerous_domains
                .iter()
                .any(|x| host_matches(&host, &x.0))
                && let Some(x) = policy
                    .html
                    .dangerous_domain
                    .handle(host, location, logger)?
            {
                let new = match url.set_host(Some(x.as_ref())) {
                    // If policy value is a valid host, replace the host of the old url
                    Ok(_) => url.to_string(),
                    // Otherwise replace the whole url with the policy value
                    Err(_) => x,
                };

                replacement = Some(new)
            }
        }

        Ok(Some((url, replacement)))
    } else {
        Ok(None)
    }
}

/// Helper function to inspect an element's URL attribute for dangerous domains and rewrite it if necessary.
///
/// # Inputs
/// * `el` - A mutable reference to the HTML element.
/// * `attr_name` - The name of the attribute containing the URL (e.g. `"href"`, `"src"`).
/// * `base_url` - The base URL of the document.
/// * `policy` - The security policy configuration.
/// * `logger` - The logging interface.
///
/// # Returns
/// * `Result<(), LoggerError>` - `Ok(())` if processing succeeded (or was handled by policies), otherwise an error.
fn handle_attribute(
    el: &mut lol_html::html_content::Element<'_, '_, lol_html::send::SendHandlerTypes>,
    attr_name: &str,
    base_url: &Url,
    policy: &Policy,
    logger: &impl Log,
) -> Result<Option<Url>, RuleError> {
    if let Some(attribute) = el.attributes().iter().find(|x| x.name() == attr_name) {
        let location = attribute
            .value_source_location()
            .unwrap_or(el.source_location())
            .bytes();

        Ok(
            sanitize_url(&attribute.value(), location, base_url, policy, logger)?.map(
                |(url, replacement)| {
                    if let Some(x) = replacement {
                        replace_attribute(&crate::rules::sanitize_attribute(&x), attr_name, el);
                    }

                    url
                },
            ),
        )
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
        let _ = element.set_attribute(name, &sanitize_attribute(value));
    }
}

/// Creates an `HtmlRewriter` to inspect and rewrite HTML contents.
///
/// If `policy.resources.fetch_sub_resources` is `true`,
/// the rewriter will rewrite relative paths for scripts, styles, and other resources to local paths,
/// and enqueue them to be crawled. Otherwise, it will only inspect and clean standard anchors and links.
///
/// # Inputs
/// * `logger` - The logging interface.
/// * `policy` - The security policy configuration.
/// * `state` - The document's base URL and discovered resources accumulator.
/// * `output` - The output stream writer to write the rewritten HTML bytes to.
///
/// # Returns
/// * The configured rewriter instance.
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
            let location = attr
                .name_source_location()
                .map(|x| x.bytes())
                .unwrap_or(0..0);

            if attr.name().starts_with("on")
                && let Some(x) =
                    policy
                        .html
                        .event_handlers
                        .handle(attr.name(), location.clone(), logger)?
            {
                to_replace.push((attr.name(), x));
                continue;
            }

            let attr_value = attr.value().trim().to_lowercase();
            if is_dangerous_uri(&attr_value)
                && let Some(x) = policy
                    .html
                    .dangerous_uris
                    .handle(attr_value, location, logger)?
            {
                to_replace.push((attr.name(), x));
                continue;
            }
        }

        for (name, value) in to_replace {
            replace_attribute(&value, &name, el);
        }

        let tag = el.tag_name();
        match tag.as_str() {
            "base" => {
                if let Some(href) = el.get_attribute("href")
                    && let Ok(new_base) = state.base.join(&href)
                {
                    state.base = new_base;
                }
            }
            "a" => {
                handle_attribute(el, "href", &state.base, policy, logger)?;
            }
            "link" => {
                let rel = el.get_attribute("rel").unwrap_or_default().to_lowercase();
                if !rel.contains("stylesheet") {
                    handle_attribute(el, "href", &state.base, policy, logger)?;
                    return Ok(());
                }

                if let Some(resolved) = handle_attribute(el, "href", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "css");

                    el.set_attribute("href", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "img" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");

                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "image" => {
                if let Some(resolved) = handle_attribute(el, "href", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");

                    el.set_attribute("href", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "source" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "js");

                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "form" => {
                handle_attribute(el, "action", &state.base, policy, logger)?;
            }
            "area" => {
                handle_attribute(el, "href", &state.base, policy, logger)?;
            }
            "audio" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "mp3");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "video" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "mp4");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "embed" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "bin");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "track" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "vtt");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "input" => {
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)?
                    && policy.resources.fetch_sub_resources
                {
                    let local_name = crate::resources::generate_local_filename(&resolved, "png");
                    el.set_attribute("src", &local_name)?;
                    state.subresources.push((resolved, local_name));
                }
            }
            "script" => {
                let location = el.source_location().bytes();

                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)? {
                    if let Some(host) = resolved.host() {
                        let host = host.to_owned();
                        if !policy.html.allow_scripts.iter().any(|allowed| {
                            if let AllowedScript::Host(allowed) = allowed {
                                host_matches(allowed, &host)
                            } else {
                                false
                            }
                        }) && let Some(replace) = policy.html.dangerous_scripts.handle(
                            host.to_string(),
                            location,
                            logger,
                        )? {
                            replace_attribute(&replace, "src", el);
                        }
                    };

                    if policy.resources.fetch_sub_resources {
                        let local_name = crate::resources::generate_local_filename(&resolved, "js");

                        el.set_attribute("src", &local_name)?;
                        state.subresources.push((resolved, local_name));
                    }
                } else {
                    if let Some(src) = el.get_attribute("src")
                        && let Some(replace) = policy
                            .html
                            .dangerous_scripts
                            .handle(src, location, logger)?
                    {
                        replace_attribute(&replace, "src", el);
                    }
                }
            }
            "iframe" => {
                let location = el.source_location().bytes();
                if let Some(resolved) = handle_attribute(el, "src", &state.base, policy, logger)? {
                    let matched = if let Some(host) = resolved.host().map(|x| x.to_owned()) {
                        policy
                            .html
                            .allow_origins
                            .iter()
                            .any(|allowed| host_matches(&host, &allowed.0))
                    } else {
                        false
                    };
                    if !matched
                        && let Some(replace) = policy
                            .html
                            .dangerous_origins
                            .handle(resolved, location, logger)?
                    {
                        replace_attribute(&replace, "src", el);
                    }
                }
            }
            "object" => {
                let location = el.source_location().bytes();
                if let Some(resolved) = handle_attribute(el, "data", &state.base, policy, logger)? {
                    let matched = if let Some(host) = resolved.host().map(|x| x.to_owned()) {
                        policy
                            .html
                            .allow_origins
                            .iter()
                            .any(|allowed| host_matches(&host, &allowed.0))
                    } else {
                        false
                    };
                    if !matched
                        && let Some(replace) = policy
                            .html
                            .dangerous_origins
                            .handle(resolved, location, logger)?
                    {
                        replace_attribute(&replace, "data", el);
                    }
                }
            }
            "meta" => {
                if let Some(http_equiv) = el.get_attribute("http-equiv")
                    && http_equiv.to_lowercase() == "refresh"
                {
                    let content = el.get_attribute("content").unwrap_or_default();
                    let location = el.source_location().bytes();

                    if let Some(replace) =
                        policy.html.meta_refresh.handle(content, location, logger)?
                    {
                        if replace.is_empty() {
                            el.remove();
                        } else {
                            replace_attribute(&replace, "content", el);
                        }
                    }
                }
            }
            _ => {}
        }

        Ok(())
    }));

    let mut inline_script = None;
    handlers.push(text!("script", move |t| {
        use base64::{Engine, prelude::BASE64_STANDARD};
        use sha2::{Digest, Sha256};

        let (text, location) =
            inline_script.get_or_insert_with(|| (String::new(), t.source_location().bytes().start));

        text.push_str(t.as_str());
        t.remove();

        if t.last_in_text_node() {
            let mut hasher = Sha256::new();
            hasher.update(text.as_bytes());
            let hash_result = hasher.finalize();
            let b64_hash = BASE64_STANDARD.encode(hash_result);
            let csp_hash = format!("sha256-{}", b64_hash);

            let start = *location;
            let end = t.source_location().bytes().end;

            if !policy.html.allow_scripts.iter().any(|allowed| {
                if let AllowedScript::Sha(allowed) = allowed {
                    csp_hash == *allowed
                } else {
                    false
                }
            }) && let Some(replace) =
                policy
                    .html
                    .dangerous_scripts
                    .handle(csp_hash, start..end, logger)?
            {
                t.replace(&replace, ContentType::Text);
            } else {
                t.replace(text, ContentType::Text);
            }

            inline_script = None;
        }
        Ok(())
    }));

    let mut inline_style = None;
    handlers.push(text!("style", move |t| {
        let mut state = state_2.lock();

        let (text, location) =
            inline_style.get_or_insert_with(|| (String::new(), t.source_location().bytes().start));

        text.push_str(t.as_str());
        t.remove();

        if t.last_in_text_node() {
            let (css, mut subresources) = crate::resources::css::sanitize(
                text,
                &state.base,
                &logger.inner_content(*location),
                policy,
            )?;
            t.replace(&css, ContentType::Text);
            state.subresources.append(&mut subresources);

            inline_style = None;
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
        rules::{self, DangerousDomain2, ReplaceRule},
    };

    fn rewrite_html(input: &[u8], policy: &Policy) -> (CrawlerState, Vec<u8>) {
        let mut output = Vec::new();
        let mut state = CrawlerState {
            base: Url::parse("https://localhost").unwrap(),
            subresources: Vec::new(),
        };

        let mut rewriter = create_rewriter(&NullLogger, policy, &mut state, &mut output);
        rewriter.write(input).unwrap();
        rewriter.end().unwrap();

        (state, output)
    }

    #[test]
    fn test_event_handler_stripping() {
        let policy = Policy::default();

        let input = b"<button onclick=\"alert(1)\" class=\"btn\" ONLOAD=\"doSomething()\">Click me</button>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<button class=\"btn\">Click me</button>");
    }

    #[test]
    fn test_event_handler_replacement() {
        let mut policy = Policy::default();
        policy.html.event_handlers = ReplaceRule::new(
            rules::EventHandlers::new("alert('blocked')"),
            LogLevel::Info,
        );

        let input = b"<button onclick=\"alert(1)\"></button>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<button onclick=\"alert('blocked')\"></button>");
    }

    #[test]
    fn test_event_handler_ignore() {
        let mut policy = Policy::default();
        policy.html.event_handlers = ReplaceRule::keep(LogLevel::Trace);

        let input = b"<button onclick=\"alert(1)\"></button>";
        let (_, output) = rewrite_html(input, &policy);
        assert_eq!(output, input);
    }

    #[test]
    fn test_script_src_allowed() {
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec!["trusted.com".parse().unwrap()];

        let input = b"<script src=\"https://trusted.com/lib.js\"></script>";
        let (_, output) = rewrite_html(input, &policy);

        let result = String::from_utf8(output).unwrap();
        assert!(result.contains("<script src=\"sub_"));
    }

    #[test]
    fn test_script_src_blocked() {
        let mut policy = Policy::default();
        policy.resources.fetch_sub_resources = false;
        policy.html.allow_scripts = vec!["trusted.com".parse().unwrap()];
        policy.html.dangerous_scripts = ReplaceRule::with_default(LogLevel::Warn);

        let input = b"<script src=\"https://untrusted.com/lib.js\"></script>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<script src=\"#\"></script>");
    }

    #[test]
    fn test_script_inline_allowed() {
        let mut policy = Policy::default();
        policy.html.allow_scripts = vec![
            "sha256-bhHHL3z2vDgxUt0W3dWQOrprscmda2Y5pLsLg4GF+pI="
                .parse()
                .unwrap(),
        ];

        let input = b"<script>alert(1)</script>";
        let (_, output) = rewrite_html(input, &policy);
        assert_eq!(output, input);
    }

    #[test]
    fn test_script_inline_blocked() {
        let mut policy = Policy::default();
        policy.html.dangerous_scripts = ReplaceRule::with_default(LogLevel::Warn);

        let input = b"<script>alert(1)</script>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<script>#</script>");
    }

    #[test]
    fn test_dangerous_uris_sanitization() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris = ReplaceRule::with_default(LogLevel::Info);

        let input = b"<a href=\"javascript:alert(1)\" src=\"  data:text/html,malicious  \" data-url=\"other\">link</a>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output,
            "<a href=\"#\" src=\"#\" data-url=\"other\">link</a>"
        );
    }

    #[test]
    fn test_dangerous_uris_bypass_whitespace() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris =
            ReplaceRule::new(rules::DangerousUris::new(""), LogLevel::Info);

        let input = b"<a href=\"\n\t javascript:alert(1)\">link</a>";
        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<a>link</a>");
    }

    #[test]
    fn test_dangerous_uris_ignore() {
        let mut policy = Policy::default();
        policy.html.dangerous_uris = ReplaceRule::keep(LogLevel::Trace);

        let input = b"<a href=\"javascript:alert(1)\">link</a>";
        let (_, output) = rewrite_html(input, &policy);
        assert_eq!(output, input);
    }

    #[test]
    fn test_idn_rewriting() {
        let mut policy = Policy::default();
        policy.resources.fetch_sub_resources = false;

        let input = b"<a href=\"http://googl\xC3\xA9.com\">Link</a>";

        // Case 1: IDN is Warn. It should preserve the link.
        policy.urls.idn = ReplaceRule::keep(LogLevel::Warn);

        let (_, output) = rewrite_html(input, &policy);
        assert_eq!(output, input);

        // Case 2: IDN is Warn with rewriting enabled. It should rewrite to "#".
        policy.urls.idn = ReplaceRule::with_default(LogLevel::Warn);

        let (_, output) = rewrite_html(input, &policy);
        let output = String::from_utf8(output).unwrap();
        assert_eq!(output, "<a href=\"#\">Link</a>");
    }

    #[test]
    fn test_iframe_object_origin_filtering() {
        let mut policy = Policy::default();
        // policy.html.allow_origins defaults to ["trusted.com"]
        policy.resources.fetch_sub_resources = false;
        policy.html.dangerous_origins = ReplaceRule::with_default(LogLevel::Warn);

        let input = b"<div>\
            <iframe src=\"https://trusted.com/page.html\"></iframe>\
            <iframe src=\"https://untrusted.com/page.html\"></iframe>\
            <object data=\"https://trusted.com/data.bin\"></object>\
            <object data=\"https://untrusted.com/data.bin\"></object>\
        </div>";

        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output,
            "<div>\
                <iframe src=\"https://trusted.com/page.html\"></iframe>\
                <iframe src=\"#\"></iframe>\
                <object data=\"https://trusted.com/data.bin\"></object>\
                <object data=\"#\"></object>\
            </div>"
        );
    }

    #[test]
    fn test_meta_refresh_removal() {
        let policy = Policy::default();
        let input = b"<html>\
            <head>\
                <meta charset=\"utf-8\">\
                <meta http-equiv=\"refresh\" content=\"5;url=https://trusted.com\">\
            </head>\
        </html>";

        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output,
            "<html>\
                <head>\
                    <meta charset=\"utf-8\">\
                </head>\
            </html>"
        );
    }

    #[test]
    fn test_broadened_url_extraction() {
        let mut policy = Policy::default();
        policy.resources.fetch_sub_resources = true;

        let input = b"<div>\
            <form action=\"https://trusted.com/submit\"></form>\
            <area href=\"https://trusted.com/map\"></area>\
            <audio src=\"https://trusted.com/song.mp3\"></audio>\
            <video src=\"https://trusted.com/movie.mp4\"></video>\
            <embed src=\"https://trusted.com/app.swf\"></embed>\
            <track src=\"https://trusted.com/sub.vtt\"></track>\
            <input src=\"https://trusted.com/btn.png\"></input>\
        </div>";

        let (state, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        // form and area are NOT sub-resources, so they should keep their original/resolved URLs
        // audio, video, embed, track, input ARE sub-resources, so they should be rewritten to local names
        assert_eq!(
            output,
            "<div>\
                <form action=\"https://trusted.com/submit\"></form>\
                <area href=\"https://trusted.com/map\"></area>\
                <audio src=\"sub_bae1797ac4ee235d.mp3\"></audio>\
                <video src=\"sub_e9926d606072a395.mp4\"></video>\
                <embed src=\"sub_217fd05b2d3da13b.swf\"></embed>\
                <track src=\"sub_74849781ede8f42b.vtt\"></track>\
                <input src=\"sub_006621e470212fda.png\"></input>\
            </div>"
        );

        assert_eq!(state.subresources.len(), 5);
    }

    #[test]
    fn test_flexible_action_handling_deny_remove() {
        let mut policy = Policy::default();
        policy.html.dangerous_domain = ReplaceRule::new(DangerousDomain2::new(""), LogLevel::Warn);
        // allow_origins contains trusted.com

        let input = b"<div>\
            <a href=\"https://evil.com/malicious\">Link</a>\
            <form action=\"https://evil.com/submit\"></form>\
        </div>";

        let (_, output) = rewrite_html(input, &policy);

        let output = String::from_utf8(output).unwrap();
        // Both the anchor href and form action point to a dangerous domain.
        assert_eq!(
            output,
            "<div>\
                <a>Link</a>\
                <form></form>\
            </div>"
        );
    }
}
