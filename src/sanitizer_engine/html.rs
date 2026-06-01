use std::io::Write;

use lol_html::{
    element,
    send::{HtmlRewriter, Settings},
};
use url::Url;

use crate::sanitizer_engine::{
    errors::{DangerousDomainInHtml, EventHandler},
    log::Logger,
    policy::Policy,
    url::RuleMatch,
};

pub fn create_rewriter<'a, W: Write>(
    logger: &'a Logger,
    policy: &'a Policy,
    mut output: W,
) -> HtmlRewriter<'a, impl FnMut(&[u8])> {
    HtmlRewriter::new(
        Settings {
            element_content_handlers: vec![
                element!("a[href], link[href]", move |el| {
                    let href = el.get_attribute("href").expect("href was required");
                    if let Ok(href) = Url::parse(&href)
                        && let Some(host) = href.host()
                    {
                        let host = host.to_owned();
                        let is_dangerous = policy
                            .urls
                            .dangerous_domains
                            .iter()
                            .any(|x| x.0.matches(&host));

                        let location = el.source_location();

                        if is_dangerous {
                            let _ = policy.html.dangerous_domain.handle(
                                logger,
                                |x| el.set_attribute("href", x),
                                DangerousDomainInHtml(host.to_owned(), location.bytes().start),
                            )?;
                        }
                    }

                    Ok(())
                }),
                element!("*", move |el| {
                    let mut to_remove = Vec::new();
                    for attribute in el.attributes() {
                        let name = attribute.name();
                        if name.starts_with("on") {
                            let clone = name.clone();
                            policy.html.event_handlers.handle(
                                logger,
                                |x| to_remove.push(clone),
                                EventHandler(
                                    name,
                                    attribute.name_source_location().map(|x| x.bytes().start),
                                ),
                            )?;
                        }
                    }

                    for name in to_remove {
                        el.remove_attribute(&name);
                    }

                    Ok(())
                }),
            ],
            ..Settings::new_send()
        },
        move |c: &[u8]| {
            // println!("{}\n", str::from_utf8(c).unwrap());
            output.write_all(c).unwrap();
        },
    )
}
