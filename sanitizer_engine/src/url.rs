use url::{Host, Url};

/// Detects if a `Url` host was originally an [Internationalized Domain Name](https://en.wikipedia.org/wiki/Internationalized_domain_name) (the `url` crate automatically performs the conversion)
/// If so, returns:
/// - the original host name
/// - the punycode-converted host name
pub fn detect_idn(url: &Url) -> Option<(&str, &str)> {
    if let Some(Host::Domain(domain, original)) = url.host()
        && domain != original
    {
        Some((original, domain))
    } else {
        None
    }
}

/// Checks if a given host matches a host specified in the policy
/// Ignores prefix labels (e.g. `wikipedia.org` matches `www.wikipedia.org`)
pub fn host_matches(host: &Host, target: &Host) -> bool {
    match (host, target) {
        (Host::Domain(host, _), Host::Domain(target, _)) => {
            let Some(prefix) = host.strip_suffix(target) else {
                return false;
            };

            prefix.is_empty() || prefix.ends_with('.')
        }
        (Host::Ipv4(a), Host::Ipv4(b)) => a == b,
        (Host::Ipv6(a), Host::Ipv6(b)) => a == b,
        _ => false,
    }
}

pub fn is_dangerous_uri(uri: &str) -> bool {
    uri.starts_with("data:") || uri.starts_with("javascript:")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_idn() {
        let hosts = [
            ("wikipedia.org", None),
            ("wіkіреdіа.org", Some("xn--wkd-8cdx9d7hbd.org")),
            ("рф", Some("xn--p1ai")),
            ("Bücher.example", Some("xn--bcher-kva.example")),
        ];

        for (original, expected) in hosts {
            let url = Url::parse(&format!("https://{original}")).unwrap();
            let actual = super::detect_idn(&url);
            assert_eq!(actual, expected.map(|x| (original, x)));
        }
    }

    #[test]
    fn host_matches() {
        let hosts = [
            ("www.wikipedia.org", "wikipedia.org", true),
            ("www.wikipedia.org", "org", true),
            ("www.wikipedia.org", ".org", false),
            ("google.com", "youtube.com", false),
        ];

        for (left, right, result) in hosts {
            let left = Host::parse(left).unwrap();
            let right = Host::parse(right).unwrap();

            assert_eq!(super::host_matches(&left, &right), result);
        }
    }
}
