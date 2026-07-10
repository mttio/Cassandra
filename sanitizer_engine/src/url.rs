use itertools::Itertools;
use url::{Host, Url};

pub fn check_domain(url: &Url) -> Option<String> {
    if let Some(Host::Domain(domain, original)) = url.host()
        && domain != original
    {
        let domain = Iterator::zip(domain.split('.'), original.split('.'))
            .map(|(parsed, original)| {
                if let Some(parsed) = parsed.strip_prefix("xn--") {
                    let mut result = String::new();
                    let mut original = original.chars();

                    'outer: for p in parsed.chars() {
                        for o in original.by_ref() {
                            if o == p {
                                result.push(o);
                                continue 'outer;
                            } else if o.to_ascii_lowercase() == p {
                                result.push_str("\x1b[95;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");
                                continue 'outer;
                            } else {
                                result.push_str("\x1b[91;1m");
                                result.push(o);
                                result.push_str("\x1b[0m");
                            }
                        }
                    }
                    result
                } else {
                    let mut result = String::new();

                    for o in original.chars() {
                        if o.is_ascii_uppercase() {
                            result.push_str("\x1b[95;1m");
                            result.push(o);
                            result.push_str("\x1b[0m");
                        } else {
                            result.push(o);
                        }
                    }
                    result
                }
            })
            .join(".");

        Some(domain)
    } else {
        None
    }
}

/// Checks if a given host matches a host specified in the policy
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
