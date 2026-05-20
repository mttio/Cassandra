use crate::sanitizer_engine::engine_structs::{Content, InputSource};
use anyhow::{anyhow, Context, Result};
use hickory_resolver::TokioResolver;
use reqwest::{Client, redirect, header};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::time::Duration;
use futures_util::StreamExt;





/*================== HELPERS ===================*/

/// Validates if an IP address is safe
fn is_safe_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !v4.is_loopback() && 
            !v4.is_private() && 
            !v4.is_link_local() && 
            !v4.is_multicast() && 
            !v4.is_broadcast() && 
            !v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            !v6.is_loopback() && 
            !is_v6_private(v6) && 
            !v6.is_multicast() && 
            !v6.is_unspecified()
        }
    }
}

/// Helper func to check if an IPv6 address is in private/local range
fn is_v6_private(v6: Ipv6Addr) -> bool {
    // Unique Local Address (fc00::/7)
    (v6.segments()[0] & 0xfe00) == 0xfc00 ||
    // Link Local (fe80::/10)
    (v6.segments()[0] & 0xffc0) == 0xfe80
}







/*================== MAIN FUNCTIONS ===================*/



/// Fetch multiple URLs and return their content
pub async fn fetch_urls(sources: Vec<InputSource>) -> Result<(Vec<Content>,Vec<anyhow::Error>)> {
    let mut results_vec = Vec::new();
    let mut errors_vec = Vec::<anyhow::Error>::new();

    for input_source in sources {
        if let InputSource::Url(url) = input_source {
            match fetch_url(&url).await {
                Ok(res) => results_vec.push(res),
                Err(e) => errors_vec.push(anyhow!("Could not fetch url {:?}: {}", url, e)),
            }
        }
    }
    Ok((results_vec,errors_vec))
}

/// Fetch a single URL with strict security controls (Anti-SSRF, Timeouts, Limits)
async fn fetch_url(url: &url::Url) -> Result<Content> {
    // Passo 2: Risoluzione DNS manuale e isolata
    let resolver = TokioResolver::builder_tokio()
        .context("Failed to create DNS resolver builder")?
        .build(); // This returns a Resolver in some versions, or Result in others.
    
    // The previous error showed it returns a Result.
    let resolver = resolver.map_err(|e| anyhow!("Failed to build resolver: {}", e))?;

    let host = url.host_str().ok_or_else(|| anyhow!("No host in URL"))?;
    
    // We lookup the IP addresses for the host
    let lookup = resolver.lookup_ip(host).await
        .with_context(|| format!("DNS lookup failed for {}", host))?;

    // Passo 3: Validazione dell'IP (Il "Filtro" Anti-SSRF)
    let safe_ip = lookup.iter()
        .find(|ip| is_safe_ip(*ip))
        .ok_or_else(|| anyhow!("No safe (public) IP addresses found for host: {}", host))?;

    // Configurazione della Connessione, Timeouts e Redirects
    let port = url.port_or_known_default().unwrap_or(80);
    let socket_addr = SocketAddr::new(safe_ip, port);

    let client = Client::builder()
        // Force IP to prevent IP reassigning
        .resolve(host, socket_addr)
        // Set connection timeout
        .connect_timeout(Duration::from_secs(3))
        // Set overall timeout
        .timeout(Duration::from_secs(30))
        // Policy sui Redirect
        .redirect(redirect::Policy::none())
        // Forzatura TLS 1.2+
        .min_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()?;

    let response = client.get(url.clone())
        .header(header::HOST, host)
        .send()
        .await
        .with_context(|| format!("Failed to send request to {}", url))?;

    if !response.status().is_success() {
        return Err(anyhow!("Server returned error status: {}", response.status()));
    }

    let content_type = response.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Streaming del Body con Limite di Byte (Max 5 MB)
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();
    let max_bytes = 5 * 1024 * 1024; 

    while let Some(item) = stream.next().await {
        let chunk = item.context("Error while streaming body")?;
        if data.len() + chunk.len() > max_bytes {
            return Err(anyhow!("Response body exceeds maximum size limit of {} bytes", max_bytes));
        }
        data.extend_from_slice(&chunk);
    }

    Ok(Content {
        source: InputSource::Url(url.clone()),
        data,
        content_type,
    })
}










/*================== TESTS ===================*/




#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_is_safe_ip_v4() {
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(!is_safe_ip(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(is_safe_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(is_safe_ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
    }

    #[test]
    fn test_is_safe_ip_v6() {
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))); // ::1
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)))); // ULA
        assert!(!is_safe_ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))); // Link-local
        assert!(is_safe_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)))); // Google DNS
    }
}
