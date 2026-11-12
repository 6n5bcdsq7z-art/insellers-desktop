//! A listening core, an HTTP error page or a 204 response is not useful traffic.
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

pub async fn check(port: u16, bytes: u64, budget: Duration) -> (bool, u64, u64, String) {
    let urls = proxy_targets(bytes);
    check_urls(port, bytes, budget, &[&urls[0], &urls[1]]).await
}

fn proxy_targets(bytes: u64) -> [String; 2] {
    let size = if bytes <= 32_768 { "32k" } else { "256k" };
    [format!("https://vpn.insellers.su/probe/{size}"),
     format!("https://speed.cloudflare.com/__down?bytes={bytes}")]
}

/// A timed-out bulk transfer is still a failed bulk check. Before tearing down
/// a path that transferred useful bytes, verify a new complete small transfer
/// through that same core. No direct-network or HTTP-error fallback is allowed.
pub(crate) async fn partial_timeout_is_slow(port: u16, received: u64, reason: &str) -> bool {
    let urls = proxy_targets(32_768);
    partial_timeout_is_slow_urls(port, received, reason, Duration::from_secs(8), &[&urls[0], &urls[1]]).await
}

pub(crate) async fn partial_timeout_is_slow_urls(port: u16, received: u64, reason: &str,
    budget: Duration, urls: &[&str]) -> bool {
    if reason != "timeout" || received < 32_768 { return false; }
    check_urls(port, 32_768, budget, urls).await.0
}

/// After the helper installs its routes, use the OS route rather than the local
/// proxy. This is a separate check: a working proxy does not prove TUN/DNS works.
pub async fn check_routed(bytes: u64, budget: Duration) -> (bool, u64, u64, String) {
    let urls = routed_targets(bytes);
    check_routed_urls(bytes, budget, &[&urls[0], &urls[1]]).await
}

fn routed_targets(bytes: u64) -> [String; 2] {
    // Management addresses are deliberately excluded from TUN. Their success
    // cannot prove that ordinary system DNS and internet traffic use the VPN.
    [format!("https://speed.cloudflare.com/__down?bytes={bytes}"),
     "https://proof.ovh.net/files/1Mb.dat".into()]
}

#[cfg(test)]
mod tests {
    #[test]
    fn system_tunnel_gate_uses_independent_non_exempt_https_origins() {
        for bytes in [32_768, 262_144] {
            let urls=super::routed_targets(bytes);
            let hosts:Vec<_>=urls.iter().map(|u| {
                let u=reqwest::Url::parse(u).unwrap();
                assert_eq!(u.scheme(), "https");
                let host=u.host_str().unwrap().to_string();
                assert!(host.parse::<std::net::IpAddr>().is_err());
                assert!(host!="insellers.su" && !host.ends_with(".insellers.su"));
                host
            }).collect();
            assert_ne!(hosts[0],hosts[1]);
        }
    }
}

pub(crate) async fn check_routed_urls(want: u64, budget: Duration, urls: &[&str]) -> (bool, u64, u64, String) {
    let client = reqwest::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none()).build();
    match client {
        Ok(client) => read_urls(client, want, budget, urls).await,
        Err(_) => (false, 0, 0, "io".into()),
    }
}

/// All requests use the explicit local core; there is no direct-network fallback.
/// The second independent HTTPS origin avoids treating our probe's outage as a
/// dead tunnel. One deadline covers headers AND the streamed response bodies.
pub(crate) async fn check_urls(
    port: u16, want: u64, budget: Duration, urls: &[&str],
) -> (bool, u64, u64, String) {
    let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
        .and_then(|proxy| reqwest::Client::builder().no_proxy().proxy(proxy)
            .redirect(reqwest::redirect::Policy::none()).build()) {
        Ok(client) => client,
        Err(_) => return (false, 0, 0, "io".into()),
    };
    read_urls(client, want, budget, urls).await
}

// Keep the primary alive for the full shared deadline. After a short hedge
// delay, race the independent origin through the same route. Dropping the
// losing future closes its in-flight request; no detached probe survives.
async fn read_urls(client: reqwest::Client, want: u64, budget: Duration, urls: &[&str]) -> (bool, u64, u64, String) {
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + budget;
    let Some((primary, rest)) = urls.split_first() else {
        return (false, 0, 0, "timeout".into());
    };
    let most_bytes = AtomicU64::new(0);
    let first = read_origin(&client, primary, want, budget, &most_bytes);
    tokio::pin!(first);
    if rest.is_empty() { return first.await; }
    let hedge = budget.div_f64(4.0).min(Duration::from_secs(1));
    let fallback = async {
        let mut result = (false, 0, 0, "timeout".into());
        for url in rest {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            if left.is_zero() { break; }
            result = read_origin(&client, url, want, left, &most_bytes).await;
            if result.0 { return result; }
        }
        result.1 = most_bytes.load(Ordering::Relaxed);
        result
    };
    let race = async {
        tokio::select! {
            result = &mut first => {
                if result.0 { result } else {
                    let mut next = fallback.await;
                    if !next.0 { next.1 = next.1.max(result.1); }
                    next
                }
            },
            _ = tokio::time::sleep(hedge) => {
                tokio::pin!(fallback);
                tokio::select! {
                    result = &mut first => {
                        if result.0 { result } else {
                            let mut next = fallback.await;
                            if !next.0 { next.1 = next.1.max(result.1); }
                            next
                        }
                    },
                    result = &mut fallback => {
                        if result.0 { result } else {
                            let mut next = first.await;
                            if !next.0 { next.1 = next.1.max(result.1); }
                            next
                        }
                    },
                }
            },
        }
    };
    let mut result = tokio::time::timeout_at(deadline, race).await
        .unwrap_or_else(|_| (false, most_bytes.load(Ordering::Relaxed), 0, "timeout".into()));
    result.2 = started.elapsed().as_millis() as u64;
    result
}

async fn read_origin(client: &reqwest::Client, url: &str, want: u64, budget: Duration, most_bytes: &AtomicU64) -> (bool, u64, u64, String) {
    let started = Instant::now();
    let elapsed = || started.elapsed().as_millis() as u64;
    let mut response = match client.get(url).timeout(budget)
        .header("Cache-Control", "no-cache").send().await {
        Ok(response) => response,
        Err(error) => return (false, 0, elapsed(),
            if error.is_timeout() { "timeout" } else if error.is_connect() { "core" } else { "io" }.into()),
    };
    if response.status().as_u16() != 200 {
        return (false, 0, elapsed(), format!("http {}", response.status().as_u16()));
    }
    let mut got = 0u64;
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                got = got.saturating_add(chunk.len() as u64);
                most_bytes.fetch_max(got, Ordering::Relaxed);
                if got >= want { return (true, got, elapsed(), String::new()); }
            }
            Ok(None) => return (false, got, elapsed(), "short".into()),
            Err(error) => return (false, got, elapsed(), if error.is_timeout() { "timeout" } else { "io" }.into()),
        }
    }
}
