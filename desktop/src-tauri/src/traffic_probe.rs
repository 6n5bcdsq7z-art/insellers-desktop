//! A listening core, an HTTP error page or a 204 response is not useful traffic.
use std::time::{Duration, Instant};

pub async fn check(port: u16, bytes: u64, budget: Duration) -> (bool, u64, u64, String) {
    let size = if bytes <= 32_768 { "32k" } else { "256k" };
    let primary = format!("https://vpn.insellers.su/probe/{size}");
    let fallback = format!("https://speed.cloudflare.com/__down?bytes={bytes}");
    check_urls(port, bytes, budget, &[&primary, &fallback]).await
}

/// All requests use the explicit local core; there is no direct-network fallback.
/// The second independent HTTPS origin avoids treating our probe's outage as a
/// dead tunnel. One deadline covers headers AND the streamed response bodies.
pub(crate) async fn check_urls(
    port: u16, want: u64, budget: Duration, urls: &[&str],
) -> (bool, u64, u64, String) {
    let started = Instant::now();
    let elapsed = || started.elapsed().as_millis() as u64;
    let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
        .and_then(|proxy| reqwest::Client::builder().no_proxy().proxy(proxy)
            .redirect(reqwest::redirect::Policy::none()).build()) {
        Ok(client) => client,
        Err(_) => return (false, 0, elapsed(), "io".into()),
    };
    let mut reason = String::from("timeout");
    let mut most_bytes = 0;
    for (index, url) in urls.iter().enumerate() {
        let remaining = budget.saturating_sub(started.elapsed());
        if remaining.is_zero() { break; }
        let timeout = remaining / ((urls.len() - index) as u32);
        let mut response = match client.get(*url).timeout(timeout)
            .header("Cache-Control", "no-cache").send().await {
            Ok(response) => response,
            Err(error) => {
                reason = if error.is_connect() { "core" } else if error.is_timeout() { "timeout" } else { "io" }.into();
                continue;
            }
        };
        if response.status().as_u16() != 200 {
            reason = format!("http {}", response.status().as_u16());
            continue;
        }
        let mut got = 0u64;
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    got = got.saturating_add(chunk.len() as u64);
                    if got >= want { return (true, got, elapsed(), String::new()); }
                }
                Ok(None) => { reason = "short".into(); break; }
                Err(error) => {
                    reason = if error.is_timeout() { "timeout" } else { "io" }.into();
                    break;
                }
            }
        }
        most_bytes = most_bytes.max(got);
    }
    (false, most_bytes, elapsed(), reason)
}
