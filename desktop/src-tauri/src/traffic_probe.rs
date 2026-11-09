//! A listening core, an HTTP error page or a 204 response is not useful traffic.
use std::time::{Duration, Instant};
use std::sync::atomic::{AtomicU64, Ordering};

pub async fn check(port: u16, bytes: u64, budget: Duration) -> (bool, u64, u64, String) {
    let size = if bytes <= 32_768 { "32k" } else { "256k" };
    let primary = format!("https://vpn.insellers.su/probe/{size}");
    let fallback = format!("https://speed.cloudflare.com/__down?bytes={bytes}");
    check_urls(port, bytes, budget, &[&primary, &fallback]).await
}

/// After the helper installs its routes, use the OS route rather than the local
/// proxy. This is a separate check: a working proxy does not prove TUN/DNS works.
pub async fn check_routed(bytes: u64, budget: Duration) -> (bool, u64, u64, String) {
    let size = if bytes <= 32_768 { "32k" } else { "256k" };
    let primary = format!("https://vpn.insellers.su/probe/{size}");
    let fallback = format!("https://speed.cloudflare.com/__down?bytes={bytes}");
    check_routed_urls(bytes, budget, &[&primary, &fallback]).await
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
