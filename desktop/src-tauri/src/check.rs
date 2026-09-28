//! Замер связи с компьютера при обрыве (29.09, владелец: «причину ставим только по замерам с устройства»).
//! Путь VPN объявлен мёртвым -> не чаще раза в 10 мин приложение само меряет адреса из /api/check/targets НАПРЯМУЮ (мимо
//! системного прокси): загрузка 256 КБ с каждого сервера + российский контроль. Итог - POST /api/check/result (src=desktop);
//! не отправилось напрямую - через системный прокси; совсем не отправилось - повтор в следующий раз (один последний замер).
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const MIN_GAP_MS: u64 = 10 * 60 * 1000;
static LAST: AtomicU64 = AtomicU64::new(0);
static PENDING: Mutex<Option<Value>> = Mutex::new(None);

fn fallback() -> Vec<(String, String, u64)> {
    vec![
        ("nl1-256k".into(), "https://vpn.insellers.su/probe/256k".into(), 262144),
        ("nl2-256k".into(), "https://n2.insellers.su/probe/256k".into(), 262144),
        ("ru-control".into(), "https://yandex.ru/favicon.ico".into(), 0),
    ]
}

async fn targets(c: &reqwest::Client) -> Vec<(String, String, u64)> {
    if let Ok(r) = c.get(format!("{}/api/check/targets", crate::BASE)).send().await {
        if let Ok(v) = r.json::<Value>().await {
            let out: Vec<(String, String, u64)> = v["targets"].as_array().map(|a| a.iter().filter_map(|t| {
                let id = t["id"].as_str()?.to_string();
                let url = t["url"].as_str()?.to_string();
                if id.is_empty() || !url.starts_with("https://") { return None; }
                Some((id, url, t["bytes"].as_u64().unwrap_or(0)))
            }).take(8).collect()).unwrap_or_default();
            if !out.is_empty() { return out; }
        }
    }
    fallback()
}

async fn measure(c: &reqwest::Client, id: &str, url: &str, want: u64) -> Value {
    let t0 = Instant::now();
    let mut got: u64 = 0;
    let res = async {
        let mut r = c.get(url).send().await.map_err(|e| if e.is_timeout() { "timeout".to_string() } else { "io".to_string() })?;
        let code = r.status().as_u16();
        if !(200..400).contains(&code) { return Err(format!("http {code}")); }
        while t0.elapsed() < Duration::from_secs(20) {
            match r.chunk().await {
                Ok(Some(b)) => got += b.len() as u64,
                Ok(None) => break,
                Err(e) => return Err(if e.is_timeout() { "timeout".into() } else { "io".into() }),
            }
        }
        Ok(())
    }.await;
    let ms = t0.elapsed().as_millis() as u64;
    match res {
        Ok(()) if want == 0 || got >= want => json!({"id": id, "ok": true, "ms": ms, "bytes": got, "err": ""}),
        Ok(()) => json!({"id": id, "ok": false, "ms": ms, "bytes": got, "err": "short"}),
        Err(e) => json!({"id": id, "ok": false, "ms": ms, "bytes": got, "err": e}),
    }
}

async fn post(body: &Value) -> bool {
    for direct in [true, false] {
        let b = reqwest::Client::builder().timeout(Duration::from_secs(8));
        let b = if direct { b.no_proxy() } else { b };
        if let Ok(c) = b.build() {
            if c.post(format!("{}/api/check/result", crate::BASE)).json(body).send().await
                .map(|r| r.status().is_success()).unwrap_or(false) { return true; }
        }
    }
    false
}

/// Запустить замер в фоне, если с прошлого прошло >= 10 мин.
pub fn maybe_run(reason: &str) {
    let now = crate::now_ms();
    if now.saturating_sub(LAST.load(Ordering::SeqCst)) < MIN_GAP_MS { return; }
    LAST.store(now, Ordering::SeqCst);
    let reason = reason.to_string();
    tauri::async_runtime::spawn(async move {
        let c = match reqwest::Client::builder().no_proxy().connect_timeout(Duration::from_secs(8))
            .timeout(Duration::from_secs(25)).build() { Ok(c) => c, Err(_) => return };
        let mut results = Vec::new();
        for (id, url, want) in targets(&c).await { results.push(measure(&c, &id, &url, want).await); }
        let body = json!({"src": "desktop", "dev": crate::install_id(), "reason": reason, "results": results});
        let prev = PENDING.lock().ok().and_then(|mut p| p.take());
        if let Some(p) = prev {
            if !post(&p).await { if let Ok(mut g) = PENDING.lock() { *g = Some(p); } }
        }
        if !post(&body).await { if let Ok(mut g) = PENDING.lock() { *g = Some(body.clone()); } }
        crate::remote_log("vpn.check_run", json!({"reason": reason, "results": results}));
    });
}
