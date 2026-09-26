//! Замеры связи для центра диагностики (26.09.2026) - как на Android (AppProbe.kt).
//! Пока VPN включён: через 2 мин после подключения и дальше раз в 60 мин (время прошлого замера - файл probe_last).
//! В фоне, без уведомлений; на Маке в режиме энергосбережения (Low Power Mode) пропускаем. Мимо туннеля: прямые сокеты
//! процесса (системный прокси их не касается). Для каждого сервера и пути из плана (/api/app/probe-plan): TCP + TLS-рукопожатие
//! на IP:443 с SNI-прикрытием протокола и чтение 64 КБ ответа (обрыв ТСПУ на ~16 КБ виден по kb). ≤ 30 с и ≤ 1 МБ за раунд.
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn one(t: &Value, want: usize, deadline: Instant) -> Value {
    let t0 = Instant::now();
    let mut got = 0usize;
    let mut hs: Option<u128> = None;
    let left = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_secs(1)).min(Duration::from_secs(10));
    let res: Result<(), String> = (|| {
        let ip: IpAddr = t["ip"].as_str().unwrap_or("").parse().map_err(|_| "плохой адрес".to_string())?;
        let port = t["port"].as_u64().unwrap_or(443) as u16;
        let tcp = TcpStream::connect_timeout(&SocketAddr::new(ip, port), left()).map_err(|e| e.to_string())?;
        tcp.set_read_timeout(Some(left())).ok();
        tcp.set_write_timeout(Some(left())).ok();
        let sni = t["sni"].as_str().unwrap_or("").to_string();
        let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|e| e.to_string())?
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = rustls::pki_types::ServerName::try_from(sni.clone()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(Arc::new(cfg), name).map_err(|e| e.to_string())?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() {
            s.conn.complete_io(&mut s.sock).map_err(|e| e.to_string())?;
        }
        hs = Some(t0.elapsed().as_millis());
        let req = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15\r\nAccept: text/html,*/*\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
            t["req"].as_str().unwrap_or("/"), sni);
        s.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = [0u8; 16384];
        while got < want && Instant::now() < deadline {
            s.sock.set_read_timeout(Some(left())).ok();
            let cap = (want - got).min(buf.len());
            match s.read(&mut buf[..cap]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => { if got > 0 { break; } return Err(e.to_string()); }
            }
        }
        Ok(())
    })();
    let mut r = json!({
        "server": t["server"].as_str().unwrap_or(""), "path": t["path"].as_str().unwrap_or(""),
        "ok": res.is_ok() && got >= want, "ms": t0.elapsed().as_millis() as u64,
        "kb": ((got as f64) / 102.4).round() / 10.0,
    });
    if let Some(h) = hs { r["hs_ms"] = json!(h as u64); }
    match res {
        Err(e) => r["err"] = json!(e.chars().take(150).collect::<String>()),
        Ok(()) if got < want => r["err"] = json!(format!("прочитано {} КБ из {}", got / 1024, want / 1024)),
        _ => {}
    }
    r
}

fn low_power() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("pmset").arg("-g").output() {
            let s = String::from_utf8_lossy(&o.stdout);
            return s.lines().any(|l| l.trim_start().starts_with("lowpowermode") && l.trim_end().ends_with('1'));
        }
    }
    false
}

/// Один раунд: план с сервера → замеры в отдельных потоках → отчёт.
pub async fn run_once(token: String) {
    if token.is_empty() || low_power() { return; }
    // мимо системного прокси (он же туннель): иначе сервер видит IP нашего сервера, а не провайдера человека
    let client = match reqwest::Client::builder().no_proxy().user_agent(format!("InsellersVPN/desktop-{}", env!("CARGO_PKG_VERSION")))
        .build() { Ok(c) => c, Err(_) => return };
    let plan: Value = match client.get(format!("{}/api/app/probe-plan", crate::BASE)).header("X-App-Token", &token)
        .timeout(Duration::from_secs(15)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
        _ => return,
    };
    if !plan["enabled"].as_bool().unwrap_or(true) { return; }
    let targets: Vec<Value> = plan["targets"].as_array().cloned().unwrap_or_default();
    let secs = plan["timeout_s"].as_u64().unwrap_or(30).clamp(5, 30);
    let mut budget = plan["max_bytes"].as_u64().unwrap_or(1_048_576).min(1_048_576) as usize;
    let results: Vec<Value> = tauri::async_runtime::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(secs);
        let hs: Vec<_> = targets.into_iter().filter_map(|t| {
            let want = (t["bytes"].as_u64().unwrap_or(65536) as usize).min(65536).min(budget);
            if want == 0 { return None; }
            budget -= want;
            Some(std::thread::spawn(move || one(&t, want, deadline)))
        }).collect();
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    }).await.unwrap_or_default();
    let body = json!({"net": "", "device": format!("ins-{}", crate::install_id()), "platform": "desktop",
                      "version": env!("CARGO_PKG_VERSION"), "results": results});
    let _ = client.post(format!("{}/api/app/probe", crate::BASE)).header("X-App-Token", &token)
        .timeout(Duration::from_secs(15)).json(&body).send().await;
}

/// Нужно ли мерить сейчас (раз в 60 мин; переподключения не учащают).
pub fn due(dir: &std::path::Path) -> bool {
    let p = dir.join("probe_last");
    let last = std::fs::read_to_string(&p).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    let now = crate::now_ms();
    if last != 0 && now >= last && now - last < 60 * 60_000 { return false; }
    let _ = std::fs::write(&p, now.to_string());
    true
}
