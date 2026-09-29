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

// ---- Часовой замер вариантов конфигурации (26.09 ночь, владелец) - как на Android (AppProbe.runVariants) ----
// Сервер подписок отдаёт проверочную конфигурацию (?format=probe: 4 варианта «сервер|вид|режим|отпечаток|xmux|frag», каждый на
// своём локальном HTTP-входе). Поднимаем ОТДЕЛЬНЫЙ Xray рядом с основным и меряем каждый вариант: первый запрос (рукопожатие),
// второй (задержка), 128 КБ (скорость; обрыв после N КБ - признак ТСПУ). ~0.5 МБ за раунд, раз в every_h (1 ч).
// Не мешаем человеку: не в энергосбережении, не на батарее < 30% (Мак), не пока он сам качает > 150 КБ/с - тогда позже.

fn battery_low() -> bool {
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("pmset").args(["-g", "batt"]).output() {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            if s.contains("discharging") {
                if let Some(p) = s.split('%').next().and_then(|a| a.rsplit(|c: char| !c.is_ascii_digit()).next()) {
                    if let Ok(v) = p.parse::<u32>() { return v < 30; }
                }
            }
        }
    }
    false
}

async fn user_busy() -> bool {
    let mut nets = sysinfo::Networks::new_with_refreshed_list();
    let _ = crate::upd::phys_rx(&mut nets);
    crate::tokio_sleep(3).await;
    crate::upd::phys_rx(&mut nets) / 3 > 150 * 1024
}

/// Пора ли (раз в every_h из плана; переподключения не учащают). Время ставим только когда замер реально пошёл.
pub fn variants_due(dir: &std::path::Path) -> bool {
    let rd = |n: &str| std::fs::read_to_string(dir.join(n)).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    let (last, every) = (rd("vprobe_last"), rd("vprobe_every_h").clamp(1, 48));
    let now = crate::now_ms();
    last == 0 || now < last || now - last >= every * 3600_000
}

async fn get_via(port: u16, url: &str, max: usize, secs: u64) -> (u64, usize, String) {
    let t0 = Instant::now();
    let c = match reqwest::Client::builder().proxy(match reqwest::Proxy::all(format!("http://127.0.0.1:{port}")) { Ok(p) => p, Err(e) => return (0, 0, e.to_string()) })
        .user_agent(format!("InsellersVPN/desktop-{} netcheck", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(secs)).build() { Ok(c) => c, Err(e) => return (0, 0, e.to_string()) };
    let mut got = 0usize;
    let err = match c.get(url).send().await {
        Ok(mut r) => {
            let st = r.status();
            loop {
                match r.chunk().await {
                    Ok(Some(b)) => { got += b.len(); if got >= max { break String::new(); } }
                    Ok(None) => break if st.is_success() { String::new() } else { format!("http {}", st.as_u16()) },
                    Err(e) => break e.to_string().chars().take(120).collect(),
                }
            }
        }
        Err(e) => e.to_string().chars().take(120).collect(),
    };
    (t0.elapsed().as_millis() as u64, got, err)
}

pub async fn run_variants(app: &tauri::AppHandle, dir: &std::path::Path, token: String) {
    use tauri_plugin_shell::ShellExt;
    // 29.09 (владелец: замеров с устройств 0 за 7 суток) - каждая причина пропуска и итог отправки - в журнал
    let skip = |why: &str| crate::remote_log("probe.variants", json!({"ok": false, "stage": "skip", "why": why}));
    if token.is_empty() { skip("no_token"); return; }
    if low_power() || battery_low() { skip("power"); return; }
    if user_busy().await { skip("user_busy"); return; }
    let direct = match reqwest::Client::builder().no_proxy().user_agent(format!("InsellersVPN/desktop-{}", env!("CARGO_PKG_VERSION")))
        .timeout(Duration::from_secs(15)).build() { Ok(c) => c, Err(_) => return };
    let sub = match crate::vpn::sub_url(&direct, &token).await { Ok(s) => s, Err(_) => { skip("no_sub"); return; } };
    let base = sub.split('?').next().unwrap_or("").to_string();
    let port: u16 = 20000 + (crate::now_ms() % 20000) as u16;
    let plan: Value = match direct.get(format!("{base}?format=probe&port={port}&net=wifi")).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
        _ => { skip("no_plan"); return; }
    };
    let vs = plan["variants"].as_array().cloned().unwrap_or_default();
    if vs.is_empty() { skip("empty_plan"); return; }
    let _ = std::fs::write(dir.join("vprobe_last"), crate::now_ms().to_string());
    let _ = std::fs::write(dir.join("vprobe_every_h"), plan["every_h"].as_u64().unwrap_or(1).to_string());
    let path = dir.join("probe-variants.json");
    if std::fs::write(&path, plan["config"].to_string()).is_err() { skip("write_config"); return; }
    let ps = path.to_string_lossy().to_string();
    let (rx, child) = match app.shell().sidecar("xray").and_then(|c| c.args(["run", "-c", ps.as_str()]).spawn()) {
        Ok(x) => x,
        Err(e) => { skip(&format!("spawn: {}", e.to_string().chars().take(100).collect::<String>())); return; }
    };
    crate::tokio_sleep(2).await;
    let lat = plan["urls"]["latency"].as_str().unwrap_or("https://vpn.insellers.su/probe/204").to_string();
    let big = plan["urls"]["big"].as_str().unwrap_or("https://vpn.insellers.su/probe/128k").to_string();
    let want = if big.ends_with("/256k") { 262144 } else if big.ends_with("/32k") { 32768 } else { 131072 };
    let mut out = Vec::new();
    for v in vs {
        let id = v["id"].as_str().unwrap_or("").to_string();
        let p = v["port"].as_u64().unwrap_or(0) as u16;
        let (hs, _, e1) = get_via(p, &lat, 1024, 10).await;
        if !e1.is_empty() { out.push(json!({"id": id, "ok": false, "err": e1, "hs_ms": hs})); continue; }
        let (rtt, _, _) = get_via(p, &lat, 1024, 10).await;
        let (ms, got, e3) = get_via(p, &big, want, 15).await;
        let ok = e3.is_empty() && got >= want;
        let mut r = json!({"id": id, "ok": ok, "hs_ms": hs, "rtt_ms": rtt, "ms": ms, "kb": ((got as f64) / 102.4).round() / 10.0});
        if ms > 0 { r["kbps"] = json!(got as f64 * 8.0 / ms as f64); }
        if !ok { r["err"] = json!(if e3.is_empty() { format!("прочитано {} КБ из {}", got / 1024, want / 1024) } else { e3 }); }
        out.push(r);
    }
    let _ = child.kill();
    drop(rx);
    let _ = std::fs::remove_file(&path);
    let n = out.len();
    let passed = out.iter().filter(|r| r["ok"].as_bool().unwrap_or(false)).count();
    let body = json!({"net": "", "device": format!("ins-{}", crate::install_id()), "platform": "desktop",
                      "version": env!("CARGO_PKG_VERSION"), "results": out});
    let st = match direct.post(format!("{}/api/app/variant-probe", crate::BASE)).header("X-App-Token", &token)
        .json(&body).send().await { Ok(r) => r.status().as_u16().to_string(), Err(e) => e.to_string().chars().take(100).collect() };
    crate::remote_log("probe.variants", json!({"ok": st == "200", "n": n, "passed": passed, "post": st}));
}
