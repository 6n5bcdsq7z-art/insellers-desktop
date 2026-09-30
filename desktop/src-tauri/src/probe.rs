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
pub async fn run_once(token: String, dir: std::path::PathBuf) {
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
    // 30.09 (Мозг v2): скорость и воронка - только если сервер включил их этому человеку (план)
    if plan["speed"].is_object() { speed(&client, &plan["speed"], &token, &dir).await; }
    if plan["funnel"].is_object() { funnel(&client, &plan["funnel"], &token, &dir, false).await; }
}

async fn post_measure(client: &reqwest::Client, token: &str, kind: &str, data: Value) {
    let body = json!({"kind": kind, "net": "", "device": format!("ins-{}", crate::install_id()), "platform": "desktop",
                      "version": env!("CARGO_PKG_VERSION"), "path": crate::vpn::cur_path(), "data": data});
    let _ = client.post(format!("{}/api/app/measure", crate::BASE)).header("X-App-Token", token)
        .timeout(Duration::from_secs(15)).json(&body).send().await;
}

fn stamp_due(dir: &std::path::Path, name: &str, every_ms: u64) -> bool {
    let p = dir.join(name);
    let last = std::fs::read_to_string(&p).ok().and_then(|t| t.trim().parse::<u64>().ok()).unwrap_or(0);
    let now = crate::now_ms();
    if last != 0 && now >= last && now - last < every_ms { return false; }
    let _ = std::fs::write(&p, now.to_string());
    true
}

/// probe_speed (30.09): через ТЕКУЩИЙ путь туннеля (вход проверки ядра; при AmneziaWG - общий вход, vpn.insellers.su идёт в туннель):
/// пинг 5 x /probe/204 по одному соединению, загрузка down_wifi (1 МБ), отдача POST up_kb. Раз в ~час, не в энергосбережении и не на батарее < 30%.
async fn speed(direct: &reqwest::Client, s: &Value, token: &str, dir: &std::path::Path) {
    if low_power() || battery_low() || !stamp_due(dir, "speed_last", 55 * 60_000) { return; }
    let port = if crate::vpn::cur_path() == "awg" { crate::vpn::HTTP_PORT } else { crate::vpn::PROBE_PORT };
    let secs = s["timeout_s"].as_u64().unwrap_or(40).clamp(10, 60);
    let c = match reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
        .and_then(|p| reqwest::Client::builder().proxy(p).pool_max_idle_per_host(1).timeout(Duration::from_secs(secs)).build()) { Ok(c) => c, Err(_) => return };
    let mut pings = Vec::new();
    let pu = s["ping_url"].as_str().unwrap_or("https://vpn.insellers.su/probe/204").to_string();
    for i in 0..s["ping_n"].as_u64().unwrap_or(5).clamp(1, 10) {
        let t0 = Instant::now();
        if let Ok(r) = c.get(format!("{pu}?r={i}")).send().await {
            if r.status().is_success() { let _ = r.bytes().await; pings.push(t0.elapsed().as_millis() as u64); }
        }
    }
    let (mut db, mut dms, mut dok) = (0u64, 0u64, 0u64);
    for (i, u) in s["down_wifi"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let t0 = Instant::now();
        if let Ok(mut r) = c.get(format!("{}?r={i}", u.as_str().unwrap_or(""))).send().await {
            let ok = r.status().is_success();
            while let Ok(Some(b)) = r.chunk().await { db += b.len() as u64; }
            if ok { dok += 1; }
        }
        dms += t0.elapsed().as_millis() as u64;
    }
    let mut d = json!({"ping_ms": pings, "down_bytes": db, "down_ms": dms, "down_ok": dok});
    if let Some(up) = s["up_url"].as_str().filter(|x| !x.is_empty()) {
        let n = (s["up_kb"].as_u64().unwrap_or(128).clamp(16, 1024) * 1024) as usize;
        let body: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
        let t0 = Instant::now();
        let code = match c.post(up).header("Content-Type", "application/octet-stream").body(body).send().await { Ok(r) => r.status().as_u16(), Err(_) => 0 };
        d["up_bytes"] = json!(if (200..300).contains(&code) { n } else { 0 });
        d["up_ms"] = json!(t0.elapsed().as_millis() as u64);
        d["up_code"] = json!(code);
    }
    post_measure(direct, token, "speed", d).await;
}

fn step(steps: &mut Vec<Value>, name: &str, t0: Instant, r: Result<(), String>) {
    steps.push(json!({"step": name, "ok": r.is_ok(), "ms": t0.elapsed().as_millis() as u64, "why": r.err().unwrap_or_default()}));
}

/// Серверный шаг воронки (блокирующий): TCP -> TLS (SNI) -> GET big, «> 16 КБ».
fn funnel_srv(name: &str, ip: &str, sni: &str, big: &str, steps: &mut Vec<Value>) {
    let to = Duration::from_secs(5);
    let t0 = Instant::now();
    let ipa: IpAddr = match ip.parse() { Ok(a) => a, Err(_) => return };
    let tcp = match TcpStream::connect_timeout(&SocketAddr::new(ipa, 443), to) {
        Ok(t) => { step(steps, &format!("ip:{name}"), t0, Ok(())); t }
        Err(e) => { step(steps, &format!("ip:{name}"), t0, Err(e.to_string())); return; }
    };
    tcp.set_read_timeout(Some(to)).ok(); tcp.set_write_timeout(Some(to)).ok();
    let t1 = Instant::now();
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = match rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions() { Ok(b) => b.with_root_certificates(roots).with_no_client_auth(), Err(_) => return };
    let Ok(sn) = rustls::pki_types::ServerName::try_from(sni.to_string()) else { return };
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(cfg), sn) else { return };
    let mut s = rustls::StreamOwned::new(conn, tcp);
    let mut hs: Result<(), String> = Ok(());
    while s.conn.is_handshaking() {
        if let Err(e) = s.conn.complete_io(&mut s.sock) { hs = Err(e.to_string()); break; }
    }
    let bad = hs.is_err();
    step(steps, &format!("tls:{name}"), t1, hs);
    if bad { return; }
    let t2 = Instant::now();
    let mut got = 0usize;
    let mut buf = [0u8; 16384];
    if s.write_all(format!("GET {big} HTTP/1.1\r\nHost: {sni}\r\nConnection: close\r\n\r\n").as_bytes()).is_ok() {
        while got < 32 * 1024 { match s.read(&mut buf) { Ok(0) | Err(_) => break, Ok(n) => got += n } }
    }
    step(steps, &format!("16kb:{name}"), t2, if got >= 16 * 1024 + 200 { Ok(()) } else { Err(format!("дошло {} КБ", got / 1024)) });
}

/// probe_funnel (30.09): МИМО туннеля (как без VPN) - DNS системный и DoH (подмена = не тот адрес), сайт, подписка, TCP до
/// серверов, TLS, > 16 КБ, «белые списки». Раз в every_h; force - после сбоя подключения.
pub async fn funnel(client: &reqwest::Client, f: &Value, token: &str, dir: &std::path::Path, force: bool) {
    if !force && !stamp_due(dir, "funnel_last", f["every_h"].as_u64().unwrap_or(6).clamp(1, 48) * 3600_000) { return; }
    let mut steps: Vec<Value> = Vec::new();
    let names = f["names"].as_object().cloned().unwrap_or_default();
    for (h, want) in &names {
        let t0 = Instant::now();
        let want = want.as_str().unwrap_or("").to_string();
        let hh = format!("{h}:443");
        let res = tauri::async_runtime::spawn_blocking(move || {
            use std::net::ToSocketAddrs;
            hh.to_socket_addrs().map(|it| it.map(|x| x.ip().to_string()).collect::<Vec<String>>()).map_err(|e| e.to_string())
        }).await.unwrap_or_else(|e| Err(e.to_string()));
        let r = match res {
            Ok(a) => {
                        if a.contains(&want) { Ok(()) } else { Err(format!("подмена: {}", a.join(",").chars().take(60).collect::<String>())) } }
            Err(e) => Err(e),
        };
        step(&mut steps, &format!("dns:{h}"), t0, r);
    }
    let want0 = names.get("vpn.insellers.su").and_then(|v| v.as_str()).unwrap_or("176.124.198.72").to_string();
    for u in f["doh"].as_array().cloned().unwrap_or_default() {
        let u = u.as_str().unwrap_or("").to_string();
        let t0 = Instant::now();
        let r = match client.get(format!("{u}?name=vpn.insellers.su&type=A")).header("accept", "application/dns-json").timeout(Duration::from_secs(5)).send().await {
            Ok(x) => match x.text().await { Ok(t) if t.contains(&want0) => Ok(()), Ok(_) => Err("другой ответ".into()), Err(e) => Err(e.to_string()) },
            Err(e) => Err(e.to_string()),
        };
        let host = u.split('/').nth(2).unwrap_or("?").to_string();
        step(&mut steps, &format!("doh:{host}"), t0, r);
    }
    async fn code(c: &reqwest::Client, u: &str) -> Result<u16, String> {
        c.get(u).timeout(Duration::from_secs(5)).send().await.map(|r| r.status().as_u16()).map_err(|e| e.to_string().chars().take(100).collect())
    }
    let t0 = Instant::now();
    let r = code(client, f["site"].as_str().unwrap_or("")).await.and_then(|c| if (200..300).contains(&c) { Ok(()) } else { Err(format!("http {c}")) });
    step(&mut steps, "site", t0, r);
    let t0 = Instant::now();
    let r = code(client, f["sub"].as_str().unwrap_or("")).await.map(|_| ());
    step(&mut steps, "sub", t0, r);
    let srv: Vec<Value> = f["servers"].as_array().cloned().unwrap_or_default();
    let more: Vec<Value> = tauri::async_runtime::spawn_blocking(move || {
        let mut st = Vec::new();
        for s in srv { funnel_srv(s["server"].as_str().unwrap_or("?"), s["ip"].as_str().unwrap_or(""), s["sni"].as_str().unwrap_or("vpn.insellers.su"),
                                  s["big"].as_str().unwrap_or("/probe/32k"), &mut st); }
        st
    }).await.unwrap_or_default();
    steps.extend(more);
    if f["whitelist"].is_object() {
        let t0 = Instant::now();
        let n = code(client, f["whitelist"]["normal"].as_str().unwrap_or("")).await;
        let normal = matches!(n, Ok(c) if (200..400).contains(&c));
        step(&mut steps, "wl:normal", t0, if normal { Ok(()) } else { Err(format!("{n:?}")) });
        let t0 = Instant::now();
        let a = code(client, f["whitelist"]["allowed"].as_str().unwrap_or("")).await;
        let allowed = matches!(a, Ok(c) if (200..400).contains(&c));
        step(&mut steps, "wl:allowed", t0, if allowed { Ok(()) } else { Err(format!("{a:?}")) });
        steps.push(json!({"step": "whitelist", "ok": normal || !allowed,
                          "why": if !normal && allowed { "похоже на белые списки: обычный сайт закрыт, разрешённый открыт" } else { "" }}));
    }
    post_measure(client, token, "funnel", json!({"steps": steps, "force": force})).await;
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
