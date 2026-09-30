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
    if plan["funnel"].is_object() { funnel(&client, &plan["funnel"], &token, &dir, false, &plan["levels"]["funnel_extra"]).await; }
    // 01.10 (MOZG v3, этап 1.3): пробы трёх уровней - только если сервер включил (PROBE_LEVELS)
    if plan["levels"].is_object() {
        if plan["levels"]["l1"].is_object() { level(&client, &plan["levels"]["l1"], &token, &dir, false).await; }
        if plan["levels"]["l2"].is_object() { level(&client, &plan["levels"]["l2"], &token, &dir, true).await; }
        if plan["levels"]["udp"].is_object() { udp_ladder(&client, &plan["levels"]["udp"], &token, &dir).await; }
    }
}

fn ping_stats(mut v: Vec<u64>) -> Value {
    v.sort_unstable();
    let mut o = json!({"ping_ms": v});
    if !v.is_empty() {
        o["ping_p50"] = json!(v[v.len() / 2]);
        o["ping_p95"] = json!(v[((0.95 * (v.len() - 1) as f64) as usize).min(v.len() - 1)]);
    }
    o
}

/// L1 (01.10): раз в every_min (55-95, случайно, от сервера) - 3 пинга по одному соединению через текущий путь и 32 КБ;
/// L2 (big = true): раз в every_h (5-11) - 256-512 КБ + отдача 128 КБ, только при активном экране (на ПК = не в энергосбережении
/// и не на батарее < 30%). Трафик: L1 ~35 КБ, L2 ~0,7 МБ за раунд.
async fn level(direct: &reqwest::Client, s: &Value, token: &str, dir: &std::path::Path, big: bool) {
    if low_power() || (big && battery_low()) { return; }
    let every = if big { s["every_h"].as_u64().unwrap_or(8).clamp(1, 48) * 3600_000 } else { s["every_min"].as_u64().unwrap_or(75).clamp(30, 240) * 60_000 };
    if !stamp_due(dir, if big { "l2_last" } else { "l1_last" }, every) { return; }
    let port = if crate::vpn::cur_path() == "awg" { crate::vpn::HTTP_PORT } else { crate::vpn::PROBE_PORT };
    let secs = s["timeout_s"].as_u64().unwrap_or(if big { 60 } else { 25 }).clamp(5, 90);
    let c = match reqwest::Proxy::all(format!("http://127.0.0.1:{port}"))
        .and_then(|p| reqwest::Client::builder().proxy(p).pool_max_idle_per_host(1).timeout(Duration::from_secs(secs)).build()) { Ok(c) => c, Err(_) => return };
    let mut pings = Vec::new();
    let pu = s["ping_url"].as_str().unwrap_or("https://vpn.insellers.su/probe/204").to_string();
    for i in 0..s["ping_n"].as_u64().unwrap_or(3).clamp(1, 5) {
        let t0 = Instant::now();
        if let Ok(r) = c.get(format!("{pu}?r={i}")).send().await {
            if r.status().is_success() { let _ = r.bytes().await; pings.push(t0.elapsed().as_millis() as u64); }
        }
    }
    let mut d = ping_stats(pings);
    let (mut db, mut dms, mut dok) = (0u64, 0u64, 0u64);
    for (i, u) in s["urls"].as_array().cloned().unwrap_or_default().iter().enumerate() {
        let t0 = Instant::now();
        if let Ok(mut r) = c.get(format!("{}?r={i}", u.as_str().unwrap_or(""))).send().await {
            let ok = r.status().is_success();
            while let Ok(Some(b)) = r.chunk().await { db += b.len() as u64; }
            if ok { dok += 1; }
        }
        dms += t0.elapsed().as_millis() as u64;
    }
    d["want_bytes"] = json!(s["want_bytes"].as_u64().unwrap_or(0));
    d["down_bytes"] = json!(db); d["down_ms"] = json!(dms); d["down_ok"] = json!(dok);
    if big {
        if let Some(up) = s["up_url"].as_str().filter(|x| !x.is_empty()) {
            let n = (s["up_kb"].as_u64().unwrap_or(128).clamp(16, 1024) * 1024) as usize;
            let body: Vec<u8> = (0..n).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect();
            let t0 = Instant::now();
            let code = match c.post(up).header("Content-Type", "application/octet-stream").body(body).send().await { Ok(r) => r.status().as_u16(), Err(_) => 0 };
            d["up_bytes"] = json!(if (200..300).contains(&code) { n } else { 0 });
            d["up_ms"] = json!(t0.elapsed().as_millis() as u64);
            d["up_code"] = json!(code);
        }
    }
    post_measure(direct, token, if big { "l2" } else { "l1" }, d).await;
}

/// Лестница UDP (01.10), мимо туннеля: сырой UDP = STUN-запрос (наши порты на чужой пакет молчат: salamander / junk AWG), рядом TCP до
/// наших серверов - UDP не ходит при живом TCP = «UDP закрыт»; рукопожатие QUIC/Hysteria - по событиям пути hy2 (L0). ~1 КБ, раз в every_h.
async fn udp_ladder(direct: &reqwest::Client, s: &Value, token: &str, dir: &std::path::Path) {
    if !stamp_due(dir, "udp_last", s["every_h"].as_u64().unwrap_or(6).clamp(1, 48) * 3600_000) { return; }
    let to = Duration::from_secs(s["timeout_s"].as_u64().unwrap_or(4).clamp(1, 10));
    let stun: Vec<(String, u16)> = s["stun"].as_array().cloned().unwrap_or_default().iter()
        .map(|x| (x["host"].as_str().unwrap_or("").to_string(), x["port"].as_u64().unwrap_or(3478) as u16)).collect();
    let targets: Vec<Value> = s["targets"].as_array().cloned().unwrap_or_default();
    let res = tauri::async_runtime::spawn_blocking(move || {
        use std::net::{ToSocketAddrs, UdpSocket};
        let (mut udp_ok, mut udp_ms) = (false, -1i64);
        for (host, port) in stun {
            let t0 = Instant::now();
            let ok = (|| -> Result<bool, String> {
                let addr = format!("{host}:{port}").to_socket_addrs().map_err(|e| e.to_string())?.find(|a| a.is_ipv4()).ok_or("нет адреса")?;
                let sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
                sock.set_read_timeout(Some(to)).ok();
                let mut req = [0u8; 20];
                req[1] = 1; req[4] = 0x21; req[5] = 0x12; req[6] = 0xA4; req[7] = 0x42;
                let seed = crate::now_ms();
                for (i, b) in req[8..].iter_mut().enumerate() { *b = ((seed >> (i % 8 * 8)) as u8) ^ (i as u8 * 37); }
                sock.send_to(&req, addr).map_err(|e| e.to_string())?;
                let mut buf = [0u8; 256];
                let (n, _) = sock.recv_from(&mut buf).map_err(|e| e.to_string())?;
                Ok(n >= 20 && buf[0] == 1 && buf[1] == 1)
            })();
            if ok.unwrap_or(false) { udp_ok = true; udp_ms = t0.elapsed().as_millis() as i64; break; }
        }
        let mut out = Vec::new();
        for t in targets {
            let ip: IpAddr = match t["ip"].as_str().unwrap_or("").parse() { Ok(a) => a, Err(_) => continue };
            let tcp_ok = TcpStream::connect_timeout(&SocketAddr::new(ip, 443), to).is_ok();
            out.push(json!({"server": t["server"], "transport": t["transport"].as_str().unwrap_or("hy2"), "port": t["port"],
                            "udp_ok": udp_ok, "udp_ms": udp_ms, "tcp_ok": tcp_ok}));
        }
        json!({"stun_ok": udp_ok, "stun_ms": udp_ms, "targets": out})
    }).await.unwrap_or(Value::Null);
    if res.is_object() { post_measure(direct, token, "udp", res).await; }
}

/// 01.10: рукопожатие TLS без проверки сертификата - только «ответил ли сервер на ClientHello с этим именем» (несколько SNI на одном
/// адресе: блок имени против блока адреса). Данных не шлём.
#[derive(Debug)]
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify {
    fn verify_server_cert(&self, _e: &rustls::pki_types::CertificateDer<'_>, _i: &[rustls::pki_types::CertificateDer<'_>], _n: &rustls::pki_types::ServerName<'_>,
                          _o: &[u8], _t: rustls::pki_types::UnixTime) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _m: &[u8], _c: &rustls::pki_types::CertificateDer<'_>, _d: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

fn tls_hello_only(ip: &str, sni: &str, to: Duration) -> Result<(), String> {
    let ipa: IpAddr = ip.parse().map_err(|_| "плохой адрес".to_string())?;
    let tcp = TcpStream::connect_timeout(&SocketAddr::new(ipa, 443), to).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(to)).ok(); tcp.set_write_timeout(Some(to)).ok();
    let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions().map_err(|e| e.to_string())?
        .dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth();
    let sn = rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
    let conn = rustls::ClientConnection::new(Arc::new(cfg), sn).map_err(|e| e.to_string())?;
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() { s.conn.complete_io(&mut s.sock).map_err(|e| e.to_string())?; }
    Ok(())
}

/// 01.10: сертификат по подменённому адресу - настоящий ли (подмена DNS против переезда адреса)
fn cert_ok_at(ip: &str, host: &str, to: Duration) -> bool {
    let ipa: IpAddr = match ip.parse() { Ok(a) => a, Err(_) => return false };
    let Ok(tcp) = TcpStream::connect_timeout(&SocketAddr::new(ipa, 443), to) else { return false };
    tcp.set_read_timeout(Some(to)).ok(); tcp.set_write_timeout(Some(to)).ok();
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let cfg = match rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions() {
        Ok(b) => b.with_root_certificates(roots).with_no_client_auth(), Err(_) => return false };
    let Ok(sn) = rustls::pki_types::ServerName::try_from(host.to_string()) else { return false };
    let Ok(conn) = rustls::ClientConnection::new(Arc::new(cfg), sn) else { return false };
    let mut s = rustls::StreamOwned::new(conn, tcp);
    while s.conn.is_handshaking() { if s.conn.complete_io(&mut s.sock).is_err() { return false; } }
    true
}

/// 30.09: после сбоя подключения - воронка (force), если в плане сервера она есть; не чаще раза в 15 мин.
pub async fn after_failure(dir: std::path::PathBuf) {
    if !stamp_due(&dir, "funnel_fail", 15 * 60_000) { return; }
    let token = crate::load_token();
    if token.is_empty() { return; }
    let client = match reqwest::Client::builder().no_proxy().user_agent(format!("InsellersVPN/desktop-{}", env!("CARGO_PKG_VERSION")))
        .build() { Ok(c) => c, Err(_) => return };
    let plan: Value = match client.get(format!("{}/api/app/probe-plan", crate::BASE)).header("X-App-Token", &token)
        .timeout(Duration::from_secs(10)).send().await {
        Ok(r) if r.status().is_success() => r.json().await.unwrap_or(Value::Null),
        _ => return,
    };
    if plan["funnel"].is_object() { funnel(&client, &plan["funnel"], &token, &dir, true, &plan["levels"]["funnel_extra"]).await; }
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
pub async fn funnel(client: &reqwest::Client, f: &Value, token: &str, dir: &std::path::Path, force: bool, extra: &Value) {
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
        let cert_check = extra["cert_check"].as_bool().unwrap_or(false);
        let (r, other) = match res {
            Ok(a) => {
                if a.contains(&want) { (Ok(()), None) } else { (Err(format!("подмена: {}", a.join(",").chars().take(60).collect::<String>())), a.first().cloned()) } }
            Err(e) => (Err(e), None),
        };
        step(&mut steps, &format!("dns:{h}"), t0, r);
        if let (true, Some(ip)) = (cert_check, other) {
            let (hh, ipc) = (h.clone(), ip.clone());
            let ok = tauri::async_runtime::spawn_blocking(move || cert_ok_at(&ipc, &hh, Duration::from_secs(5))).await.unwrap_or(false);
            steps.push(json!({"step": format!("cert:{h}"), "ok": ok, "ms": 0, "why": if ok { "адрес другой, сертификат наш" } else { "сертификат не наш" }}));
        }
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
    if extra.is_object() {
        // 01.10: несколько имён на одном адресе, контрольные адреса другого AS, наборы allow / non-allow
        let snis: Vec<String> = extra["sni"].as_array().cloned().unwrap_or_default().iter().filter_map(|x| x.as_str().map(String::from)).collect();
        let first = f["servers"].as_array().and_then(|a| a.first()).cloned().unwrap_or(Value::Null);
        if first.is_object() && !snis.is_empty() {
            let (ip, srvn) = (first["ip"].as_str().unwrap_or("").to_string(), first["server"].as_str().unwrap_or("?").to_string());
            let more2: Vec<Value> = tauri::async_runtime::spawn_blocking(move || {
                let mut st = Vec::new();
                for sni in snis {
                    let t0 = Instant::now();
                    let r = tls_hello_only(&ip, &sni, Duration::from_secs(5));
                    step(&mut st, &format!("tls2:{sni}@{srvn}"), t0, r);
                }
                st
            }).await.unwrap_or_default();
            steps.extend(more2);
        }
        let mut ctl_ok = false; let mut ctl_n = 0;
        for u in extra["control"].as_array().cloned().unwrap_or_default() {
            ctl_n += 1;
            if matches!(code(client, u.as_str().unwrap_or("")).await, Ok(c) if (200..400).contains(&c)) { ctl_ok = true; }
        }
        if ctl_n > 0 { steps.push(json!({"step": "control", "ok": ctl_ok, "ms": 0, "why": if ctl_ok { "" } else { "контрольные адреса другого AS не открылись" }})); }
        let (mut allow_n, mut non_n, mut allow_t, mut non_t) = (0, 0, 0, 0);
        for u in extra["allow"].as_array().cloned().unwrap_or_default() { allow_t += 1; if matches!(code(client, u.as_str().unwrap_or("")).await, Ok(c) if (200..400).contains(&c)) { allow_n += 1; } }
        for u in extra["non_allow"].as_array().cloned().unwrap_or_default() { non_t += 1; if matches!(code(client, u.as_str().unwrap_or("")).await, Ok(c) if (200..400).contains(&c)) { non_n += 1; } }
        if allow_t > 0 && non_t > 0 {
            steps.push(json!({"step": "wl:allowed", "ok": allow_n > 0, "ms": 0, "why": format!("{allow_n} из {allow_t}")}));
            steps.push(json!({"step": "wl:normal", "ok": non_n > 0, "ms": 0, "why": format!("{non_n} из {non_t}")}));
            steps.push(json!({"step": "whitelist", "ok": non_n > 0 || allow_n == 0,
                              "why": if non_n == 0 && allow_n > 0 { "похоже на белые списки: разрешённые сайты открыты, обычные - нет" } else { "" }}));
        }
    }
    if f["whitelist"].is_object() && !extra["allow"].is_array() {
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
    post_measure(client, token, "funnel", json!({"steps": steps, "force": force, "why": if force { "failure" } else { "schedule" }})).await;
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

// ---- «Не работает?» (01.10, владелец): воронка мимо туннеля по нажатию - InsellersNative.probeFunnel() -> событие ins:funnel ----
// <= 6 с, ~30 КБ, без скачивания: матрица путей (TCP + рукопожатие TLS с прикрытием Reality/XHTTP до NL-1 и NL-2), «портал» Wi-Fi
// (generate_204 напрямую), сдвиг часов по NTP, раздача (Mac: шлюз 172.20.10.1 - точка доступа iPhone), энергосбережение, текущий путь.
// Hysteria/AmneziaWG (UDP) без своего протокола не проверяются. failure_class - таксономия backend/failure_class.py.

fn fclass(stage: &str, e: &str) -> &'static str {
    let l = e.to_lowercase();
    if l.contains("unreachable") || l.contains("no route") { return "CLIENT_NETWORK_BAD"; }
    if stage == "tcp" {
        if l.contains("refused") || l.contains("reset") { return "TCP_RST"; }
        return "TCP_CONNECT_TIMEOUT";
    }
    if l.contains("timed out") || l.contains("timeout") || l.contains("would block") { return "TLS_CLIENT_HELLO_TIMEOUT"; }
    if l.contains("reset") || l.contains("eof") || l.contains("closed") || l.contains("broken pipe") { return "TLS_RST"; }
    if l.contains("alert") { return "TLS_ALERT"; }
    "UNKNOWN"
}

fn tls_path(proto: &str, sni: &str, srv: &str, ip: &str, to: Duration) -> Value {
    let t0 = Instant::now();
    let mut o = json!({"proto": proto, "server": srv});
    let ipa: IpAddr = match ip.parse() { Ok(a) => a, Err(_) => return o };
    let tcp = match TcpStream::connect_timeout(&SocketAddr::new(ipa, 443), to) {
        Ok(t) => t,
        Err(e) => { let s = e.to_string(); o["tcp_ok"] = json!(false); o["hs_ok"] = json!(false); o["failure_class"] = json!(fclass("tcp", &s));
                    o["error_code"] = json!(s.chars().take(100).collect::<String>()); o["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64); return o; }
    };
    o["tcp_ok"] = json!(true); o["tcp_ms"] = json!(t0.elapsed().as_millis() as u64);
    tcp.set_read_timeout(Some(to)).ok(); tcp.set_write_timeout(Some(to)).ok();
    let t1 = Instant::now();
    let r = (|| -> Result<(), String> {
        let cfg = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions().map_err(|e| e.to_string())?
            .dangerous().with_custom_certificate_verifier(Arc::new(NoVerify)).with_no_client_auth();
        let sn = rustls::pki_types::ServerName::try_from(sni.to_string()).map_err(|e| e.to_string())?;
        let conn = rustls::ClientConnection::new(Arc::new(cfg), sn).map_err(|e| e.to_string())?;
        let mut s = rustls::StreamOwned::new(conn, tcp);
        while s.conn.is_handshaking() { s.conn.complete_io(&mut s.sock).map_err(|e| e.to_string())?; }
        Ok(())
    })();
    match r {
        Ok(()) => { o["hs_ok"] = json!(true); o["hs_ms"] = json!(t1.elapsed().as_millis() as u64); o["failure_class"] = json!("NONE"); }
        Err(e) => { o["hs_ok"] = json!(false); o["failure_class"] = json!(fclass("tls", &e)); o["error_code"] = json!(e.chars().take(100).collect::<String>()); }
    }
    o["elapsed_ms"] = json!(t0.elapsed().as_millis() as u64);
    o
}

fn ntp_skew() -> Value {
    use std::net::{ToSocketAddrs, UdpSocket};
    let t0 = Instant::now();
    let r = (|| -> Result<f64, String> {
        let addr = "time.google.com:123".to_socket_addrs().map_err(|e| e.to_string())?.find(|a| a.is_ipv4()).ok_or("нет адреса")?;
        let s = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
        s.set_read_timeout(Some(Duration::from_secs(2))).ok();
        let mut req = [0u8; 48]; req[0] = 0x1B;
        let sent = crate::now_ms() as f64;
        s.send_to(&req, addr).map_err(|e| e.to_string())?;
        let mut b = [0u8; 48];
        s.recv_from(&mut b).map_err(|e| e.to_string())?;
        let recv = crate::now_ms() as f64;
        let secs = u32::from_be_bytes([b[40], b[41], b[42], b[43]]) as f64;
        let frac = u32::from_be_bytes([b[44], b[45], b[46], b[47]]) as f64;
        let server = (secs - 2208988800.0) * 1000.0 + frac * 1000.0 / 4294967296.0;
        Ok(((sent + recv) / 2.0 - server) / 1000.0)
    })();
    match r {
        Ok(sk) => json!({"ok": true, "skew_s": (sk * 10.0).round() / 10.0, "elapsed_ms": t0.elapsed().as_millis() as u64,
                         "failure_class": if sk.abs() > 300.0 { "CLIENT_CLOCK_SKEW" } else { "NONE" }}),
        Err(e) => json!({"ok": false, "failure_class": "UDP_TIMEOUT", "error_code": e.chars().take(80).collect::<String>(), "elapsed_ms": t0.elapsed().as_millis() as u64}),
    }
}

fn gateway() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("route").args(["-n", "get", "default"]).output() {
            let s = String::from_utf8_lossy(&o.stdout).to_string();
            if let Some(l) = s.lines().find(|l| l.trim_start().starts_with("gateway:")) { return l.split(':').nth(1).unwrap_or("").trim().to_string(); }
        }
    }
    String::new()
}

pub async fn funnel_now() -> Value {
    let t0 = Instant::now();
    let matrix: Vec<Value> = tauri::async_runtime::spawn_blocking(|| {
        let mut hs = Vec::new();
        for (srv, ip) in [("NL-1", "176.124.198.72"), ("NL-2", "212.34.151.212")] {
            for (proto, sni) in [("reality", "www.samsung.com"), ("xhttp", "www.philips.com")] {
                hs.push(std::thread::spawn(move || tls_path(proto, sni, srv, ip, Duration::from_secs(3))));
            }
        }
        hs.into_iter().filter_map(|h| h.join().ok()).collect()
    }).await.unwrap_or_default();
    let ntp = tauri::async_runtime::spawn_blocking(ntp_skew).await.unwrap_or(Value::Null);
    let cap = match reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(Duration::from_millis(2500)).build() {
        Ok(c) => match c.get("http://connectivitycheck.gstatic.com/generate_204").send().await {
            Ok(r) => { let code = r.status().as_u16(); json!({"ok": code == 204, "code": code, "portal": code != 204, "failure_class": if code == 204 { "NONE" } else { "CLIENT_NETWORK_BAD" }}) }
            Err(e) => { let s = e.to_string(); json!({"ok": false, "failure_class": fclass("tcp", &s), "error_code": s.chars().take(100).collect::<String>()}) }
        },
        Err(_) => Value::Null,
    };
    let gw = gateway();
    let mut steps = Vec::new();
    for m in &matrix {
        let (srv, proto) = (m["server"].as_str().unwrap_or(""), m["proto"].as_str().unwrap_or(""));
        let tok = m["tcp_ok"].as_bool().unwrap_or(false);
        steps.push(json!({"step": format!("ip:{srv}"), "ok": tok, "ms": m["tcp_ms"].clone(), "failure_class": if tok { "NONE" } else { m["failure_class"].as_str().unwrap_or("") },
                          "why": if tok { "" } else { m["error_code"].as_str().unwrap_or("") }}));
        if tok { steps.push(json!({"step": format!("tls2:{proto}@{srv}"), "ok": m["hs_ok"].clone(), "ms": m["hs_ms"].clone(), "failure_class": m["failure_class"].clone(), "why": m["error_code"].clone()})); }
    }
    if cap.is_object() { steps.push(json!({"step": "control", "ok": cap["ok"].as_bool().unwrap_or(false) || cap["code"].as_u64().map(|c| (200..400).contains(&c)).unwrap_or(false),
                                           "why": if cap["portal"].as_bool().unwrap_or(false) { format!("портал Wi-Fi (ответ {})", cap["code"]) } else { cap["error_code"].as_str().unwrap_or("").to_string() }})); }
    if ntp["ok"].as_bool().unwrap_or(false) { steps.push(json!({"step": "clock", "ok": ntp["skew_s"].as_f64().unwrap_or(0.0).abs() < 300.0, "skew_s": ntp["skew_s"].clone()})); }
    json!({"v": 1, "src": "desktop", "matrix": matrix, "captive": cap, "ntp": ntp, "steps": steps,
           "gateway": if gw.is_empty() { Value::Null } else { json!(gw) }, "hotspot": gw == "172.20.10.1",
           "power_save": low_power(), "other_vpn": Value::Null, "net_changes_10m": Value::Null,
           "vpn": {"path": crate::vpn::cur_path()},
           "udp": {"note": "Hysteria/AmneziaWG без своего протокола не проверяются - только текущее подключение"},
           "ms": t0.elapsed().as_millis() as u64})
}
