//! Загрузка обновления (26.09 ночь, владелец: «обновление не должно мешать человеку ни секунды»).
//! - Одна загрузка за раз: повторный запрос (кнопка, перезагрузка страницы, автопроверка) не начинает новую, а показывает
//!   прогресс текущей. 26.09 у владельца шли три загрузки сразу, полоса прыгала 52% -> 3% -> 52%, сеть легла.
//! - Напрямую с нашего сервера; медленно (< 500 КБ/с) или обрыв - через туннель (вход проверки ядра). VPN при загрузке не трогаем.
//! - 40% канала - только когда кроме нас идёт заметный трафик; в простое - полная скорость; медленно напрямую - туннель.
//! - Докачка при обрыве (Range), до 30 попыток.
//! - Подпись проверяем так же, как плагин обновлений (minisign, ключ из tauri.conf.json), и только потом ставим.
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

pub static BUSY: AtomicBool = AtomicBool::new(false);
pub static PCT: AtomicU64 = AtomicU64::new(0);

pub struct BusyGuard;
impl Drop for BusyGuard {
    fn drop(&mut self) { BUSY.store(false, Ordering::SeqCst); PCT.store(0, Ordering::SeqCst); }
}

async fn sleep_ms(ms: u64) {
    tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_millis(ms))).await.ok();
}

fn client(via_tunnel: bool) -> Result<reqwest::Client, String> {
    let b = reqwest::Client::builder()
        .user_agent(format!("InsellersVPN/desktop-{} updater", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .read_timeout(Duration::from_secs(20));
    // «через туннель» = вход проверки ядра (probe-in -> балансировщик): обычный http-вход отправляет адрес нашего сервера
    // (vpn.insellers.su = IP сервера) напрямую, мимо туннеля
    let b = if via_tunnel {
        b.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", crate::vpn::PROBE_PORT)).map_err(|e| e.to_string())?)
    } else { b.no_proxy() };
    b.build().map_err(|e| e.to_string())
}

/// Сколько байт пришло по физическим интерфейсам (без loopback и туннелей) с прошлого вызова.
fn phys_rx(nets: &mut sysinfo::Networks) -> u64 {
    nets.refresh();
    nets.iter().filter(|(n, _)| {
        let n = n.to_lowercase();
        !(n.starts_with("lo") || n.contains("loopback") || n.contains("tun") || n.starts_with("wg") || n.contains("insellers") || n.starts_with("ifb"))
    }).map(|(_, d)| d.received()).sum()
}

/// Скачать файл обновления. `progress(pct)` - 0..100.
/// 26.09 ночь (владелец): полная скорость, пока человек сетью не пользуется; 40% канала - только когда кроме нас идёт заметный
/// трафик (> 50 КБ/с по физическим интерфейсам). Напрямую медленнее ~500 КБ/с (замер за первые 6 с) или обрыв - сразу через
/// туннель (если VPN включён), с докачкой с того же места. Цель - ~100 МБ за 1-2 минуты.
pub async fn fetch(url: &str, tunnel_ok: bool, mut progress: impl FnMut(u64)) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut total: Option<u64> = None;
    let mut via_tunnel = false;
    let mut cap: f64 = 0.0;                  // байт/с без ограничения (лучшее измеренное)
    let mut last_err = String::new();
    let mut nets = sysinfo::Networks::new_with_refreshed_list();
    for attempt in 0..30u32 {
        if attempt > 0 { sleep_ms(if via_tunnel { 500 } else { 1500 }).await; }
        let c = client(via_tunnel)?;
        let mut req = c.get(url).header("Accept", "application/octet-stream");
        if !buf.is_empty() { req = req.header("Range", format!("bytes={}-", buf.len())); }
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = e.to_string();
                if !via_tunnel && tunnel_ok { via_tunnel = true; crate::remote_log("update.via_tunnel", serde_json::json!({"why": "connect", "have": buf.len()})); }
                continue;
            }
        };
        let st = resp.status().as_u16();
        if st == 200 && !buf.is_empty() { buf.clear(); }
        if st != 200 && st != 206 { last_err = format!("HTTP {st}"); continue; }
        if total.is_none() || st == 200 {
            total = resp.content_length().map(|l| l + buf.len() as u64);
        }
        let t0 = Instant::now();
        let start_len = buf.len();
        let _ = phys_rx(&mut nets);
        let (mut win_t, mut win_ours) = (Instant::now(), 0u64);
        let mut busy = false;
        let mut slow = false;
        loop {
            match resp.chunk().await {
                Ok(Some(ch)) => {
                    buf.extend_from_slice(&ch);
                    win_ours += ch.len() as u64;
                    if let Some(t) = total { if t > 0 {
                        let p = (buf.len() as u64 * 100 / t).min(99);
                        if p != PCT.load(Ordering::SeqCst) { PCT.store(p, Ordering::SeqCst); progress(p); }
                    } }
                    let el = t0.elapsed().as_secs_f64();
                    let got = (buf.len() - start_len) as f64;
                    // раз в секунду: наша скорость и чужой трафик
                    let wdt = win_t.elapsed().as_secs_f64();
                    if wdt >= 1.0 {
                        let all = phys_rx(&mut nets) as f64;
                        let ours = win_ours as f64;
                        let other = ((all - ours) / wdt).max(0.0);
                        if !busy { cap = cap.max(ours / wdt); }
                        busy = other > 50_000.0;
                        win_t = Instant::now(); win_ours = 0;
                    }
                    if !via_tunnel && tunnel_ok && el >= 6.0 && got / el < 500_000.0 && !busy {
                        slow = true;              // напрямую медленно - пробуем туннель
                        break;
                    }
                    if busy && cap > 0.0 {
                        let rate = (cap * 0.4).max(64.0 * 1024.0);
                        let need = win_ours as f64 / rate;
                        let wel = win_t.elapsed().as_secs_f64();
                        if need > wel { sleep_ms(((need - wel) * 1000.0) as u64).await; }
                    }
                }
                Ok(None) => {
                    if total.map(|t| buf.len() as u64 >= t).unwrap_or(true) { return Ok(buf); }
                    last_err = "оборвалось".into();
                    break;
                }
                Err(e) => { last_err = e.to_string(); break; }
            }
        }
        if slow {
            via_tunnel = true;
            crate::remote_log("update.via_tunnel", serde_json::json!({"why": "slow", "kbs": (buf.len() - start_len) as u64 / 1024 / 6, "have": buf.len()}));
            continue;
        }
        if !via_tunnel && tunnel_ok { via_tunnel = true; }   // обрыв напрямую - докачиваем через туннель
        crate::remote_log("update.resume", serde_json::json!({"have": buf.len(), "err": last_err, "tunnel": via_tunnel}));
    }
    Err(format!("Не удалось скачать обновление: {last_err}"))
}

/// Подпись minisign (как в tauri-plugin-updater): ключ и подпись - base64 от текстового minisign.
pub fn verify(data: &[u8], sig_b64: &str, pub_b64: &str) -> Result<(), String> {
    use base64::Engine;
    let dec = |s: &str| base64::engine::general_purpose::STANDARD.decode(s.trim()).map_err(|e| e.to_string())
        .and_then(|v| String::from_utf8(v).map_err(|e| e.to_string()));
    let pk = minisign_verify::PublicKey::decode(&dec(pub_b64)?).map_err(|e| e.to_string())?;
    let sig = minisign_verify::Signature::decode(&dec(sig_b64)?).map_err(|e| e.to_string())?;
    pk.verify(data, &sig, true).map_err(|e| format!("подпись не сошлась: {e}"))
}
