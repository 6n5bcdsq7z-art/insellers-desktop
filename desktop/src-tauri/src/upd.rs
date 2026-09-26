//! Загрузка обновления (26.09 ночь, владелец: «обновление не должно мешать человеку ни секунды»).
//! - Одна загрузка за раз: повторный запрос (кнопка, перезагрузка страницы, автопроверка) не начинает новую, а показывает
//!   прогресс текущей. 26.09 у владельца шли три загрузки сразу, полоса прыгала 52% -> 3% -> 52%, сеть легла.
//! - Напрямую с нашего сервера (vpn.insellers.su = IP сервера, в TUN и в ядре он и так мимо туннеля); не открылся напрямую -
//!   через туннель (HTTP-вход ядра). VPN при загрузке не трогаем.
//! - Не больше ~40% канала: первые 1.5 с меряем скорость, дальше держим 40% от неё (не меньше 64 КБ/с).
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
        .read_timeout(Duration::from_secs(30));
    let b = if via_tunnel {
        b.proxy(reqwest::Proxy::all(format!("http://127.0.0.1:{}", crate::vpn::HTTP_PORT)).map_err(|e| e.to_string())?)
    } else { b.no_proxy() };
    b.build().map_err(|e| e.to_string())
}

/// Скачать файл обновления. `progress(pct)` - 0..100.
pub async fn fetch(url: &str, tunnel_ok: bool, mut progress: impl FnMut(u64)) -> Result<Vec<u8>, String> {
    let mut buf: Vec<u8> = Vec::new();
    let mut total: Option<u64> = None;
    let mut via_tunnel = false;
    let mut rate: f64 = 0.0;                 // байт/с, 0 - ещё меряем
    let mut last_err = String::new();
    for attempt in 0..30u32 {
        if attempt > 0 { sleep_ms(3000).await; }
        let c = client(via_tunnel)?;
        let mut req = c.get(url).header("Accept", "application/octet-stream");
        if !buf.is_empty() { req = req.header("Range", format!("bytes={}-", buf.len())); }
        let mut resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                last_err = e.to_string();
                // напрямую не открылся ни разу - через туннель (если VPN включён)
                if !via_tunnel && buf.is_empty() && attempt >= 1 && tunnel_ok { via_tunnel = true; crate::remote_log("update.via_tunnel", serde_json::json!({})); }
                continue;
            }
        };
        let st = resp.status().as_u16();
        if st == 200 && !buf.is_empty() { buf.clear(); }           // сервер не умеет докачку - сначала
        if st != 200 && st != 206 { last_err = format!("HTTP {st}"); continue; }
        if total.is_none() || st == 200 {
            total = resp.content_length().map(|l| l + buf.len() as u64);
        }
        let t0 = Instant::now();
        let start_len = buf.len();
        loop {
            match resp.chunk().await {
                Ok(Some(ch)) => {
                    buf.extend_from_slice(&ch);
                    if let Some(t) = total { if t > 0 {
                        let p = (buf.len() as u64 * 100 / t).min(99);
                        if p != PCT.load(Ordering::SeqCst) { PCT.store(p, Ordering::SeqCst); progress(p); }
                    } }
                    let el = t0.elapsed().as_secs_f64();
                    let got = (buf.len() - start_len) as f64;
                    if rate == 0.0 {
                        if el >= 1.5 { rate = (got / el * 0.4).max(64.0 * 1024.0); }
                    } else {
                        let need = got / rate;                      // столько секунд должна была занять эта часть
                        if need > el { sleep_ms(((need - el) * 1000.0) as u64).await; }
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
