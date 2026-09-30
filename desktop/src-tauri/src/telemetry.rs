//! События пути в единой схеме (01.10, владелец: система отслеживания продукта, sv=2) - как на Android (Telemetry.kt):
//! vpn.attempt {attempt_id, path, protocol, server, trigger}, vpn.result {attempt_id, result, ms, failure_stage, error_code},
//! vpn.first_traffic {attempt_id, ms_from_connect, bytes}, vpn.disconnect {attempt_id, connected_ms, bytes_up, bytes_down, reason},
//! vpn.core_panic {last_line, exit_code, protocol}, net.captive {code}. Без адресов и доменов: сервер - NL-1/NL-2, путь - вид.
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

static ATTEMPT: Mutex<String> = Mutex::new(String::new());
static TRIGGER: Mutex<String> = Mutex::new(String::new());
static STOP_REASON: Mutex<String> = Mutex::new(String::new());
static ATTEMPT_AT: AtomicU64 = AtomicU64::new(0);
static CONNECTED_AT: AtomicU64 = AtomicU64::new(0);
static RESULTED: AtomicU64 = AtomicU64::new(0);
static RX: AtomicU64 = AtomicU64::new(0);
static TX: AtomicU64 = AtomicU64::new(0);
static FIRST_SENT: AtomicU64 = AtomicU64::new(0);
static CAPTIVE_AT: AtomicU64 = AtomicU64::new(0);

fn server() -> String {
    let d = crate::vpn::cur_desc();
    if d.contains("176.124.198.72") || d.contains("2a01:e5c0") { "NL-1".into() } else if d.contains("212.34.151.212") { "NL-2".into() }
    else if crate::vpn::cur_path() == "awg" { "awg".into() } else { "".into() }
}

pub fn set_trigger(t: &str) { *TRIGGER.lock().unwrap() = t.to_string(); }
pub fn set_stop_reason(r: &str) { *STOP_REASON.lock().unwrap() = r.to_string(); }

fn protocol() -> String { let p = crate::vpn::cur_path(); if p.is_empty() { "auto".into() } else { p.split(['@', '~']).next().unwrap_or("").to_string() } }
fn scrub(s: &str) -> String {
    s.split_whitespace().map(|w| if w.chars().filter(|c| *c == '.').count() == 3 && w.chars().any(|c| c.is_ascii_digit()) { "<ip>" } else { w })
        .collect::<Vec<_>>().join(" ").chars().take(100).collect()
}

pub fn attempt(server: &str) {
    let id = format!("{:x}", crate::now_ms() ^ 0x5bd1e995);
    *ATTEMPT.lock().unwrap() = id.clone();
    ATTEMPT_AT.store(crate::now_ms(), Ordering::Relaxed); RESULTED.store(0, Ordering::Relaxed); CONNECTED_AT.store(0, Ordering::Relaxed);
    let trig = { let mut t = TRIGGER.lock().unwrap(); let v = if t.is_empty() { "auto".to_string() } else { t.clone() }; t.clear(); v };
    crate::remote_log("vpn.attempt", json!({"attempt_id": id, "path": protocol(), "protocol": protocol(), "server": if server.is_empty() { self::server() } else { server.to_string() }, "trigger": trig}));
}

pub fn result(res: &str, stage: &str, code: &str) {
    if RESULTED.swap(1, Ordering::Relaxed) == 1 { return; }
    let id = ATTEMPT.lock().unwrap().clone();
    if id.is_empty() { return; }
    let mut o = json!({"attempt_id": id, "result": res, "ms": crate::now_ms().saturating_sub(ATTEMPT_AT.load(Ordering::Relaxed))});
    if !stage.is_empty() { o["failure_stage"] = json!(stage); }
    if !code.is_empty() { o["error_code"] = json!(scrub(code)); }
    if res == "connected" {
        // путь известен только после подключения (Автовыбор выбирает сам) - в результате, без адреса
        o["path"] = json!(protocol()); o["server"] = json!(server());
    }
    crate::remote_log("vpn.result", o);
    if res == "connected" {
        CONNECTED_AT.store(crate::now_ms(), Ordering::Relaxed);
        RX.store(0, Ordering::Relaxed); TX.store(0, Ordering::Relaxed); FIRST_SENT.store(0, Ordering::Relaxed);
    }
}

/// Раз в 2 с из цикла статуса (main.rs): объём по физическим интерфейсам за 2 с; первый трафик после подключения - событие.
static STALL_FROM: AtomicU64 = AtomicU64::new(0);
static STALL_TX: AtomicU64 = AtomicU64::new(0);

pub fn tick(rx: u64, tx: u64) {
    let at = CONNECTED_AT.load(Ordering::Relaxed);
    if at == 0 { STALL_FROM.store(0, Ordering::Relaxed); return; }
    // P1 (01.10): зависание - отправляем, а в ответ > 8 с ничего (простой без запросов - не зависание). Событие - когда данные вернулись.
    let now = crate::now_ms();
    if rx < 200 && tx > 0 {
        if STALL_FROM.load(Ordering::Relaxed) == 0 { STALL_FROM.store(now, Ordering::Relaxed); STALL_TX.store(0, Ordering::Relaxed); }
        STALL_TX.fetch_add(tx, Ordering::Relaxed);
    } else if rx >= 200 {
        let from = STALL_FROM.swap(0, Ordering::Relaxed);
        if from > 0 && now.saturating_sub(from) >= 8_000 && STALL_TX.load(Ordering::Relaxed) > 0 {
            crate::remote_log("vpn.traffic_stall", json!({"path": protocol(), "stall_ms": now.saturating_sub(from), "bytes_before": RX.load(Ordering::Relaxed),
                "attempt_id": ATTEMPT.lock().unwrap().clone()}));
        }
    }
    let got = RX.fetch_add(rx, Ordering::Relaxed) + rx;
    TX.fetch_add(tx, Ordering::Relaxed);
    if got > 1500 && FIRST_SENT.swap(1, Ordering::Relaxed) == 0 {
        crate::remote_log("vpn.first_traffic", json!({"attempt_id": ATTEMPT.lock().unwrap().clone(), "ms_from_connect": crate::now_ms().saturating_sub(at), "bytes": got}));
    }
}

pub fn disconnect() {
    let at = CONNECTED_AT.swap(0, Ordering::Relaxed);
    let reason = { let mut r = STOP_REASON.lock().unwrap(); let v = if r.is_empty() { "unknown".to_string() } else { r.clone() }; r.clear(); v };
    if at == 0 { return; }
    crate::remote_log("vpn.disconnect", json!({"attempt_id": ATTEMPT.lock().unwrap().clone(), "connected_ms": crate::now_ms().saturating_sub(at),
        "bytes_up": TX.load(Ordering::Relaxed), "bytes_down": RX.load(Ordering::Relaxed), "reason": reason}));
}

/// Поля схемы для смены пути (vpn.path_switch / vpn.hot_switch).
pub fn switch_fields(mut o: Value, reason: &str) -> Value {
    let at = CONNECTED_AT.load(Ordering::Relaxed);
    o["reason"] = json!(reason);
    o["time_since_connect"] = json!(if at > 0 { crate::now_ms().saturating_sub(at) as i64 } else { -1 });
    o["traffic_before"] = json!(RX.load(Ordering::Relaxed));
    o["attempt_id"] = json!(ATTEMPT.lock().unwrap().clone());
    o
}

pub fn core_panic(last: &str, code: Option<i32>) {
    crate::remote_log("vpn.core_panic", json!({"last_line": scrub(last), "exit_code": code, "protocol": protocol()}));
}

/// Портал Wi-Fi перед подключением: generate_204 напрямую. true - портал. Повторное нажатие в течение минуты - без проверки.
pub async fn captive() -> bool {
    if crate::now_ms().saturating_sub(CAPTIVE_AT.load(Ordering::Relaxed)) < 60_000 { return false; }
    let c = match reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(2)).build() { Ok(c) => c, Err(_) => return false };
    match c.get("http://connectivitycheck.gstatic.com/generate_204").send().await {
        Ok(r) if r.status().as_u16() != 204 => {
            CAPTIVE_AT.store(crate::now_ms(), Ordering::Relaxed);
            crate::remote_log("net.captive", json!({"code": r.status().as_u16()}));
            true
        }
        _ => false,
    }
}
