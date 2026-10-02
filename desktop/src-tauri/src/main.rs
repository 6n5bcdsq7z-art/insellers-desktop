// INSELLERS VPN — оболочка для Windows/macOS.
// Интерфейс грузится с https://vpn.insellers.su (изменения видны сразу).
// Вход через бота (как в Android), токен в системном хранилище (Keychain / Credential Manager),
// самообновление с проверкой подписи (tauri-plugin-updater), навигация только на свой домен.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vpn;
mod check;
mod probe;
mod tun;
mod upd;
mod telemetry;

use std::time::Duration;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;

pub const BASE: &str = "https://vpn.insellers.su";
/// 29.09: запасной адрес бэкенда - через NL-2 (nginx n2.insellers.su /api/app/ -> Hetzner по WG)
pub const BASE_ALT: &str = "https://n2.insellers.su";
const HOST: &str = "vpn.insellers.su";

fn keyring_entry() -> Option<keyring::Entry> {
    keyring::Entry::new("su.insellers.vpn", "session").ok()
}

/// Папка данных приложения (без AppHandle — для токена и id установки).
fn data_path(name: &str) -> Option<std::path::PathBuf> {
    let base = if cfg!(target_os = "macos") {
        std::env::var("HOME").ok().map(|h| std::path::PathBuf::from(h).join("Library/Application Support/su.insellers.vpn"))
    } else if cfg!(target_os = "windows") {
        std::env::var("APPDATA").ok().map(|h| std::path::PathBuf::from(h).join("su.insellers.vpn"))
    } else {
        std::env::var("HOME").ok().map(|h| std::path::PathBuf::from(h).join(".local/share/su.insellers.vpn"))
    }?;
    let _ = std::fs::create_dir_all(&base);
    Some(base.join(name))
}

fn write_private(p: &std::path::Path, v: &str) -> bool {
    if std::fs::write(p, v).is_err() { return false; }
    #[cfg(unix)]
    { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o600)); }
    true
}

/// Токен: системное хранилище паролей, а если оно недоступно (неподписанное приложение на macOS) — файл 0600.
pub fn load_token() -> String {
    let k = keyring_entry().and_then(|e| e.get_password().ok()).unwrap_or_default();
    if !k.is_empty() { return k; }
    data_path("session.token").and_then(|p| std::fs::read_to_string(p).ok()).unwrap_or_default().trim().to_string()
}
fn save_token(t: &str) -> (bool, bool) {
    let kr = if let Some(e) = keyring_entry() {
        if t.is_empty() { let _ = e.delete_credential(); true } else { e.set_password(t).is_ok() }
    } else { false };
    let file = match data_path("session.token") {
        Some(p) => if t.is_empty() { let _ = std::fs::remove_file(&p); true } else { write_private(&p, t) },
        None => false,
    };
    (kr, file)
}

/// VPN до входа (ограниченный режим - только Telegram, чтобы зайти в Telegram и войти): ссылку выдаёт сервер (POST /api/app/guest — делает страница),
/// здесь только храним её со сроком (мс по часам этого компьютера) и проверяем.
const GUEST_PREFIX: &str = "https://direct.insellers.su/vpn/";
// 27.09 (владелец, tasks/0000): ограниченный режим БЕССРОЧНЫЙ - срок страницы не проверяем, ссылка действует, пока её не отзовут
const GUEST_MAX_MS: u64 = 31 * 86_400_000;
pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}
fn guest_valid(u: &str) -> bool {
    u.starts_with(GUEST_PREFIX) && u.len() >= GUEST_PREFIX.len() + 4 && u.len() <= 300
        && !u.chars().any(|c| c.is_whitespace() || c == '"' || c == '\\')
}
/// (ссылка, конец в мс), пока гостевой доступ действует.
pub fn guest_load() -> Option<(String, u64)> {
    let t = std::fs::read_to_string(data_path("guest.json")?).ok()?;
    let v: serde_json::Value = serde_json::from_str(&t).ok()?;
    let url = v["url"].as_str()?.to_string();
    let _ = v["until"].as_u64();
    if guest_valid(&url) { Some((url, now_ms() + GUEST_MAX_MS)) } else { None }
}
fn guest_save(url: &str, until: u64) {
    if let Some(p) = data_path("guest.json") { write_private(&p, &serde_json::json!({"url": url, "until": until}).to_string()); }
}
pub fn guest_clear() { if let Some(p) = data_path("guest.json") { let _ = std::fs::remove_file(p); } }
pub fn guest_until() -> u64 { guest_load().map(|(_, u)| u).unwrap_or(0) }

/// Настройки поведения на этом компьютере (prefs.json рядом с данными приложения).
pub fn prefs() -> serde_json::Value {
    let mut v = serde_json::json!({"autoconnect": true, "reconnect": true, "killswitch": false, "theme_light": false, "lang_en": false});
    if let Some(p) = data_path("prefs.json") {
        if let Ok(t) = std::fs::read_to_string(p) {
            if let Ok(serde_json::Value::Object(m)) = serde_json::from_str::<serde_json::Value>(&t) {
                for (k, x) in m { if x.is_boolean() { v[k] = x; } }
            }
        }
    }
    v
}
pub fn pref(k: &str) -> bool { prefs()[k].as_bool().unwrap_or(false) }
fn set_pref(app: &AppHandle, k: &str, val: bool) {
    if !["autoconnect", "reconnect", "killswitch"].contains(&k) { return; }
    let mut v = prefs(); v[k] = serde_json::Value::Bool(val);
    if let Some(p) = data_path("prefs.json") { write_private(&p, &v.to_string()); }
    if k == "autoconnect" { apply_autostart(app, val); }
}
/// Запуск вместе с системой — вместе с «Автоподключением».
fn apply_autostart(app: &AppHandle, on: bool) {
    use tauri_plugin_autostart::ManagerExt;
    let m = app.autolaunch();
    let _ = if on { m.enable() } else { m.disable() };
}

pub fn host_model() -> String {
    let os = if cfg!(target_os = "macos") { "Mac" } else if cfg!(target_os = "windows") { "Windows" } else { "Linux" };
    format!("{} {}", os, sysinfo::System::host_name().unwrap_or_default()).trim().to_string()
}

/// id установки для диагностики
pub fn install_id() -> String {
    if let Some(p) = data_path("install.id") {
        if let Ok(v) = std::fs::read_to_string(&p) { if !v.trim().is_empty() { return v.trim().to_string(); } }
        let id = format!("d{:x}", std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        write_private(&p, &id);
        return id;
    }
    "unknown".into()
}

/// Диагностический лог на сервер (без секретов). 01.10 (владелец, схема sv=2 - как мини-апп applog.js): контекст install, sid, sv, platform,
/// version, vpn, path; очередь <= 300, склейка одинаковых событий за 60 с (счётчик n), пачка по 50 - раз в 30 с, при 50 событиях, при
/// событиях связи и при скрытии окна / выходе (flush_logs); 5xx / 429 / нет сети - повтор с растущей паузой 4 с ... 5 мин.
static LOG_QUEUE: std::sync::Mutex<Vec<serde_json::Value>> = std::sync::Mutex::new(Vec::new());
static LOG_BACKOFF: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LOG_FAIL_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LOG_SENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static LOG_TIMER: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static LOG_SID: std::sync::OnceLock<String> = std::sync::OnceLock::new();

pub fn remote_log(ev: &str, data: serde_json::Value) {
    use std::sync::atomic::Ordering;
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let (n, urgent) = {
        let mut q = LOG_QUEUE.lock().unwrap();
        let key = data.to_string();
        if let Some(e) = q.iter_mut().rev().find(|e| e["ev"] == ev && now.saturating_sub(e["ts"].as_u64().unwrap_or(0)) < 60 && e["_k"] == key.as_str()) {
            e["n"] = serde_json::json!(e["n"].as_u64().unwrap_or(1) + 1);
        } else {
            q.push(serde_json::json!({"ts": now, "ev": ev, "data": data, "_k": key}));
        }
        if q.len() > 300 {
            let mut i = 0;
            while q.len() > 300 && i < q.len() { if q[i]["ev"].as_str().unwrap_or("").starts_with("perf.") { q.remove(i); } else { i += 1; } }
            let over = q.len().saturating_sub(300); q.drain(..over);
        }
        (q.len(), ev.starts_with("vpn.") || ev.starts_with("net.") || ev.starts_with("update."))
    };
    if !LOG_TIMER.swap(true, Ordering::Relaxed) {
        tauri::async_runtime::spawn(async { loop { tokio_sleep(30).await; flush_logs(false).await; } });
    }
    if n >= 50 || urgent { tauri::async_runtime::spawn(async { flush_logs(false).await; }); }
}

/// Отправить накопленное (force - мимо паузы: окно скрыто / выход).
pub async fn flush_logs(force: bool) {
    use std::sync::atomic::Ordering;
    if LOG_SENDING.swap(true, Ordering::Relaxed) { return; }
    loop {
        if !force && LOG_BACKOFF.load(Ordering::Relaxed) > 0 && now_ms() < LOG_FAIL_AT.load(Ordering::Relaxed) { break; }
        let batch: Vec<serde_json::Value> = { let q = LOG_QUEUE.lock().unwrap(); q.iter().take(50).cloned().collect() };
        if batch.is_empty() { break; }
        let os = if cfg!(target_os = "macos") { "mac" } else if cfg!(target_os = "windows") { "windows" } else { "linux" };
        let sid = LOG_SID.get_or_init(|| format!("{:x}", now_ms())).clone();
        let evs: Vec<serde_json::Value> = batch.iter().map(|e| { let mut d = e["data"].clone(); if let Some(n) = e["n"].as_u64() { d["n"] = serde_json::json!(n); }
            serde_json::json!({"ts": e["ts"], "ev": e["ev"], "data": d}) }).collect();
        let body = serde_json::json!({"ctx": {"install": install_id(), "platform": format!("desktop-{os}-native"), "version": env!("CARGO_PKG_VERSION"),
                                              "sid": sid, "sv": 2, "path": vpn::cur_path()}, "events": evs});
        // 26.09: сначала мимо системного прокси (= нашего туннеля): событие «путь умер» через мёртвый путь не дошло бы
        let t = load_token();
        let mut code = 0u16;
        for direct in [true, false] {
            let b = reqwest::Client::builder().timeout(Duration::from_secs(10));
            let b = if direct { b.no_proxy() } else { b };
            if let Ok(c) = b.build() {
                let mut rq = c.post(format!("{BASE}/api/app/log")).json(&body);
                if !t.is_empty() { rq = rq.header("X-App-Token", t.clone()); }
                if let Ok(r) = rq.send().await { code = r.status().as_u16(); if r.status().is_success() { break; } }
            }
        }
        if (200..300).contains(&code) || ((400..500).contains(&code) && code != 429) {   // принято или отвергнуто навсегда - убираем
            let mut q = LOG_QUEUE.lock().unwrap();
            let sent: std::collections::HashSet<String> = batch.iter().map(|e| e.to_string()).collect();
            q.retain(|e| !sent.contains(&e.to_string()));
            LOG_BACKOFF.store(0, Ordering::Relaxed);
        } else {
            let b = LOG_BACKOFF.load(Ordering::Relaxed);
            let nb = if b == 0 { 4_000 } else { (b * 2).min(300_000) };
            LOG_BACKOFF.store(nb, Ordering::Relaxed); LOG_FAIL_AT.store(now_ms() + nb, Ordering::Relaxed);
            break;
        }
    }
    LOG_SENDING.store(false, Ordering::Relaxed);
}

/// 30.09 (владелец: окно на Mac ушло в чёрный экран - страница перезагрузилась в 10 с перезапуска сервера, получила 502 и
/// осталась на странице ошибки без нашего кода). Сторож страницы: страница раз в 5 с шлёт «жива» (page_alive); окно на экране
/// и в фокусе, а сигнала нет 15 с - перезагрузить; 3 раза подряд без толку - встроенный экран «Переподключаемся…» (заставка
/// dist/index.html?reconnect=<причина>, повтор каждые 5 с по проверке сервера server_ok). Страница ошибки (5xx) - сразу туда же.
/// Процесс WebKit упал - Tauri (с 2.11) перезагружает страницу сам; наш след - page_crashed (страница умерла без выгрузки).
/// Каждый случай - в журнал: desktop.reload {why, n} / desktop.crash {why}.
static LAST_ALIVE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static LOAD_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static SEEN_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);   // окно стало видимым / в фокусе / проснулись
static WD_RELOAD_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static WD_FAILS: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
static ALIVE_VIA: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);    // 1 - IPC Tauri, 2 - переход /__native/
const WD_SILENT_MS: u64 = 15_000;

/// 30.09 (владелец, Алеся на SOVAM): страница не пришла напрямую за 3 с при включённом VPN - окно пересоздаётся с прокси
/// на локальный вход ядра page-in (страница идёт через туннель) до перезапуска приложения. У части операторов фильтр режет
/// приветствие шифрования в 2 пакета (у WebKit и WebView2 - постквантовый ключ), а запросы самого приложения проходят.
/// macOS - прокси окна только с macOS 14. Журнал desktop.page_fallback {why, mac}.
static PAGE_PROXY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
static WIN_BG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// 30.09 (владелец: нагрев/батарея): процессорное время нашего процесса и его ядер (xray / sing-box / wireproxy / помощник) - `ps`
/// (Mac, Linux), мс накопленно. Windows - нет (None).
fn proc_cpu_ms() -> Option<(u64, u64)> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let me = std::process::id();
        let out = std::process::Command::new("ps").args(["-A", "-o", "pid=,ppid=,time="]).output().ok()?;
        let txt = String::from_utf8_lossy(&out.stdout).to_string();
        let mut rows: Vec<(u32, u32, u64)> = Vec::new();
        for l in txt.lines() {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 3 { continue; }
            let (Ok(pid), Ok(ppid)) = (f[0].parse::<u32>(), f[1].parse::<u32>()) else { continue };
            // время: [[дд-]чч:]мм:сс[.сс]
            let t = f[2]; let (d, rest) = t.split_once('-').map(|(a, b)| (a.parse::<u64>().unwrap_or(0), b)).unwrap_or((0, t));
            let parts: Vec<f64> = rest.split(':').map(|x| x.parse::<f64>().unwrap_or(0.0)).collect();
            let secs = parts.iter().fold(0.0, |acc, x| acc * 60.0 + x) + d as f64 * 86400.0;
            rows.push((pid, ppid, (secs * 1000.0) as u64));
        }
        let own = rows.iter().find(|r| r.0 == me).map(|r| r.2).unwrap_or(0);
        let mut kids: Vec<u32> = vec![me]; let mut core = 0u64; let mut i = 0;
        while i < kids.len() {
            let p = kids[i];
            for r in rows.iter().filter(|r| r.1 == p) { kids.push(r.0); core += r.2; }
            i += 1;
            if kids.len() > 64 { break; }
        }
        return Some((own, core));
    }
    #[allow(unreachable_code)]
    None
}

fn battery() -> (i64, bool) {
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("pmset").args(["-g", "batt"]).output() {
            let t = String::from_utf8_lossy(&o.stdout).to_string();
            let pct = t.split('%').next().and_then(|a| a.rsplit(|c: char| !c.is_ascii_digit()).next()).and_then(|x| x.parse().ok()).unwrap_or(-1);
            return (pct, t.contains("AC Power"));
        }
    }
    (-1, false)
}

/// Раз в 5 мин - desktop.power: процессор приложения и ядер за период, окно (на экране / свёрнуто / скрыто), батарея. Сводка - ops/diag/power.py.
fn start_power(h: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut prev = proc_cpu_ms(); let mut t0 = now_ms();
        loop {
            tokio_sleep(300).await;
            let cur = proc_cpu_ms(); let t = now_ms();
            let (fg, vis) = h.get_webview_window("main").map(|w| (w.is_focused().unwrap_or(false), w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false))).unwrap_or((false, false));
            let (bat, chg) = battery();
            let (cpu, core) = match (prev, cur) { (Some(a), Some(b)) => (b.0.saturating_sub(a.0) as i64, b.1.saturating_sub(a.1) as i64), _ => (-1, -1) };
            remote_log("desktop.power", serde_json::json!({"cpu_ms": cpu, "core_ms": core, "sec": (t - t0) / 1000, "fg": fg,
                "screen": vis, "vpn": vpn_running(&h), "bat": bat, "chg": chg}));
            prev = cur; t0 = t;
        }
    });
}
static PAGE_DONE_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn mac_major() -> u32 {
    #[cfg(target_os = "macos")]
    {
        return std::process::Command::new("sw_vers").arg("-productVersion").output().ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| v.trim().split('.').next().and_then(|x| x.parse().ok())).unwrap_or(0);
    }
    #[allow(unreachable_code)]
    99
}

fn page_proxy_ok() -> bool { !cfg!(target_os = "macos") || mac_major() >= 14 }

/// Навигация на нашу страницу началась: через 3 с нет ни загрузки, ни сигнала «жива» - запасной путь через туннель.
fn arm_page_fallback(app: &AppHandle) {
    use std::sync::atomic::Ordering::Relaxed;
    if PAGE_PROXY.load(Relaxed) { return; }
    let started = now_ms();
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio_sleep(3).await;                          // 30.09 (владелец): 3 с (было 6)
        if PAGE_PROXY.load(Relaxed) || PAGE_DONE_AT.load(Relaxed) >= started || LAST_ALIVE.load(Relaxed) >= started { return; }
        if !vpn_running(&a) { return; }
        if !page_proxy_ok() {
            remote_log("desktop.page_fallback", serde_json::json!({"why": "slow", "done": false, "mac": mac_major()}));
            return;
        }
        PAGE_PROXY.store(true, Relaxed);
        remote_log("desktop.page_fallback", serde_json::json!({"why": "slow", "done": true, "mac": mac_major()}));
        let b = a.clone();
        let _ = a.run_on_main_thread(move || { let _ = build_main(&b); });
    });
}

fn app_url(app: &AppHandle) -> String { format!("https://{HOST}/?app=desktop&v={}", app.package_info().version) }

/// Встроенная заставка в режиме «Переподключаемся…» (macOS/Linux - tauri://localhost, Windows - http://tauri.localhost).
fn reconnect_url(why: &str) -> String {
    let base = if cfg!(target_os = "windows") { "http://tauri.localhost/index.html" } else { "tauri://localhost/index.html" };
    let why: String = why.chars().filter(|c| c.is_ascii_alphanumeric() || *c == '_').take(24).collect();
    format!("{base}?reconnect={why}")
}

fn show_reconnect(app: &AppHandle, why: &str) {
    if let Some(w) = app.get_webview_window("main") {
        if let Ok(u) = url::Url::parse(&reconnect_url(why)) { let _ = w.navigate(u); }
    }
}

/// Сигнал «страница жива» (IPC или переход /__native/alive).
fn mark_alive(via: u8) {
    LAST_ALIVE.store(now_ms(), std::sync::atomic::Ordering::Relaxed);
    WD_FAILS.store(0, std::sync::atomic::Ordering::Relaxed);
    ALIVE_VIA.store(via, std::sync::atomic::Ordering::Relaxed);
}

/// Страница сообщила, что загрузилась страница ошибки (502 во время выкладки и т.п.) - сразу встроенный экран с повтором.
fn on_page_failed(app: &AppHandle, why: &str) {
    remote_log("desktop.reload", serde_json::json!({"why": why, "to": "screen"}));
    show_reconnect(app, why);
}

/// Страница после загрузки увидела, что прошлая умерла без выгрузки (падение процесса WebKit или зависание).
fn on_page_crashed(arg: &serde_json::Value) {
    // своя перезагрузка сторожа только что - уже записана как desktop.reload
    if now_ms().saturating_sub(WD_RELOAD_AT.load(std::sync::atomic::Ordering::Relaxed)) < 30_000 { return; }
    remote_log("desktop.crash", serde_json::json!({"why": "no_unload", "ago_ms": arg["ago"].as_u64().unwrap_or(0), "nav": arg["nav"].as_str().unwrap_or("")}));
}

#[tauri::command]
fn page_alive() { mark_alive(1); }

#[tauri::command]
fn page_failed(app: AppHandle, why: String) { on_page_failed(&app, &why); }

#[tauri::command]
fn page_crashed(ago: Option<u64>, nav: Option<String>) { on_page_crashed(&serde_json::json!({"ago": ago.unwrap_or(0), "nav": nav.unwrap_or_default()})); }

/// Для заставки: сервер страницы отвечает по-настоящему (200 и «ok»), а не 502 - сначала напрямую, потом через системный прокси.
/// 30.09 (владелец): кнопка «Отправить отчёт об ошибке» на экране загрузки (как на Android). Обращение уходит запросом самого
/// приложения (не страницы): напрямую, не вышло - через вход ядра (туннель), потом через сервер NL-2. Владельцу - как «Не работает?».
#[tauri::command]
async fn splash_report(app: AppHandle, why: String, secs: u64) -> bool {
    let tok = load_token();
    let why: String = why.chars().take(120).collect();
    let body = serde_json::json!({
        "text": format!("Экран загрузки приложения на компьютере: «{why}», {secs} с"),
        "n_img": 0,
        "diag": {"platform": format!("desktop-{}", std::env::consts::OS), "version": app.package_info().version.to_string(),
                 "model": host_model(), "os": std::env::consts::OS, "vpn": if vpn_running(&app) { "connected" } else { "disconnected" },
                 "page": "splash", "splash": why, "secs": secs}
    });
    remote_log("splash.report", serde_json::json!({"why": why, "secs": secs}));
    let tries: [(&str, Option<u16>); 3] = [(BASE, None), (BASE, Some(vpn::PROBE_PORT)), (BASE_ALT, None)];
    for (base, proxy) in tries {
        let b = reqwest::Client::builder().timeout(Duration::from_secs(12));
        let b = match proxy {
            Some(p) => match reqwest::Proxy::all(format!("http://127.0.0.1:{p}")) { Ok(px) => b.proxy(px), Err(_) => continue },
            None => b.no_proxy(),
        };
        let Ok(c) = b.build() else { continue };
        let mut rq = c.post(format!("{base}/api/app/feedback")).json(&body);
        if !tok.is_empty() { rq = rq.header("X-App-Token", tok.clone()); }
        if let Ok(r) = rq.send().await { if r.status().is_success() { return true; } }
    }
    false
}

#[tauri::command]
async fn server_ok() -> bool {
    for direct in [true, false] {
        let b = reqwest::Client::builder().timeout(Duration::from_secs(5));
        let b = if direct { b.no_proxy() } else { b };
        let Ok(c) = b.build() else { continue };
        if let Ok(r) = c.get(format!("{BASE}/health?wd={}", now_ms())).send().await {
            if r.status().is_success() && r.text().await.map(|t| t.contains("ok")).unwrap_or(false) { return true; }
        }
    }
    false
}

/// Раз в 5 с: окно на экране и в фокусе, открыта наша страница, сигнала «жива» нет 15 с - перезагрузить; 3 раза - экран.
fn start_watchdog(h: AppHandle) {
    use std::sync::atomic::Ordering::Relaxed;
    tauri::async_runtime::spawn(async move {
        let mut last_tick = now_ms();
        let mut acts: Vec<u64> = Vec::new();             // предохранитель: не больше 6 срабатываний в час
        loop {
            tokio_sleep(5).await;
            let now = now_ms();
            // сон компьютера / долгая пауза: таймеры страницы тоже стояли - отсчёт заново
            if now.saturating_sub(last_tick) > 20_000 { SEEN_AT.store(now, Relaxed); }
            last_tick = now;
            let Some(w) = h.get_webview_window("main") else { continue };
            // 30.09 (владелец: нагрев): окно скрыто/свёрнуто - странице флаг «в фоне» (анимации и реклама в полосе стоят)
            let bg = !w.is_visible().unwrap_or(true) || w.is_minimized().unwrap_or(false);
            if bg != WIN_BG.swap(bg, Relaxed) {
                let _ = w.eval(&format!("window.__INS_BG={bg};window.dispatchEvent(new CustomEvent('ins:bg',{{detail:{{bg:{bg}}}}}))"));
            }
            let shown = w.is_visible().unwrap_or(false) && !w.is_minimized().unwrap_or(false) && w.is_focused().unwrap_or(false);
            if !shown { continue; }
            let on_page = w.url().map(|u| u.host_str() == Some(HOST)).unwrap_or(false);
            if !on_page { continue; }                     // заставка / экран переподключения повторяют сами
            let since = LAST_ALIVE.load(Relaxed).max(LOAD_AT.load(Relaxed)).max(SEEN_AT.load(Relaxed));
            if now.saturating_sub(since) < WD_SILENT_MS { continue; }
            acts.retain(|t| now.saturating_sub(*t) < 3_600_000);
            if acts.len() >= 6 {
                if acts.len() == 6 { remote_log("desktop.reload", serde_json::json!({"why": "wd_giveup", "n": 6})); acts.push(now); }
                continue;
            }
            acts.push(now);
            let n = WD_FAILS.fetch_add(1, Relaxed) + 1;
            WD_RELOAD_AT.store(now, Relaxed);
            LOAD_AT.store(now, Relaxed);
            let silent = now.saturating_sub(LAST_ALIVE.load(Relaxed));
            if n >= 3 {
                WD_FAILS.store(0, Relaxed);
                remote_log("desktop.reload", serde_json::json!({"why": "no_alive", "n": n, "to": "screen", "silent_ms": silent, "via": ALIVE_VIA.load(Relaxed)}));
                show_reconnect(&h, "no_alive");
            } else {
                remote_log("desktop.reload", serde_json::json!({"why": "no_alive", "n": n, "to": "page", "silent_ms": silent, "via": ALIVE_VIA.load(Relaxed)}));
                if let Ok(u) = url::Url::parse(&app_url(&h)) { let _ = w.navigate(u); }
            }
        }
    });
}

/// 27.09 (tasks/0000c): срок доступа (мс) со страницы - трей показывает остаток, а не только скорость. 0 - неизвестно.
static ACCESS_UNTIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

fn access_left_text() -> String {
    let until = ACCESS_UNTIL.load(std::sync::atomic::Ordering::Relaxed);
    if until == 0 { return String::new(); }
    let now = now_ms();
    if until <= now { return "только Telegram".to_string(); }
    let left = (until - now) / 1000;
    if left >= 86_400 { format!("осталось {} дн.", left / 86_400) }
    else if left >= 3_600 { format!("осталось {} ч {} мин", left / 3_600, left % 3_600 / 60) }
    else { format!("осталось {} мин", (left / 60).max(1)) }
}

/// Мост для страницы: те же методы, что у Android (window.InsellersNative).
fn init_script(token: &str, version: &str) -> String {
    let tok = serde_json::to_string(token).unwrap_or_else(|_| "\"\"".into());
    let ver = serde_json::to_string(version).unwrap_or_else(|_| "\"\"".into());
    let prefs_js = prefs().to_string();
    let hw = serde_json::to_string(&format!("ins-{}", install_id())).unwrap_or_default();
    let model = serde_json::to_string(&host_model()).unwrap_or_default();
    let guest = guest_until();
    format!(r#"
(function () {{
  if (location.host !== "{HOST}") return;
  window.__INS_PREFS = {prefs_js};
  window.__INS_GUEST_UNTIL = {guest};
  // Канал страница → приложение: переход на /__native/<команда>. Приложение перехватывает его
  // в on_navigation и отменяет — страница остаётся на месте. Не зависит от IPC Tauri для удалённых сайтов.
  var inv = function (cmd, args) {{
    try {{ location.href = "/__native/" + cmd + "?a=" + encodeURIComponent(JSON.stringify(args || {{}})); }} catch (e) {{}}
  }};
  window.InsellersNative = {{
    isApp: function () {{ return true; }},
    getPlatform: function () {{ return "desktop"; }},
    getVersion: function () {{ return {ver}; }},
    getToken: function () {{ try {{ var o = sessionStorage.getItem("ins_tok"); if (o !== null) return o; }} catch (e) {{}} return {tok}; }},
    login: function () {{ inv("login"); }},
    setToken: function (t) {{ inv("set_token", {{ token: t }}); }},
    logout: function () {{ inv("logout"); }},
    checkUpdate: function () {{ inv("check_update", {{ manual: true }}); }},
    installUpdate: function () {{ inv("check_update", {{ manual: true }}); }},
    getConnectedAt: function () {{ return window.__INS_CONN_AT || 0; }},
    getHwid: function () {{ return {hw}; }},
    getModel: function () {{ return {model}; }},
    getSessionBytes: function () {{ return window.__INS_BYTES || 0; }},
    getPref: function (k) {{ return !!(window.__INS_PREFS || {{}})[k]; }},
    setPref: function (k, v) {{ (window.__INS_PREFS = window.__INS_PREFS || {{}})[k] = !!v; inv("set_pref", {{ key: k, value: !!v }}); }},
    openExternal: function (u) {{ inv("open_external", {{ url: u }}); }},
    connect: function () {{ inv("vpn_connect"); }},
    disconnect: function () {{ inv("vpn_disconnect"); }},
    setTheme: function (t) {{ inv("set_theme", {{ theme: String(t) }}); }},
    setLang: function (l) {{ inv("set_lang", {{ lang: String(l) }}); }},
    hasVpn: function () {{ return true; }},
    hasAwg: function () {{ return true; }},
    connectGuest: function (u, t) {{ inv("vpn_guest", {{ url: String(u), until: String(t) }}); }},
    getGuestUntil: function () {{ var g = +window.__INS_GUEST_UNTIL || 0; return String(g > Date.now() ? g : 0); }},
    getVpnState: function () {{ return window.__INS_VPN || "disconnected"; }},
    setAccessUntil: function (ms) {{ inv("set_access", {{ ms: String(ms) }}); }},
    // 29.09: проверка ЧЕРЕЗ туннель из ядра - ответ событием window "ins:probe" {{ok, ms, how}} и в window.__INS_PROBE
    probe: function () {{ inv("probe"); }},
    // 01.10: «Не работает?» - воронка мимо туннеля, ответ событием window "ins:funnel"
    probeFunnel: function () {{ inv("probe_funnel"); }}
  }};
  // 30.09 (владелец: чёрный экран на Mac): сторож. Сначала IPC Tauri, не вышло - переход /__native/ (перехватывает приложение).
  var send = function (cmd, args) {{
    try {{
      var ti = window.__TAURI_INTERNALS__;
      if (ti && ti.invoke) {{ ti.invoke(cmd, args || {{}}).catch(function () {{ inv(cmd, args); }}); return; }}
    }} catch (e) {{}}
    inv(cmd, args);
  }};
  // прошлая страница этой вкладки умерла без выгрузки (упал процесс WebKit / зависла) - след в журнал
  try {{
    var la = +sessionStorage.getItem("__ins_la") || 0, cl = +sessionStorage.getItem("__ins_cl") || 0;
    sessionStorage.removeItem("__ins_la");
    if (la && cl < la && Date.now() - la < 120000) {{
      var nt = "";
      try {{ nt = (performance.getEntriesByType("navigation")[0] || {{}}).type || ""; }} catch (e) {{}}
      var ago = Date.now() - la;
      setTimeout(function () {{ send("page_crashed", {{ ago: ago, nav: nt }}); }}, 1500);
    }}
  }} catch (e) {{}}
  window.addEventListener("pagehide", function () {{ try {{ sessionStorage.setItem("__ins_cl", String(Date.now())); }} catch (e) {{}} }});
  // «жива» раз в 5 с - только наша страница (журнал и полоса баннера на месте), а не страница ошибки
  var ours = function () {{ return typeof window.INS_LOG === "function" || !!document.getElementById("ad-bar"); }};
  var alive = function () {{
    if (document.visibilityState !== "visible" || !ours()) return;
    try {{ sessionStorage.setItem("__ins_la", String(Date.now())); }} catch (e) {{}}
    send("page_alive");
  }};
  setInterval(alive, 5000);
  // страница ошибки вместо приложения (502/503/504 во время выкладки) - сразу встроенный экран с повтором
  var errCheck = function () {{
    if (ours()) return;
    var t = (document.title || "") + " " + ((document.body && document.body.innerText) || "").slice(0, 300);
    var m = t.match(/\b(50[0-9]|52[0-9])\b[^\n]{{0,40}}(Gateway|Error|Unavailable|Time-?out|timed out)/i) || t.match(/(Bad Gateway|Service Unavailable|Gateway Time-?out)/i);
    if (m) send("page_failed", {{ why: "http_" + (m[1] && /^\d+$/.test(m[1]) ? m[1] : "5xx") }});
  }};
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", function () {{ setTimeout(errCheck, 300); alive(); }});
  else {{ setTimeout(errCheck, 300); alive(); }}
  // 29.09 (владелец): во внешний браузер - только переходы по нажатию человека (ссылка, window.open из клика). iframe и
  // фоновые запросы рекламных SDK (GigaPub pxl.iframe, VAST OnClickA, RichAds) остаются внутри окна.
  var ext = function (u) {{
    try {{
      var x = new URL(String(u), location.href);
      if (x.protocol === "tg:") return x.href;
      if ((x.protocol === "https:" || x.protocol === "http:") && x.host !== location.host) return x.href;
    }} catch (e) {{}}
    return null;
  }};
  document.addEventListener("click", function (e) {{
    if (!e.isTrusted) return;                                   // нажатие человека, а не скрипт
    var a = e.target && e.target.closest ? e.target.closest("a[href]") : null;
    var u = a ? ext(a.getAttribute("href")) : null;
    if (!u) return;
    e.preventDefault(); e.stopPropagation();
    inv("open_external", {{ url: u }});
  }}, true);
  var wo = window.open;
  window.open = function (u) {{
    var x = u ? ext(u) : null;
    if (!x) return wo.apply(window, arguments);
    var act = navigator.userActivation ? navigator.userActivation.isActive : true;
    if (act) inv("open_external", {{ url: x }});                // без нажатия (фон SDK) - никуда не открываем
    return {{ closed: false, close: function () {{}}, focus: function () {{}}, blur: function () {{}}, postMessage: function () {{}}, location: {{}} }};
  }};
}})();
"#)
}

// 29.09 (владелец): Windows (WebView2 шлёт UA Edge с «Edg/…») - как обычный Chrome для всей страницы: рекламные сети
// охотнее отдают ролики браузеру, чем встроенному окну. Версия - как у Chromium текущих устройств (журналы, 29.09: 151-156).
#[cfg(target_os = "windows")]
const WIN_CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Safari/537.36";
#[cfg(target_os = "macos")]
const MAC_SAFARI_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.5 Safari/605.1.15";

/// 02.10: фон окна под тему страницы (светлая - слоновая кость, как light.css)
fn theme_bg(light: bool) -> tauri::window::Color {
    if light { tauri::window::Color(0xfa, 0xf7, 0xf2, 255) } else { tauri::window::Color(0, 0, 0, 255) }
}

fn build_main(app: &AppHandle) -> tauri::Result<()> {
    if let Some(w) = app.get_webview_window("main") { let _ = w.destroy(); }
    let token = load_token();
    let version = app.package_info().version.to_string();
    let handle = app.clone();
    let handle_nw = app.clone();
    // Окно открывается с локальной заставки (dist/index.html): «Идёт подключение» с анимацией.
    // Она ждёт, пока сервер станет доступен, и сама уходит на страницу приложения. Раньше окно
    // сразу грузило сайт — после перезагрузки без интернета оставался белый экран навсегда.
    let builder = WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()));
    // 27.09 (владелец, п.15 - реклама на ПК): WKWebView на Mac шлёт UA без «Version/… Safari/…» - рекламные сети считают
    // такой браузер ненастоящим и не отдают показ (28 «nofill» из 28). Ставим UA обычного Safari той же платформы.
    #[cfg(target_os = "macos")]
    let builder = builder.user_agent(MAC_SAFARI_UA);
    #[cfg(target_os = "windows")]
    let builder = builder.user_agent(WIN_CHROME_UA);
    // 30.09: запасной путь страницы - прокси окна на вход ядра page-in (см. arm_page_fallback)
    let builder = if PAGE_PROXY.load(std::sync::atomic::Ordering::Relaxed) {
        match url::Url::parse(&format!("http://127.0.0.1:{}", vpn::PAGE_PORT)) { Ok(u) => builder.proxy_url(u), Err(_) => builder }
    } else { builder };
    builder
        .title("INSELLERS VPN")
        .background_color(theme_bg(pref("theme_light")))
        // 02.10: заставка (локальная страница) - в теме, которую человек выбрал на странице
        .initialization_script(if pref("theme_light") { "if(location.host!==\"vpn.insellers.su\")document.documentElement.setAttribute(\"data-theme\",\"light\");" } else { "" })
        // 02.10: язык заставки - как выбран на странице
        .initialization_script(if pref("lang_en") { "window.__INS_LANG_EN=1;" } else { "" })
        .inner_size(430.0, 880.0)
        .min_inner_size(380.0, 700.0)
        .resizable(true)
        .initialization_script(&init_script(&token, &version))
        .initialization_script(&format!("window.__INS_V = {};", serde_json::to_string(&version).unwrap_or_default()))
        // 26.09: после перезагрузки страницы (обновление веб-части, заставка → сайт) она не знала, что VPN уже включён
        // (состояние приходит только событиями) - и её «автоподключение» перезапускало рабочее подключение
        .on_page_load(move |w, p| {
            // 29.09: главное окно само ушло на чужой сайт (рекламный скрипт увёл всю страницу) - адрес во внешний браузер,
            // окно - обратно на приложение. iframe сюда не попадают (событие только главного окна).
            if p.event() == tauri::webview::PageLoadEvent::Started && matches!(p.url().scheme(), "https" | "http")
                && p.url().host_str() != Some(HOST) && p.url().host_str() != Some("tauri.localhost") {
                let _ = w.app_handle().opener().open_url(p.url().as_str(), None::<&str>);
                if let Ok(back) = url::Url::parse(&format!("https://{HOST}/?app=desktop&v={}", w.app_handle().package_info().version)) {
                    let _ = w.navigate(back);
                }
                return;
            }
            if p.event() == tauri::webview::PageLoadEvent::Started { LOAD_AT.store(now_ms(), std::sync::atomic::Ordering::Relaxed); }
            if p.url().host_str() == Some(HOST) {
                if p.event() == tauri::webview::PageLoadEvent::Started { arm_page_fallback(w.app_handle()); }
                else { PAGE_DONE_AT.store(now_ms(), std::sync::atomic::Ordering::Relaxed); }
            }
            if p.event() == tauri::webview::PageLoadEvent::Finished && p.url().host_str() == Some(HOST) && vpn_running(w.app_handle()) {
                let _ = w.eval("if(!window.__INS_VPN||window.__INS_VPN==='disconnected'){window.__INS_VPN='connected';if(!window.__INS_CONN_AT)window.__INS_CONN_AT=Date.now();window.dispatchEvent(new CustomEvent('ins:vpn',{detail:{state:'connected',msg:'',code:''}}))}");
            }
        })
        // 29.09: запрос НОВОГО окна (ссылка target=_blank или window.open внутри рекламного iframe - это нажатие на рекламу)
        // - во внешний браузер, окон внутри приложения не создаём
        .on_new_window(move |u, _features| {
            if matches!(u.scheme(), "https" | "http" | "tg") {
                let _ = handle_nw.opener().open_url(u.as_str(), None::<&str>);
            }
            tauri::webview::NewWindowResponse::Deny
        })
        .on_navigation(move |u| {
            // своя локальная заставка (macOS/Linux: tauri://localhost, Windows: http(s)://tauri.localhost)
            if u.scheme() == "tauri" || u.host_str() == Some("tauri.localhost") { return true; }
            if u.scheme() == "https" && u.host_str() == Some(HOST) && u.path().starts_with("/__native/") {
                let cmd = u.path().trim_start_matches("/__native/").to_string();
                let arg: serde_json::Value = u.query_pairs().find(|(k, _)| k == "a")
                    .and_then(|(_, v)| serde_json::from_str(&v).ok()).unwrap_or_default();
                // 30.09: сторож страницы - без записи native.cmd (раз в 5 с)
                match cmd.as_str() {
                    "page_alive" => { mark_alive(2); return false; }
                    "page_crashed" => { on_page_crashed(&arg); return false; }
                    "page_failed" => {
                        let (h, why) = (handle.clone(), arg["why"].as_str().unwrap_or("http").to_string());
                        let _ = handle.run_on_main_thread(move || on_page_failed(&h, &why));
                        return false;
                    }
                    _ => {}
                }
                let h = handle.clone();
                tauri::async_runtime::spawn(async move { native_cmd(h, &cmd, arg).await; });
                return false;
            }
            // 29.09 (владелец): раньше ЛЮБОЙ чужой https (и iframe рекламных SDK - на Mac обработчик зовётся и для них)
            // открывался во внешнем браузере. Теперь: чужие http(s)/about/data/blob грузятся внутри (iframe, счётчики SDK);
            // переходы по нажатию человека уводит во внешний браузер скрипт страницы (open_external), а если главное окно
            // всё же уходит на чужой сайт - его возвращает on_page_load. tg: - всегда наружу.
            if u.scheme() == "tg" {
                let _ = handle.opener().open_url(u.as_str(), None::<&str>);
                return false;
            }
            matches!(u.scheme(), "https" | "http" | "about" | "data" | "blob")
        })
        .build()?;
    Ok(())
}

/// Показать главное окно (из трея / по клику на значок в доке).
fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.unminimize(); let _ = w.set_focus(); }
    else { let _ = build_main(app); }
}

/// 29.09 (владелец): свой пульс, пока VPN включён, - и при закрытом окне (страница мини-аппа тогда не шлёт).
/// Тот же /api/app/heartbeat и тот же hwid, что у страницы; команда выдаётся один раз - выполняет тот, кто спросил первым.
/// «disconnect» (кнопка «Отключить» в мини-аппе на другом устройстве) - как ручное выключение (vpn_disconnect).
fn start_pulse(h: AppHandle) {
    tauri::async_runtime::spawn(async move {
        let hw = format!("ins-{}", install_id());
        let os = if cfg!(target_os = "macos") { "mac" } else if cfg!(target_os = "windows") { "windows" } else { "linux" };
        let mut conn_at: u64 = 0;
        loop {
            tokio_sleep(20).await;
            if !vpn_running(&h) { conn_at = 0; continue; }
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
            if conn_at == 0 { conn_at = now; }
            let t = load_token();
            if t.is_empty() { continue; }
            let body = serde_json::json!({"hwid": hw, "connected_at": conn_at, "bytes": 0, "platform": "desktop", "model": host_model()});
            // как remote_log: сначала мимо системного прокси, не вышло - через него
            let mut cmd = String::new();
            for direct in [true, false] {
                let b = reqwest::Client::builder().timeout(Duration::from_secs(10));
                let b = if direct { b.no_proxy() } else { b };
                let Ok(c) = b.build() else { continue };
                let Ok(r) = c.post(format!("{BASE}/api/app/heartbeat")).header("X-App-Token", t.clone()).json(&body).send().await else { continue };
                if !r.status().is_success() { break; }
                if let Ok(j) = r.json::<serde_json::Value>().await { cmd = j.get("cmd").and_then(|v| v.as_str()).unwrap_or("").to_string(); }
                break;
            }
            if cmd.is_empty() { continue; }
            remote_log("devices.cmd_exec", serde_json::json!({"cmd": cmd, "src": format!("desktop-{os}-native")}));
            if cmd == "disconnect" && vpn_running(&h) { vpn_disconnect(h.clone()); conn_at = 0; }
        }
    });
}

struct TrayItems { status: tauri::menu::MenuItem<tauri::Wry>, toggle: tauri::menu::MenuItem<tauri::Wry> }

fn vpn_running(app: &AppHandle) -> bool {
    app.try_state::<vpn::VpnState>().map(|s| s.child.lock().unwrap().is_some()).unwrap_or(false)
}

fn fmt_rate(bps: f64) -> String {
    if bps >= 1_000_000.0 { format!("{:.1} МБ/с", bps / 1_000_000.0) }
    else if bps >= 1_000.0 { format!("{:.0} КБ/с", bps / 1_000.0) }
    else { format!("{:.0} Б/с", bps) }
}

/// Значок в трее / строке меню: статус, скорость, подключить/отключить, выход.
fn setup_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let status = MenuItem::with_id(app, "status", "Не подключено", false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", "Открыть INSELLERS VPN", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Включить", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&status, &PredefinedMenuItem::separator(app)?, &open, &toggle, &PredefinedMenuItem::separator(app)?, &quit])?;
    let mut tb = TrayIconBuilder::with_id("main")
        .tooltip("INSELLERS VPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, e| match e.id.as_ref() {
            "open" => show_main(app),
            "toggle" => {
                let a = app.clone();
                if vpn_running(app) { vpn_disconnect(a); }
                else { telemetry::set_trigger("manual"); tauri::async_runtime::spawn(async move { let _ = vpn_connect(a).await; }); }
            }
            "quit" => { telemetry::set_stop_reason("user"); vpn::set_wanted(app, false); vpn::stop(app); tauri::async_runtime::block_on(flush_logs(true)); app.exit(0); }
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e { show_main(tray.app_handle()); }
        });
    if let Some(icon) = app.default_window_icon() { tb = tb.icon(icon.clone()); }
    let tray = tb.build(app)?;
    app.manage(TrayItems { status: status.clone(), toggle: toggle.clone() });

    // раз в 2 с — статус и скорость сети
    let h = app.handle().clone();
    tauri::async_runtime::spawn(async move {
        let mut nets = sysinfo::Networks::new_with_refreshed_list();
        let mut session_bytes: u64 = 0;
        let mut tick: u64 = 0;
        let mut upd_ready = false;
        let my_ver = h.package_info().version.to_string();
        loop {
            tokio_sleep(2).await;
            tick += 1;
            // раз в 10 минут (и через 20 с после запуска) — не вышло ли обновление, даже если окно закрыто
            if tick == 10 || tick % 300 == 0 {
                if let Ok(c) = reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)).build() {
                    if let Ok(r) = c.get(format!("{BASE}/app/desktop/latest.json")).send().await {
                        if let Ok(j) = r.json::<serde_json::Value>().await {
                            let remote = j.get("version").and_then(|v| v.as_str()).unwrap_or("");
                            let p = |v: &str| v.split('.').map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
                            upd_ready = !remote.is_empty() && p(remote) > p(&my_ver);
                        }
                    }
                }
            }
            nets.refresh();
            let (mut rx, mut tx) = (0u64, 0u64);
            for (name, d) in nets.iter() {
                let n = name.to_lowercase();
                if n.starts_with("lo") || n.contains("loopback") { continue; }
                rx += d.received(); tx += d.transmitted();
            }
            let on = vpn_running(&h);
            if on { session_bytes = session_bytes.saturating_add(rx + tx); telemetry::tick(rx, tx); } else { session_bytes = 0; }
            if let Some(w) = h.get_webview_window("main") { let _ = w.eval(&format!("window.__INS_BYTES={session_bytes}")); }
            let (down, up) = (fmt_rate(rx as f64 / 2.0), fmt_rate(tx as f64 / 2.0));
            if let Some(items) = h.try_state::<TrayItems>() {
                let al = access_left_text();
                let st = if on { if al.is_empty() { format!("Подключено · ↓ {down}  ↑ {up}") } else { format!("Подключено · {al} · ↓ {down}  ↑ {up}") } }
                         else { "Не подключено".to_string() };
                let _ = items.status.set_text(if upd_ready { format!("⬆ Вышло обновление! · {st}") } else { st });
                let _ = items.toggle.set_text(if on { "Отключить" } else { "Включить" });
            }
            let al = access_left_text();
            let _ = tray.set_tooltip(Some(if on { format!("INSELLERS VPN - защищено{}\n↓ {down}   ↑ {up}", if al.is_empty() { String::new() } else { format!(" · {al}") }) }
                                         else { "INSELLERS VPN - не подключено".to_string() }));
            #[cfg(target_os = "macos")]
            {
                // 28.09 (владелец): в строке меню без «/с» - короче, значок не уходит за вырез экрана
                let t = if on { format!("↓{} ↑{}", down.trim_end_matches("/с"), up.trim_end_matches("/с")) } else { String::new() };
                let t = if upd_ready { format!("⬆ {t}").trim().to_string() } else { t };
                let _ = tray.set_title(if t.is_empty() { None } else { Some(t) });
            }
        }
    });
    Ok(())
}

/// Команды со страницы (через перехват навигации /__native/…).
async fn native_cmd(app: AppHandle, cmd: &str, arg: serde_json::Value) {
    remote_log("native.cmd", serde_json::json!({"cmd": cmd}));
    match cmd {
        "login" => { let _ = login(app).await; }
        "logout" => logout(app),
        "set_token" => set_token(app, arg["token"].as_str().unwrap_or_default().to_string()),
        "open_external" => open_external(app, arg["url"].as_str().unwrap_or_default().to_string()),
        "check_update" => { let _ = check_update(app, Some(arg["manual"].as_bool().unwrap_or(false))).await; }
        "vpn_connect" => { telemetry::set_trigger("manual"); let _ = vpn_connect(app).await; }
        "vpn_guest" => {
            let url = arg["url"].as_str().unwrap_or_default().to_string();
            let until = now_ms() + GUEST_MAX_MS;
            if !guest_valid(&url) { crate::remote_log("guest.reject", serde_json::json!({"why": "url", "len": url.len()})); }
            if guest_valid(&url) {
                guest_save(&url, until);
                if let Some(w) = app.get_webview_window("main") { let _ = w.eval(&format!("window.__INS_GUEST_UNTIL={until}")); }
                let _ = vpn_connect(app).await;
            }
        }
        "vpn_disconnect" => vpn_disconnect(app),
        "set_pref" => set_pref(&app, arg["key"].as_str().unwrap_or_default(), arg["value"].as_bool().unwrap_or(false)),
        // 02.10 (владелец): тема страницы - фон окна и заставка под неё (запоминается в prefs.json)
        // 02.10 (владелец): язык страницы - заставка на нём при следующем запуске (prefs.json)
        "set_lang" => {
            let en = arg["lang"].as_str() == Some("en");
            let mut v = prefs(); v["lang_en"] = serde_json::Value::Bool(en);
            if let Some(p) = data_path("prefs.json") { write_private(&p, &v.to_string()); }
        }
        "set_theme" => {
            let light = arg["theme"].as_str() == Some("light");
            let mut v = prefs(); v["theme_light"] = serde_json::Value::Bool(light);
            if let Some(p) = data_path("prefs.json") { write_private(&p, &v.to_string()); }
            if let Some(w) = app.get_webview_window("main") { let _ = w.set_background_color(Some(theme_bg(light))); }
        }
        "probe" => {
            let (ok, ms, how) = vpn::tunnel_check().await;
            if let Some(w) = app.get_webview_window("main") {
                let d = serde_json::json!({"ok": ok, "ms": ms, "how": how}).to_string();
                let _ = w.eval(&format!("window.__INS_PROBE={d};window.dispatchEvent(new CustomEvent('ins:probe',{{detail:{d}}}))"));
            }
        }
        "probe_funnel" => {
            let d = crate::probe::funnel_now().await.to_string();
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.eval(&format!("window.dispatchEvent(new CustomEvent('ins:funnel',{{detail:{d}}}))"));
            }
        }
        "set_access" => ACCESS_UNTIL.store(arg["ms"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0), std::sync::atomic::Ordering::Relaxed),
        _ => {}
    }
}

/// Код перехода «INSELLERS-INVITE:<код>» из буфера обмена - системной командой (без лишних зависимостей).
fn invite_from_clipboard() -> String {
    #[cfg(target_os = "macos")]
    let out = std::process::Command::new("pbpaste").output();
    #[cfg(target_os = "windows")]
    let out = {
        use std::os::windows::process::CommandExt;
        std::process::Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard"])
            .creation_flags(0x0800_0000).output()                 // CREATE_NO_WINDOW - без мигающего окна
    };
    #[cfg(target_os = "linux")]
    let out = std::process::Command::new("sh").args(["-c", "wl-paste -n 2>/dev/null || xclip -o -selection clipboard 2>/dev/null"]).output();
    let t = out.map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).unwrap_or_default();
    match t.strip_prefix("INSELLERS-INVITE:") { Some(c) if c.len() < 64 => c.to_string(), _ => String::new() }
}

#[tauri::command]
async fn login(app: AppHandle) -> Result<(), String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    // 27.09 (владелец): приглашение засчитывается по коду со страницы /i/<uid> (буфер обмена), IP - только подтверждение
    let invite = tauri::async_runtime::spawn_blocking(invite_from_clipboard).await.unwrap_or_default();
    let body = if invite.is_empty() { serde_json::json!({}) } else { serde_json::json!({"invite": invite}) };
    let r: serde_json::Value = client.post(format!("{BASE}/api/app/login/start")).json(&body).send().await
        .map_err(|e| e.to_string())?.json().await.map_err(|e| e.to_string())?;
    let nonce = r["nonce"].as_str().unwrap_or_default().to_string();
    let link = r["bot_link"].as_str().unwrap_or_default().to_string();
    let _ = app.opener().open_url(&link, None::<&str>);
    for _ in 0..150 {
        tokio_sleep(2).await;
        let p: serde_json::Value = match client.get(format!("{BASE}/api/app/login/poll")).query(&[("nonce", &nonce)]).send().await {
            Ok(resp) => resp.json().await.unwrap_or_default(),
            Err(_) => continue,
        };
        if let Some(t) = p["token"].as_str() {
            save_token(t);
            let a = app.clone();
            let _ = app.run_on_main_thread(move || { let _ = build_main(&a); });
            return Ok(());
        }
        if p["expired"].as_bool() == Some(true) { break; }
    }
    Err("timeout".into())
}

pub async fn tokio_sleep(s: u64) { tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_secs(s))).await.ok(); }

#[tauri::command]
fn set_token(app: AppHandle, token: String) {
    if token.len() > 20 && token.len() < 600 && token.contains('.') {
        let (kr, file) = save_token(&token);
        let back = load_token() == token;
        remote_log("login.saved", serde_json::json!({"keyring": kr, "file": file, "readback": back}));
        swap_token(&app, &token);
    }
}

/// Подменить токен в открытом окне и перезагрузить страницу — окно не пересоздаётся.
fn swap_token(app: &AppHandle, token: &str) {
    let js = format!("try{{sessionStorage.setItem('ins_tok',{});}}catch(e){{}}location.replace('/?app=desktop&v={}');",
        serde_json::to_string(token).unwrap_or_else(|_| "\"\"".into()), app.package_info().version);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.eval(&js);
        let _ = w.show(); let _ = w.unminimize(); let _ = w.set_focus();
    } else {
        let a = app.clone();
        let _ = app.run_on_main_thread(move || { let _ = build_main(&a); });
    }
}

#[tauri::command]
async fn vpn_connect(app: AppHandle) -> Result<(), String> {
    // 01.10 (владелец): портал Wi-Fi - сначала войти в сеть (иначе ложные «не подключается»); повтор в течение минуты - без проверки
    if !vpn_running(&app) && telemetry::captive().await {
        vpn::notify_code(&app, "error", "Авторизуйтесь в сети Wi-Fi: откройте любой сайт в браузере, войдите в сеть и нажмите «Подключить» ещё раз", "captive");
        return Err("CAPTIVE".into());
    }
    vpn::notify(&app, "connecting", "");
    telemetry::attempt("");
    match vpn::start(app.clone()).await {
        Ok(()) => { remote_log("vpn.connected", serde_json::json!({})); telemetry::result("connected", "", ""); vpn::notify(&app, "connected", &vpn::take_connect_msg()); Ok(()) }
        Err(e) if e == "BUSY" => Err(e),   // подключение уже идёт — второй раз не запускаем
        Err(e) if e == "CANCELLED" => { telemetry::result("cancelled", "", ""); vpn::notify(&app, "disconnected", ""); Err(e) }   // нажали «Отключить» во время подключения
        Err(e) => {
            let stage = if e.starts_with("OTHER_VPN:") { "tunnel" } else if e.contains("подписк") || e.contains("доступ") || e.contains("конфиг") { "config" } else { "handshake" };
            telemetry::result("failed", stage, &e);
            remote_log("vpn.start_error", serde_json::json!({"err": e}));
            vpn::stop(&app);
            // код other_vpn — страница покажет подсказку
            if let Some(m) = e.strip_prefix("OTHER_VPN:") { vpn::notify_code(&app, "error", m, "other_vpn"); }
            else { vpn::notify(&app, "error", &e); }
            Err(e)
        }
    }
}

#[tauri::command]
fn vpn_disconnect(app: AppHandle) {
    telemetry::set_stop_reason("user");
    vpn::set_wanted(&app, false);
    vpn::stop(&app);
    vpn::notify(&app, "disconnected", "");
}

#[tauri::command]
fn logout(app: AppHandle) {
    vpn::set_wanted(&app, false);
    vpn::stop(&app);
    save_token("");
    swap_token(&app, "");
}

#[tauri::command]
fn open_external(app: AppHandle, url: String) {
    if url.starts_with("https://") || url.starts_with("tg://") { let _ = app.opener().open_url(&url, None::<&str>); }
}

/// 30.09: событие обновления странице без процента (стадия + пометка причины)
fn update_page(app: &AppHandle, stage: &str, msg: &str) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.eval(&format!("window.dispatchEvent(new CustomEvent('ins:update-progress',{{detail:{{pct:0,stage:'{stage}',msg:'{msg}'}}}}))"));
    }
}

/// 30.09 (владелец: Mac - обновление висит на 0%): проверка обновления не дольше 12 с напрямую; не вышло и VPN включён - через
/// туннель (вход проверки ядра probe-in: адрес нашего сервера обычные входы шлют напрямую). Одновременно - одна проверка по кнопке
/// (страница повторяла её каждые 20 с, и они копились по 2 минуты каждая).
static UPD_CHECKING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
struct CheckGuard;
impl Drop for CheckGuard { fn drop(&mut self) { UPD_CHECKING.store(false, std::sync::atomic::Ordering::SeqCst); } }

async fn updater_check(app: &AppHandle, via_tunnel: bool) -> Result<Option<tauri_plugin_updater::Update>, String> {
    // 29.09: X-App-Token - бэкенд отдаёт владельцу кандидата (Mac в режиме TUN ходит с адреса нашего сервера - по адресу не узнать)
    let tok = load_token();
    let mut b = app.updater_builder().timeout(Duration::from_secs(if via_tunnel { 25 } else { 12 }));
    if !tok.is_empty() { b = b.header("X-App-Token", tok).map_err(|e| e.to_string())?; }
    if via_tunnel {
        if let Ok(u) = url::Url::parse(&format!("http://127.0.0.1:{}", vpn::PROBE_PORT)) { b = b.proxy(u); }
    }
    b.build().map_err(|e| e.to_string())?.check().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn check_update(app: AppHandle, manual: Option<bool>) -> Result<bool, String> {
    if manual.unwrap_or(false) {
        if UPD_CHECKING.swap(true, std::sync::atomic::Ordering::SeqCst) { return Ok(true); }   // проверка по кнопке уже идёт
    }
    let _cg = if manual.unwrap_or(false) { Some(CheckGuard) } else { None };
    let res = match updater_check(&app, false).await {
        Err(e) if vpn_running(&app) => {
            remote_log("update.check_tunnel", serde_json::json!({"err": e}));
            updater_check(&app, true).await.map_err(|e2| format!("{e}; через туннель: {e2}"))
        }
        r => r,
    };
    match res {
        Ok(Some(update)) => {
            if manual.unwrap_or(false) {
                // по кнопке: качаем (VPN работает — раньше гасили его ДО загрузки, и сеть пропадала, а экран
                // писал «Защищено»), проверяем подпись (плагин), ставим, гасим VPN и перезапускаемся;
                // после перезапуска VPN включится сам, если был включён
                let was_on = vpn_running(&app);
                let w = app.get_webview_window("main");
                let emit = |pct: u64, stage: &str| {
                    if let Some(w) = &w {
                        let _ = w.eval(&format!("window.dispatchEvent(new CustomEvent('ins:update-progress',{{detail:{{pct:{pct},stage:'{stage}'}}}}))"));
                    }
                };
                // 26.09 ночь: одна загрузка за раз - повторный запрос только показывает прогресс текущей (upd.rs)
                if upd::BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    emit(upd::PCT.load(std::sync::atomic::Ordering::SeqCst), "download");
                    return Ok(true);
                }
                let _busy = upd::BusyGuard;
                remote_log("update.download", serde_json::json!({"v": update.version}));
                emit(0, "download");
                let pubkey = app.config().plugins.0.get("updater").and_then(|u| u.get("pubkey")).and_then(|k| k.as_str()).unwrap_or("").to_string();
                // 27.09 (п.17): Mac - сначала дельта (патч ~2 МБ от установленной версии, подпись tar проверена внутри)
                #[cfg(target_os = "macos")]
                let delta = upd::delta::try_update(update.download_url.as_str(), &pubkey, was_on, |p| emit(p, "download")).await;
                #[cfg(not(target_os = "macos"))]
                let delta: Option<Vec<u8>> = None;
                let bytes = if let Some(b) = delta { b } else {
                    let b = match upd::fetch(update.download_url.as_str(), was_on, |p| emit(p, "download")).await {
                        Ok(b) => b,
                        Err(e) => { emit(0, "error"); remote_log("update.fail", serde_json::json!({"err": e})); return Err(e); }
                    };
                    if let Err(e) = upd::verify(&b, &update.signature, &pubkey) {
                        emit(0, "error"); remote_log("update.fail", serde_json::json!({"err": e})); return Err(e);
                    }
                    // база для следующего дельта-обновления (распакованный tar этой версии)
                    #[cfg(target_os = "macos")]
                    {
                        let (bc, v) = (b.clone(), update.version.clone());
                        let _ = tauri::async_runtime::spawn_blocking(move || upd::delta::save_base_from_tgz(&bc, &v)).await;
                    }
                    b
                };
                emit(100, "install");
                if let Err(e) = update.install(&bytes) { emit(0, "error"); return Err(e.to_string()); }
                if was_on { if let Some(p) = data_path("resume") { let _ = std::fs::write(p, "1"); } }
                vpn::stop(&app);
                app.restart();
            }
            // в фоне: только сообщаем странице — она покажет плашку «Обновить»
            if let Some(w) = app.get_webview_window("main") {
                let v = serde_json::to_string(&update.version).unwrap_or_default();
                let _ = w.eval(&format!("window.__INS_UPDATE={v};window.dispatchEvent(new CustomEvent('ins:update',{{detail:{{version:{v}}}}}))"));
            }
            Ok(true)
        }
        // 30.09 (владелец): по кнопке «новой версии нет» и «проверка не удалась» - не молча: странице 'error' (следующее нажатие -
        // установщик в браузере), в журнал update.none / update.fail. Бывает, когда страница знает о кандидате, а проверка
        // обновлений ходит без токена (сборки до 1.0.130) или через туннель с адреса сервера.
        Ok(None) => {
            if manual.unwrap_or(false) {
                update_page(&app, "error", "none");
                remote_log("update.none", serde_json::json!({"cur": env!("CARGO_PKG_VERSION"), "token": !load_token().is_empty()}));
            }
            Ok(false)
        }
        Err(e) => {
            if manual.unwrap_or(false) {
                update_page(&app, "error", "check");
                remote_log("update.fail", serde_json::json!({"err": e, "stage": "check"}));
            }
            Err(e)
        }
    }
}

fn main() {
    tauri::Builder::default()
        // 29.09: вторая копия (Windows: так приходит ссылка insellers://open) - не запускаем, показываем окно первой
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| { show_main(app); }))
        .plugin(tauri_plugin_deep_link::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .manage(vpn::VpnState::default())
        .invoke_handler(tauri::generate_handler![login, logout, set_token, open_external, check_update, vpn_connect, vpn_disconnect,
                                                 page_alive, page_failed, page_crashed, server_ok, splash_report])
        .on_window_event(|window, event| {
            // закрытие окна — сворачиваем в трей, VPN продолжает работать; выход — через меню значка
            if let tauri::WindowEvent::CloseRequested { api, .. } = event { let _ = window.hide(); api.prevent_close(); }
            // 30.09: окно снова перед глазами - сторож отсчитывает 15 с заново (таймеры скрытой страницы спят)
            if let tauri::WindowEvent::Focused(true) = event { SEEN_AT.store(now_ms(), std::sync::atomic::Ordering::Relaxed); }
            if let tauri::WindowEvent::Focused(false) = event { tauri::async_runtime::spawn(async { flush_logs(true).await; }); }   // 01.10: окно ушло - журнал сразу
        })
        .setup(|app| {
            remote_log("app.start", serde_json::json!({"hasToken": !load_token().is_empty()}));
            build_main(app.handle())?;
            // 29.09: insellers://open (Mac - событие ссылки в запущенное приложение) - показать окно
            {
                use tauri_plugin_deep_link::DeepLinkExt;
                let h = app.handle().clone();
                app.deep_link().on_open_url(move |_ev| { show_main(&h); });
            }
            start_pulse(app.handle().clone());
            start_watchdog(app.handle().clone());
            start_power(app.handle().clone());
            if let Err(e) = setup_tray(app) { remote_log("tray.error", serde_json::json!({"err": e.to_string()})); }
            apply_autostart(app.handle(), pref("autoconnect"));
            // VPN был включён до обновления — включаем снова, даже без автоподключения
            let resume = data_path("resume").map(|p| { let e = p.exists(); let _ = std::fs::remove_file(&p); e }).unwrap_or(false);
            let will_autoconnect = (pref("autoconnect") || resume) && !load_token().is_empty();
            // прошлый сеанс оборвался — убрать свой прокси и Xray (при автоподключении это делает сам запуск)
            if !will_autoconnect { std::thread::spawn(vpn::cleanup_stale); }
            if will_autoconnect {
                let h = app.handle().clone();
                // После перезагрузки интернета часто ещё нет (Wi-Fi/раздача поднимаются позже) —
                // ждём, пока сервер ответит (до 10 минут), и только тогда подключаемся.
                tauri::async_runtime::spawn(async move {
                    tokio_sleep(3).await;
                    let c = reqwest::Client::builder().no_proxy().timeout(std::time::Duration::from_secs(5)).build();
                    for _ in 0..150 {
                        let ok = match &c { Ok(c) => c.get(format!("{BASE}/app/desktop/latest.json")).send().await.is_ok(), Err(_) => true };
                        if ok { break; }
                        tokio_sleep(4).await;
                    }
                    if !vpn_running(&h) { telemetry::set_trigger("startup"); let _ = vpn_connect(h).await; }   // человек мог уже подключиться сам
                });
            }
            let h = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                tokio_sleep(8).await; // дать странице загрузиться
                loop {
                    let _ = check_update(h.clone(), None).await;
                    tokio_sleep(30 * 60).await;
                }
            });
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build INSELLERS VPN")
        .run(|app, event| {
            match &event {
                // закрылось последнее окно — приложение живёт в трее/строке меню; выходим только по «Выйти»
                tauri::RunEvent::ExitRequested { code: None, api, .. } => { api.prevent_exit(); }
                // при выходе ВСЕГДА выключаем системный прокси, иначе у человека пропадёт интернет
                tauri::RunEvent::Exit => { vpn::stop(app); }
                #[cfg(target_os = "macos")]
                tauri::RunEvent::Reopen { .. } => { show_main(app); }
                _ => {}
            }
        });
}
