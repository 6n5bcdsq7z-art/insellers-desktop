// INSELLERS VPN — оболочка для Windows/macOS.
// Интерфейс грузится с https://vpn.insellers.su (изменения видны сразу).
// Вход через бота (как в Android), токен в системном хранилище (Keychain / Credential Manager),
// самообновление с проверкой подписи (tauri-plugin-updater), навигация только на свой домен.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod vpn;
mod probe;
mod tun;
mod upd;

use std::time::Duration;
use tauri::{AppHandle, Manager, WebviewUrl, WebviewWindowBuilder};
use tauri_plugin_opener::OpenerExt;
use tauri_plugin_updater::UpdaterExt;

pub const BASE: &str = "https://vpn.insellers.su";
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
const GUEST_MAX_MS: u64 = 15 * 60_000;
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
    let until = v["until"].as_u64()?;
    let now = now_ms();
    if guest_valid(&url) && until > now && until <= now + GUEST_MAX_MS { Some((url, until)) } else { None }
}
fn guest_save(url: &str, until: u64) {
    if let Some(p) = data_path("guest.json") { write_private(&p, &serde_json::json!({"url": url, "until": until}).to_string()); }
}
pub fn guest_clear() { if let Some(p) = data_path("guest.json") { let _ = std::fs::remove_file(p); } }
pub fn guest_until() -> u64 { guest_load().map(|(_, u)| u).unwrap_or(0) }

/// Настройки поведения на этом компьютере (prefs.json рядом с данными приложения).
pub fn prefs() -> serde_json::Value {
    let mut v = serde_json::json!({"autoconnect": true, "reconnect": true, "killswitch": false});
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

/// Диагностический лог на сервер (без секретов).
pub fn remote_log(ev: &str, data: serde_json::Value) {
    let ev = ev.to_string();
    tauri::async_runtime::spawn(async move {
        let os = if cfg!(target_os = "macos") { "mac" } else if cfg!(target_os = "windows") { "windows" } else { "linux" };
        let body = serde_json::json!({
            "ctx": {"install": install_id(), "platform": format!("desktop-{os}-native"), "version": env!("CARGO_PKG_VERSION")},
            "events": [{"ts": std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0), "ev": ev, "data": data}]
        });
        // 26.09: сначала мимо системного прокси (= нашего туннеля): событие «путь умер» через мёртвый путь не дошло бы,
        // и сервер видит IP провайдера, а не нашего сервера. Не вышло напрямую - через системный прокси.
        let t = load_token();
        for direct in [true, false] {
            let b = reqwest::Client::builder().timeout(Duration::from_secs(10));
            let b = if direct { b.no_proxy() } else { b };
            if let Ok(c) = b.build() {
                let mut rq = c.post(format!("{BASE}/api/app/log")).json(&body);
                if !t.is_empty() { rq = rq.header("X-App-Token", t.clone()); }
                if rq.send().await.map(|r| r.status().is_success()).unwrap_or(false) { break; }
            }
        }
    });
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
    hasVpn: function () {{ return true; }},
    hasAwg: function () {{ return true; }},
    connectGuest: function (u, t) {{ inv("vpn_guest", {{ url: String(u), until: String(t) }}); }},
    getGuestUntil: function () {{ var g = +window.__INS_GUEST_UNTIL || 0; return String(g > Date.now() ? g : 0); }},
    getVpnState: function () {{ return window.__INS_VPN || "disconnected"; }}
  }};
}})();
"#)
}

fn build_main(app: &AppHandle) -> tauri::Result<()> {
    if let Some(w) = app.get_webview_window("main") { let _ = w.destroy(); }
    let token = load_token();
    let version = app.package_info().version.to_string();
    let handle = app.clone();
    // Окно открывается с локальной заставки (dist/index.html): «Идёт подключение» с анимацией.
    // Она ждёт, пока сервер станет доступен, и сама уходит на страницу приложения. Раньше окно
    // сразу грузило сайт — после перезагрузки без интернета оставался белый экран навсегда.
    WebviewWindowBuilder::new(app, "main", WebviewUrl::App("index.html".into()))
        .title("INSELLERS VPN")
        .background_color(tauri::window::Color(0, 0, 0, 255))
        .inner_size(430.0, 880.0)
        .min_inner_size(380.0, 700.0)
        .resizable(true)
        .initialization_script(&init_script(&token, &version))
        .initialization_script(&format!("window.__INS_V = {};", serde_json::to_string(&version).unwrap_or_default()))
        // 26.09: после перезагрузки страницы (обновление веб-части, заставка → сайт) она не знала, что VPN уже включён
        // (состояние приходит только событиями) - и её «автоподключение» перезапускало рабочее подключение
        .on_page_load(|w, p| {
            if p.event() == tauri::webview::PageLoadEvent::Finished && p.url().host_str() == Some(HOST) && vpn_running(w.app_handle()) {
                let _ = w.eval("if(!window.__INS_VPN||window.__INS_VPN==='disconnected'){window.__INS_VPN='connected';if(!window.__INS_CONN_AT)window.__INS_CONN_AT=Date.now();window.dispatchEvent(new CustomEvent('ins:vpn',{detail:{state:'connected',msg:'',code:''}}))}");
            }
        })
        .on_navigation(move |u| {
            // своя локальная заставка (macOS/Linux: tauri://localhost, Windows: http(s)://tauri.localhost)
            if u.scheme() == "tauri" || u.host_str() == Some("tauri.localhost") { return true; }
            if u.scheme() == "https" && u.host_str() == Some(HOST) && u.path().starts_with("/__native/") {
                let cmd = u.path().trim_start_matches("/__native/").to_string();
                let arg: serde_json::Value = u.query_pairs().find(|(k, _)| k == "a")
                    .and_then(|(_, v)| serde_json::from_str(&v).ok()).unwrap_or_default();
                let h = handle.clone();
                tauri::async_runtime::spawn(async move { native_cmd(h, &cmd, arg).await; });
                return false;
            }
            let ours = u.scheme() == "https" && u.host_str() == Some(HOST);
            if !ours && (u.scheme() == "https" || u.scheme() == "tg") {
                let _ = handle.opener().open_url(u.as_str(), None::<&str>);
            }
            ours
        })
        .build()?;
    Ok(())
}

/// Показать главное окно (из трея / по клику на значок в доке).
fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") { let _ = w.show(); let _ = w.unminimize(); let _ = w.set_focus(); }
    else { let _ = build_main(app); }
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
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
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
                else { tauri::async_runtime::spawn(async move { let _ = vpn_connect(a).await; }); }
            }
            "quit" => { vpn::set_wanted(app, false); vpn::stop(app); app.exit(0); }
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
            if on { session_bytes = session_bytes.saturating_add(rx + tx); } else { session_bytes = 0; }
            if let Some(w) = h.get_webview_window("main") { let _ = w.eval(&format!("window.__INS_BYTES={session_bytes}")); }
            let (down, up) = (fmt_rate(rx as f64 / 2.0), fmt_rate(tx as f64 / 2.0));
            if let Some(items) = h.try_state::<TrayItems>() {
                let st = if on { format!("Подключено · ↓ {down}  ↑ {up}") } else { "Не подключено".to_string() };
                let _ = items.status.set_text(if upd_ready { format!("⬆ Вышло обновление! · {st}") } else { st });
                let _ = items.toggle.set_text(if on { "Отключить" } else { "Подключить" });
            }
            let _ = tray.set_tooltip(Some(if on { format!("INSELLERS VPN - защищено\n↓ {down}   ↑ {up}") } else { "INSELLERS VPN - не подключено".to_string() }));
            #[cfg(target_os = "macos")]
            {
                let t = if on { format!("↓{down} ↑{up}") } else { String::new() };
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
        "vpn_connect" => { let _ = vpn_connect(app).await; }
        "vpn_guest" => {
            let url = arg["url"].as_str().unwrap_or_default().to_string();
            let until: u64 = arg["until"].as_str().and_then(|x| x.parse().ok()).unwrap_or(0);
            let now = now_ms();
            if guest_valid(&url) && until > now && until <= now + GUEST_MAX_MS {
                guest_save(&url, until);
                if let Some(w) = app.get_webview_window("main") { let _ = w.eval(&format!("window.__INS_GUEST_UNTIL={until}")); }
                let _ = vpn_connect(app).await;
            }
        }
        "vpn_disconnect" => vpn_disconnect(app),
        "set_pref" => set_pref(&app, arg["key"].as_str().unwrap_or_default(), arg["value"].as_bool().unwrap_or(false)),
        _ => {}
    }
}

#[tauri::command]
async fn login(app: AppHandle) -> Result<(), String> {
    let client = reqwest::Client::builder().timeout(Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let r: serde_json::Value = client.post(format!("{BASE}/api/app/login/start")).send().await
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
    vpn::notify(&app, "connecting", "");
    match vpn::start(app.clone()).await {
        Ok(()) => { remote_log("vpn.connected", serde_json::json!({})); vpn::notify(&app, "connected", &vpn::take_connect_msg()); Ok(()) }
        Err(e) if e == "BUSY" => Err(e),   // подключение уже идёт — второй раз не запускаем
        Err(e) if e == "CANCELLED" => { vpn::notify(&app, "disconnected", ""); Err(e) }   // нажали «Отключить» во время подключения
        Err(e) => {
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

#[tauri::command]
async fn check_update(app: AppHandle, manual: Option<bool>) -> Result<bool, String> {
    let updater = app.updater().map_err(|e| e.to_string())?;
    match updater.check().await {
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
                let bytes = match upd::fetch(update.download_url.as_str(), was_on, |p| emit(p, "download")).await {
                    Ok(b) => b,
                    Err(e) => { emit(0, "error"); remote_log("update.fail", serde_json::json!({"err": e})); return Err(e); }
                };
                let pubkey = app.config().plugins.0.get("updater").and_then(|u| u.get("pubkey")).and_then(|k| k.as_str()).unwrap_or("").to_string();
                if let Err(e) = upd::verify(&bytes, &update.signature, &pubkey) {
                    emit(0, "error"); remote_log("update.fail", serde_json::json!({"err": e})); return Err(e);
                }
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
        Ok(None) => { let _ = manual; Ok(false) }
        Err(e) => Err(e.to_string()),
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_updater::Builder::new().build())
        .plugin(tauri_plugin_process::init())
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
        .manage(vpn::VpnState::default())
        .invoke_handler(tauri::generate_handler![login, logout, set_token, open_external, check_update, vpn_connect, vpn_disconnect])
        .on_window_event(|window, event| {
            // закрытие окна — сворачиваем в трей, VPN продолжает работать; выход — через меню значка
            if let tauri::WindowEvent::CloseRequested { api, .. } = event { let _ = window.hide(); api.prevent_close(); }
        })
        .setup(|app| {
            remote_log("app.start", serde_json::json!({"hasToken": !load_token().is_empty()}));
            build_main(app.handle())?;
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
                    if !vpn_running(&h) { let _ = vpn_connect(h).await; }   // человек мог уже подключиться сам
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
