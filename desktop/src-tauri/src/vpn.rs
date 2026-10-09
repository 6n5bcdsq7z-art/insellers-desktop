// VPN-режим на компьютере: Xray (sidecar) + системный прокси.
// Конфигурацию человека отдаёт наш сервер подписок (Xray JSON по User-Agent InsellersVPN/…),
// здесь мы только подменяем входы на локальные 127.0.0.1:38808 (SOCKS) / :38809 (HTTP).
use serde_json::{json, Value};
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;
use tauri::{AppHandle, Manager};
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tauri_plugin_shell::ShellExt;

/// Известные VPN/прокси-клиенты: перед подключением закрываем их, чтобы не перехватывали трафик.
const OTHER_VPN: &[(&str, &str)] = &[
    ("happ", "Happ"), ("v2rayn", "v2rayN"), ("v2raytun", "v2RayTun"), ("clash", "Clash"), ("mihomo", "Clash"),
    ("hiddify", "Hiddify"), ("karing", "Karing"), ("nekoray", "NekoRay"), ("nekobox", "NekoBox"),
    ("sing-box", "sing-box"), ("outline", "Outline"), ("amnezia", "AmneziaVPN"), ("streisand", "Streisand"),
    ("foxray", "FoXray"), ("v2box", "V2Box"), ("xray", "Xray"), ("throne", "Throne"), ("flclash", "FlClash"),
];

/// Закрывает чужие VPN-клиенты. Возвращает (кого закрыли, кого закрыть не получилось).
pub fn kill_other_vpns() -> (Vec<String>, Vec<String>) {
    let mut killed = Vec::new();
    let mut failed = Vec::new();
    let own_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf()));
    let sys = sysinfo::System::new_all();
    let me = std::process::id();
    for (pid, p) in sys.processes() {
        if pid.as_u32() == me { continue; }
        let name = p.name().to_string_lossy().to_lowercase();
        if name.contains("insellers") { continue; }
        // наш TUN (26.09): sing-box помощника работает от root из его папки - exe у root-процесса часто не виден, узнаём по имени
        if (name == "sing-box" || name == "sing-box.exe" || name.starts_with("ins-helper")) && crate::tun::installed() { continue; }
        // наш собственный Xray (sidecar) лежит рядом с приложением — его не трогаем
        if let (Some(exe), Some(dir)) = (p.exe(), own_dir.as_ref()) { if exe.starts_with(dir) { continue; } }
        if let Some((_, title)) = OTHER_VPN.iter().find(|(k, _)| name.contains(k)) {
            let t = title.to_string();
            if p.kill() { if !killed.contains(&t) { killed.push(t); } }
            else if !failed.contains(&t) { failed.push(t); }
        }
    }
    (killed, failed)
}

/// macOS: VPN через системные расширения (Happ из App Store, Outline, Amnezia, WireGuard…) не видны как
/// обычные процессы и не трогают системный прокси — их туннель останавливаем через `scutil --nc stop`.
#[cfg(target_os = "macos")]
fn stop_other_ne_vpns() -> Vec<String> {
    let out = std::process::Command::new("/usr/sbin/scutil").args(["--nc", "list"]).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let mut stopped = Vec::new();
    for line in out.lines() {
        if !line.contains("(Connected)") && !line.contains("(Connecting)") { continue; }
        let name = match line.split('"').nth(1) { Some(n) if !n.is_empty() => n.to_string(), _ => continue };
        if name.to_lowercase().contains("insellers") { continue; }
        let _ = std::process::Command::new("/usr/sbin/scutil").args(["--nc", "stop", &name]).output();
        stopped.push(name);
    }
    stopped
}

/// Наш VPN — единственный: пока он включён, закрываем чужие клиенты и их туннели.
/// Два VPN одновременно мешают друг другу (трафик уходит то в один, то в другой, сайты «не грузятся»).
fn enforce_exclusive() -> Vec<String> {
    let (mut k, _) = kill_other_vpns();
    #[cfg(target_os = "macos")]
    for n in stop_other_ne_vpns() { if !k.contains(&n) { k.push(n); } }
    k
}

/// Наш ли сейчас системный прокси.
fn proxy_is_ours() -> bool {
    #[cfg(target_os = "macos")]
    return mac::all_ours(HTTP_PORT);
    #[cfg(not(target_os = "macos"))]
    return match sysproxy::Sysproxy::get_system_proxy() {
        Ok(p) => p.enable && p.port == HTTP_PORT && (p.host == "127.0.0.1" || p.host == "localhost"),
        Err(_) => true, // не смогли прочитать — не дёргаем зря
    };
}

/// Остался ли где-то наш прокси (для уборки после сбоя).
fn proxy_left_on() -> bool {
    #[cfg(target_os = "macos")]
    return mac::any_ours(HTTP_PORT, SOCKS_PORT);
    #[cfg(not(target_os = "macos"))]
    return match sysproxy::Sysproxy::get_system_proxy() {
        Ok(p) => p.enable && (p.port == HTTP_PORT || p.port == SOCKS_PORT) && (p.host == "127.0.0.1" || p.host == "localhost"),
        Err(_) => false,
    };
}

/// macOS: прокси ставим и снимаем на ВСЕХ сетевых службах (Wi-Fi, Ethernet, USB-модем, Thunderbolt…).
/// Раньше ставили только на текущую — после смены сети выключение не находило свой прокси и он оставался.
#[cfg(target_os = "macos")]
mod mac {
    use std::process::Command;
    fn ns(args: &[&str]) -> String {
        Command::new("/usr/sbin/networksetup").args(args).output().ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default()
    }
    /// Включённые сетевые службы (выключенные помечены «*»).
    fn services() -> Vec<String> {
        ns(&["-listallnetworkservices"]).lines().skip(1)
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty() && !l.starts_with('*'))
            .collect()
    }
    fn field(out: &str, key: &str) -> String {
        out.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string()).unwrap_or_default()
    }
    /// Включён и смотрит на 127.0.0.1:port.
    fn ours(out: &str, port: u16) -> bool {
        field(out, "Enabled:") == "Yes"
            && matches!(field(out, "Server:").as_str(), "127.0.0.1" | "localhost")
            && field(out, "Port:") == port.to_string()
    }
    pub fn enable(http: u16, socks: u16) {
        let (hp, sp) = (http.to_string(), socks.to_string());
        for s in services() {
            ns(&["-setwebproxy", &s, "127.0.0.1", &hp]);
            ns(&["-setsecurewebproxy", &s, "127.0.0.1", &hp]);
            ns(&["-setsocksfirewallproxy", &s, "127.0.0.1", &sp]);   // SOCKS — на SOCKS-порт (раньше ошибочно стоял HTTP)
            ns(&["-setproxybypassdomains", &s, "localhost", "127.0.0.1", "*.local", "169.254/16", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]);
        }
    }
    /// Снимаем только свой прокси (чужие настройки человека не трогаем).
    pub fn disable(http: u16, socks: u16) {
        for s in services() {
            if ours(&ns(&["-getwebproxy", &s]), http) { ns(&["-setwebproxystate", &s, "off"]); }
            if ours(&ns(&["-getsecurewebproxy", &s]), http) { ns(&["-setsecurewebproxystate", &s, "off"]); }
            let so = ns(&["-getsocksfirewallproxy", &s]);
            if ours(&so, socks) || ours(&so, http) { ns(&["-setsocksfirewallproxystate", &s, "off"]); }
        }
    }
    pub fn all_ours(http: u16) -> bool {
        let sv = services();
        // службы, где прокси не настраивается (networksetup не отдаёт «Enabled:»), не считаем
        !sv.is_empty() && sv.iter().all(|s| { let o = ns(&["-getwebproxy", s]); !o.contains("Enabled:") || ours(&o, http) })
    }
    pub fn any_ours(http: u16, socks: u16) -> bool {
        services().iter().any(|s| {
            let so = ns(&["-getsocksfirewallproxy", s]);
            ours(&ns(&["-getwebproxy", s]), http) || ours(&ns(&["-getsecurewebproxy", s]), http) || ours(&so, socks) || ours(&so, http)
        })
    }
}

/// Наши собственные процессы Xray (лежат рядом с приложением) — на случай «потерянных» после сбоя или двойного запуска.
fn kill_own_xray(keep_pid: Option<u32>) {
    let own_dir = match std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())) { Some(d) => d, None => return };
    let sys = sysinfo::System::new_all();
    for (pid, p) in sys.processes() {
        if Some(pid.as_u32()) == keep_pid { continue; }
        let name = p.name().to_string_lossy().to_lowercase();
        // и wireproxy (AmneziaWG): «потерянный» после падения держал бы наши порты 38808/38809
        if !name.contains("xray") && !name.contains("wireproxy") { continue; }
        if let Some(exe) = p.exe() { if exe.starts_with(&own_dir) { let _ = p.kill(); } }
    }
}

/// Для отчёта о связи: проверки трафика за час (1 — ок, 0 — сбой, 2 — «нет связи», 3 — перезапуск).
static HEALTH: std::sync::Mutex<Vec<(u64, u8)>> = std::sync::Mutex::new(Vec::new());
static UP_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn mark(app: &AppHandle, kind: u8) {
    let now = crate::now_ms();
    let (ok, fail, deg, rs) = {
        let mut h = HEALTH.lock().unwrap();
        h.push((now, kind));
        h.retain(|(t, _)| *t + 3_600_000 > now);
        let c = |k: u8| h.iter().filter(|(_, x)| *x == k).count();
        (c(1), c(0), c(2), c(3))
    };
    let up = UP_AT.load(std::sync::atomic::Ordering::SeqCst);
    let up_min = if up > 0 { (now.saturating_sub(up)) / 60_000 } else { 0 };
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.eval(&format!("window.__INS_HEALTH={{ok_1h:{ok},fails_1h:{fail},degraded_1h:{deg},restarts_1h:{rs},up_min:{up_min}}}"));
    }
}

/// Один запуск подключения за раз: повторное нажатие / трей / автоподключение не плодят второй Xray.
/// До какого времени (мс) ручной протокол заменён «Автовыбором» (ручной путь не пропускал трафик). 0 - не заменён.
static TEMP_AUTO_UNTIL: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn manual_name(c: &str) -> &'static str { match c { "reality" => "Быстрый", "xhttp" => "Стабильный", "hysteria2" => "Для Wi-Fi", _ => "выбранная конфигурация" } }
static STARTING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
struct StartGuard;
impl Drop for StartGuard { fn drop(&mut self) { STARTING.store(false, std::sync::atomic::Ordering::SeqCst); } }

/// При запуске приложения: если прошлый сеанс оборвался (сбой, принудительный выход) — убираем свой прокси и Xray,
/// иначе у человека «VPN как будто работает» или пропадает интернет.
pub fn cleanup_stale() {
    if STARTING.swap(true, std::sync::atomic::Ordering::SeqCst) { return; }
    let _g = StartGuard;
    kill_own_xray(None);
    if proxy_left_on() { set_proxy(false); }
}

// 26.09: были 10808/10809 - это стандартные порты Happ/v2rayN; пока работал наш Xray, Happ не запускался
// («Порт 10808 уже занят другим процессом»). Берём свои редкие порты.
const SOCKS_PORT: u16 = 38808;
/// 28.09 (tasks/00000c): вход wireproxy за маршрутизатором (только SOCKS, снаружи не виден)
const AWG_INNER_PORT: u16 = 38818;
/// 28.09 (владелец, tasks/00000c): невидимый маршрутизатор перед AWG - всё российское мимо туннеля. Откат: false.
const AWG_ROUTER: bool = true;
pub const HTTP_PORT: u16 = 38809;
/// 26.09: вход только для проверки пути реальной загрузкой (правило маршрута ведёт его строго в путь, см. add_probe_rule)
pub const PROBE_PORT: u16 = 38810;
const API_PORT: u16 = 38813;
/// 30.09 (владелец, SOVAM): вход для страницы приложения - запасной путь окна, если напрямую страница не открылась (фильтр режет
/// приветствие шифрования WebKit/WebView2 в 2 пакета). Маршрут - как у проверки (в туннель); у AmneziaWG - insellers.su -> awg.
pub const PAGE_PORT: u16 = 38815;
/// 27.09 (п.5): счётчики трафика ядра по выходам (xray metrics, /debug/vars) - мгновенное обнаружение заморозки
const METRICS_PORT: u16 = 38814;
const PROBE_URL: &str = "https://vpn.insellers.su/probe/";

#[derive(Default)]
pub struct VpnState {
    pub child: Mutex<Option<CommandChild>>,
    /// 28.09 (tasks/00000c): локальный маршрутизатор перед AmneziaWG (xray: российское напрямую, остальное - в wireproxy)
    pub router: Mutex<Option<CommandChild>>,
    /// Человек хочет быть подключённым (не нажимал «Отключить») — для переподключения и Kill Switch.
    pub wanted: std::sync::atomic::AtomicBool,
    pub retries: std::sync::atomic::AtomicU32,
    /// Поколение подключения: растёт при каждом «Отключить»/новом подключении. Таймеры, сторож и
    /// незаконченный запуск проверяют его и не трогают прокси, если человек уже отключился.
    pub guest_gen: std::sync::atomic::AtomicU32,
}

fn bump_gen(app: &AppHandle) -> u32 {
    app.try_state::<VpnState>().map(|s| s.guest_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1).unwrap_or(0)
}
fn cur_gen(app: &AppHandle) -> u32 {
    app.try_state::<VpnState>().map(|s| s.guest_gen.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(0)
}

const GUEST_END_MSG: &str = "Бесплатный VPN до входа закончился - войдите через Telegram. Полный интернет: 30 минут за ролик, +3 дня за друга или подписка";

/// По окончании гостевых минут: есть вход и подписка — переключаемся на неё, иначе отключаемся.
fn arm_guest_timer(app: &AppHandle, until: u64) {
    let gen = bump_gen(app);
    if until == 0 { return; }
    let a = app.clone();
    std::thread::spawn(move || {
        loop {
            let now = crate::now_ms();
            if now >= until { break; }
            std::thread::sleep(Duration::from_millis((until - now).min(1000)));
            if cur_gen(&a) != gen { return; }
        }
        let running = a.try_state::<VpnState>().map(|s| s.child.lock().unwrap().is_some()).unwrap_or(false);
        if cur_gen(&a) != gen || !running { return; }
        crate::guest_clear();
        if let Some(w) = a.get_webview_window("main") { let _ = w.eval("window.__INS_GUEST_UNTIL=0"); }
        if !crate::load_token().is_empty() {
            if tauri::async_runtime::block_on(start(a.clone())).is_ok() { notify(&a, "connected", ""); return; }
        }
        stop(&a);
        notify_code(&a, "error", GUEST_END_MSG, "guest_expired");
    });
}

/// Выбор протокола в мини-аппе (auto / reality / xhttp / hysteria2); не узнали — "".
/// AmneziaWG на этом устройстве не проходит (26.09): ключ получили, а трафик через wireproxy не идёт - 6 часов AWG здесь
/// не пробуем, подключаемся через Xray (как Android). Отметка - файл awg_off (время в мс) в папке данных.
// 27.09 (tasks/0000b): AmneziaWG - умолчание; не пошёл - Xray на 30 мин, потом снова пробуем AWG (было 6 ч)
const AWG_OFF_MS: u64 = 30 * 60 * 1000;
/// 30.09: когда в последний раз уходили с AmneziaWG по живой проверке (не чаще раза в 30 с)
static LAST_AWG_SW: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
fn awg_off(dir: &PathBuf) -> bool {
    std::fs::read_to_string(dir.join("awg_off")).ok().and_then(|t| t.trim().parse::<u64>().ok())
        .map(|t| crate::now_ms().saturating_sub(t) < AWG_OFF_MS).unwrap_or(false)
}
fn set_awg_off(dir: &PathBuf) { let _ = std::fs::write(dir.join("awg_off"), crate::now_ms().to_string()); }

/// Шлюз по умолчанию физической сети (для журнала «сменилась сеть»): macOS - `route -n get default` (при TUN это
/// маршрут sing-box, поэтому берём строку interface+gateway как есть - смена Wi-Fi всё равно меняет её), Windows - пусто.
fn default_gateway() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Ok(o) = std::process::Command::new("/sbin/route").args(["-n", "get", "default"]).output() {
            let t = String::from_utf8_lossy(&o.stdout);
            return t.lines().filter(|l| l.contains("gateway:") || l.contains("interface:"))
                .map(|l| l.trim().to_string()).collect::<Vec<_>>().join(" ");
        }
    }
    String::new()
}

/// AmneziaWG (25.09): ключ этого компьютера с сервера и конфиг для wireproxy-awg — он поднимает AWG и отдаёт
/// его как локальные SOCKS/HTTP-прокси на тех же портах, что Xray. Прав администратора не нужно.
async fn awg_conf(client: &reqwest::Client, token: &str) -> Result<String, String> {
    let r = client.post(format!("{}/api/app/awg/config", crate::BASE)).header("X-App-Token", token)
        // caps awg31 (26.09): wireproxy-awg v1.0.18 умеет HeaderProtectionKey/RandomTrailers/DisableCookies - сервер не выдаст
        // AWG с ними тем, кто не умеет
        .json(&json!({"hwid": format!("ins-{}", crate::install_id()), "caps": ["awg31"]})).send().await
        .map_err(|_| "Сервер AmneziaWG недоступен".to_string())?;
    match r.status().as_u16() {
        200..=299 => {}
        402 => return Err("Нет активной подписки".into()),
        409 => return Err("Достигнут лимит устройств - отключите лишнее в «Устройствах»".into()),
        _ => return Err("AmneziaWG сейчас недоступен - выберите другой протокол".into()),
    }
    let v: Value = r.json().await.map_err(|_| "AmneziaWG: неверный ответ сервера".to_string())?;
    awg_text(&v)
}

/// 27.09 (tasks/0000b): AmneziaWG гостю до входа - пир по hwid и гостевой подписке, сервер держит его в ограниченном режиме.
async fn awg_conf_guest(client: &reqwest::Client, sub: &str) -> Result<String, String> {
    let r = client.post(format!("{}/api/app/awg/guest", crate::BASE))
        .json(&json!({"hwid": format!("ins-{}", crate::install_id()), "sub": sub, "caps": ["awg31"]})).send().await
        .map_err(|_| "Сервер AmneziaWG недоступен".to_string())?;
    if !r.status().is_success() { return Err(format!("AmneziaWG до входа недоступен ({})", r.status().as_u16())); }
    let v: Value = r.json().await.map_err(|_| "AmneziaWG: неверный ответ сервера".to_string())?;
    awg_text(&v)
}

/// Тот же конфиг AWG, но wireproxy слушает только внутренний SOCKS (за маршрутизатором).
fn awg_inner(conf: &str) -> String {
    let i = conf.find("\n[Socks5]").unwrap_or(conf.len());
    format!("{}\n[Socks5]\nBindAddress = 127.0.0.1:{AWG_INNER_PORT}\n", &conf[..i])
}

fn awg_text(v: &Value) -> Result<String, String> {
    let c = &v["config"];
    let s = |k: &str| c[k].as_str().unwrap_or("").to_string();
    if s("private_key").is_empty() || s("server_pubkey").is_empty() || s("endpoint").is_empty() {
        return Err("AmneziaWG: сервер не прислал настройки".into());
    }
    let dns: Vec<String> = c["dns"].as_array().map(|a| a.iter().filter_map(|x| x.as_str().map(|y| y.to_string())).collect()).unwrap_or_default();
    let mut t = String::from("[Interface]\n");
    t += &format!("PrivateKey = {}\nAddress = {}\n", s("private_key"), s("address"));
    t += &format!("DNS = {}\n", if dns.is_empty() { "1.1.1.1".to_string() } else { dns.join(", ") });
    t += &format!("MTU = {}\n", c["mtu"].as_u64().unwrap_or(1280));
    if let Some(a) = c["awg"].as_object() {
        for k in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
                  "HeaderProtectionKey", "RandomTrailers", "DisableCookies"] {   // последние три - AmneziaWG 3.1 (26.09)
            let v = match a.get(k) { Some(Value::String(x)) => x.clone(), Some(Value::Number(n)) => n.to_string(),
                                     Some(Value::Bool(b)) => b.to_string(), _ => continue };
            if !v.is_empty() { t += &format!("{k} = {v}\n"); }
        }
    }
    t += "\n[Peer]\n";
    t += &format!("PublicKey = {}\n", s("server_pubkey"));
    if !s("psk").is_empty() { t += &format!("PresharedKey = {}\n", s("psk")); }
    t += &format!("Endpoint = {}\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = {}\n", s("endpoint"), c["keepalive"].as_u64().unwrap_or(25));
    t += &format!("\n[Socks5]\nBindAddress = 127.0.0.1:{SOCKS_PORT}\n\n[http]\nBindAddress = 127.0.0.1:{HTTP_PORT}\n");
    Ok(t)
}

async fn transport_choice(client: &reqwest::Client, token: &str) -> String {
    let r = client.get(format!("{}/api/transport", crate::BASE)).header("X-App-Token", token).timeout(Duration::from_secs(8)).send().await;
    match r {
        // режим продления (26.09): сервер отдаёт grace=true - AmneziaWG в нём не пускается, берём Xray «только Telegram»
        // (как при «Автовыборе»); после ролика/оплаты grace=false - при следующем подключении снова выбранный протокол
        Ok(r) => r.json::<Value>().await.ok().map(|v| {
            // 27.09 (tasks/0000b): «Автовыбор» = то, что предлагает сервер (effective: AmneziaWG у всех, кроме операторов, где он
            // массово не работает); AmneziaWG и в ограниченном режиме - «только Telegram» для него держит сервер
            let c = v["choice"].as_str().unwrap_or("").to_string();
            if (c.is_empty() || c == "auto") && v["effective"].as_str() == Some("amneziawg") { "amneziawg".to_string() } else { c }
        }).unwrap_or_default(),
        Err(_) => String::new(),
    }
}

fn is_hy(o: &Value) -> bool {
    let p = o["protocol"].as_str().unwrap_or("").to_lowercase();
    let n = o.pointer("/streamSettings/network").and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
    ["hysteria", "hysteria2", "hy2"].contains(&p.as_str()) || ["hysteria", "hysteria2", "hy2"].contains(&n.as_str())
}
fn is_proxy(o: &Value) -> bool {
    let p = o["protocol"].as_str().unwrap_or("").to_lowercase();
    ["vless", "vmess", "trojan", "shadowsocks"].contains(&p.as_str()) && !is_hy(o)
}

fn net_of(o: &Value) -> String { o.pointer("/streamSettings/network").and_then(|v| v.as_str()).unwrap_or("").to_lowercase() }

/// Конфигурация по выбору человека. «Автовыбор» - как отдал сервер (несколько путей, проверки observatory реальной
/// загрузкой 32 КБ, leastLoad; порядок - центр диагностики для провайдера). Явный протокол («Быстрый» → Reality,
/// «Стабильный» → XHTTP, «Для Wi-Fi» → hy2) - один путь без балансировщика.
fn pick_config(raw: Value, choice: &str) -> Value {
    let list: Vec<Value> = match raw { Value::Array(a) => a, v => vec![v] };
    if list.is_empty() { return Value::Null; }
    // «Автовыбор» (25.09): конфиг сервера как есть — несколько путей + проверки + балансировщик,
    // ядро само переключается на рабочий путь. Один путь — только при явном выборе протокола.
    if choice != "reality" && choice != "xhttp" && choice != "hysteria2" {
        let outs_of = |c: &Value| -> Vec<Value> { c["outbounds"].as_array().cloned().unwrap_or_default() };
        if let Some(c) = list.iter().find(|c| outs_of(c).iter().any(is_proxy)) { return c.clone(); }
    }
    let want = |o: &Value| -> bool {
        match choice {
            "hysteria2" => is_hy(o),
            "xhttp" => is_proxy(o) && net_of(o) == "xhttp",
            "reality" => is_proxy(o) && net_of(o) != "xhttp",
            _ => false,   // «Автовыбор»: путь решает сервер — берём его первый выход как есть (25.09)
        }
    };
    let outs = |c: &Value| -> Vec<Value> { c["outbounds"].as_array().cloned().unwrap_or_default() };
    let idx = list.iter().position(|c| outs(c).iter().any(|o| want(o)))
        .or_else(|| list.iter().position(|c| outs(c).iter().any(is_proxy)));
    let mut c = match idx { Some(i) => list[i].clone(), None => return list[0].clone() };
    let all = outs(&c);
    let main = match all.iter().find(|o| want(o)).or_else(|| all.iter().find(|o| is_proxy(o))) { Some(m) => m.clone(), None => return c };
    let tag = main["tag"].as_str().unwrap_or("").to_string();
    let others: Vec<String> = all.iter().filter(|o| (is_proxy(o) || is_hy(o)) && **o != main)
        .map(|o| o["tag"].as_str().unwrap_or("").to_string()).collect();
    let mut keep = vec![main.clone()];
    keep.extend(all.into_iter().filter(|o| !is_proxy(o) && !is_hy(o)));
    c["outbounds"] = Value::Array(keep);
    if let Some(obj) = c.as_object_mut() { obj.remove("observatory"); obj.remove("burstObservatory"); }
    if let Some(r) = c.get_mut("routing").and_then(|r| r.as_object_mut()) { r.remove("balancers"); }
    if let Some(rules) = c.pointer_mut("/routing/rules").and_then(|r| r.as_array_mut()) {
        for r in rules.iter_mut() {
            if let Some(o) = r.as_object_mut() {
                if o.remove("balancerTag").is_some() { o.insert("outboundTag".into(), json!(tag)); }
            }
            if r["outboundTag"].as_str().map(|t| others.iter().any(|x| x == t)).unwrap_or(false) { r["outboundTag"] = json!(tag); }
        }
    }
    c
}

/// Видео (аудит 24.09): QUIC (UDP 443) через Reality+Vision не ходит — блокируем сразу, чтобы шли по TCP.
fn tune(cfg: &mut Value) {
    let block = cfg["outbounds"].as_array().and_then(|a| a.iter().find(|o| o["protocol"] == "blackhole"))
        .and_then(|o| o["tag"].as_str()).map(|s| s.to_string());
    let block = match block {
        Some(t) => t,
        None => {
            if let Some(a) = cfg["outbounds"].as_array_mut() { a.push(json!({"tag": "ins-block", "protocol": "blackhole"})); }
            "ins-block".to_string()
        }
    };
    if !cfg["routing"].is_object() { cfg["routing"] = json!({}); }
    let old = cfg["routing"]["rules"].as_array().cloned().unwrap_or_default();
    let mut rules = vec![json!({"type": "field", "network": "udp", "port": "443", "outboundTag": block})];
    rules.extend(old);
    cfg["routing"]["rules"] = Value::Array(rules);
    // macOS: если маршрут по умолчанию сейчас у чужого туннеля (Happ, Outline и т.п.), наш Xray шёл бы
    // к серверу ВНУТРИ него — «VPN в VPN», секундный пинг и тормоза видео. Привязываем выход к физической сети.
    #[cfg(target_os = "macos")]
    if let Some(ifc) = mac_physical_if_when_hijacked() {
        if let Some(outs) = cfg["outbounds"].as_array_mut() {
            for o in outs.iter_mut() {
                if is_proxy(o) || is_hy(o) {
                    if !o["streamSettings"].is_object() { o["streamSettings"] = json!({}); }
                    if !o["streamSettings"]["sockopt"].is_object() { o["streamSettings"]["sockopt"] = json!({}); }
                    o["streamSettings"]["sockopt"]["interface"] = json!(ifc);
                }
            }
        }
    }
}

/// Физический интерфейс (en0 и т.п.), если маршрут по умолчанию сейчас у чужого utun/ppp/ipsec.
#[cfg(target_os = "macos")]
fn mac_physical_if_when_hijacked() -> Option<String> {
    let run = |args: &[&str], prog: &str| std::process::Command::new(prog).args(args).output().ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default();
    let def = run(&["-n", "get", "default"], "/sbin/route");
    let cur = def.lines().find_map(|l| l.trim().strip_prefix("interface:")).map(|v| v.trim().to_string()).unwrap_or_default();
    let virt = |n: &str| n.starts_with("utun") || n.starts_with("ppp") || n.starts_with("ipsec") || n.starts_with("tun");
    if cur.is_empty() || !virt(&cur) { return None; }
    let nwi = run(&["--nwi"], "/usr/sbin/scutil");
    nwi.lines().find_map(|l| l.trim().strip_prefix("Network interfaces:"))
        .and_then(|v| v.split_whitespace().find(|n| !virt(n)).map(|n| n.to_string()))
}

/// Есть ли свежая (не старше 14 дней) сохранённая рабочая конфигурация.
fn fresh_last(p: &std::path::Path) -> bool {
    std::fs::metadata(p).and_then(|m| m.modified())
        .map(|t| t.elapsed().map(|d| d.as_secs() < 14 * 86400).unwrap_or(false))
        .unwrap_or(false)
}

/// Ссылка на подписку человека по токену входа.
pub(crate) async fn sub_url(client: &reqwest::Client, token: &str) -> Result<String, String> {
    // 26.09: сразу после закрытия другого VPN (Happ в режиме TUN) сеть на Маке пару секунд «висит» - один запрос на 20 с
    // давал «Нет связи с сервером», хотя повтор через 6 с проходил за 2 с. Теперь 3 попытки по 8 с с паузой 2 с.
    let mut resp = None;
    // 29.09 (владелец: на Маке постоянно «по сохранённым настройкам»): вторая попытка - через NL-2 (n2.insellers.su -> тот же
    // бэкенд по WG): если оператор режет адрес NL-1, свежие настройки придут другим путём
    for (i, base) in [crate::BASE, crate::BASE_ALT, crate::BASE].iter().enumerate() {
        if i > 0 { crate::tokio_sleep(2).await; }
        match client.get(format!("{}/api/app/sub", base)).header("X-App-Token", token)
            .timeout(Duration::from_secs(8)).send().await {
            Ok(r) if r.status().is_server_error() => continue,   // 26.09: 502 на рестарте сервера - повтор, а не «ответил неверно»
            Ok(r) if *base == crate::BASE_ALT && !r.status().is_success() && r.status().as_u16() != 401 => continue,   // запасной ещё не настроен
            Ok(r) => { resp = Some(r); break; }
            Err(_) => continue,
        }
    }
    let sub: Value = resp.ok_or("Нет связи с сервером".to_string())?
        .json().await.map_err(|_| "Сервер ответил неверно".to_string())?;
    Ok(sub["sub"].as_str().ok_or("Нет активной подписки")?.to_string())
}

pub fn set_wanted(app: &AppHandle, v: bool) {
    if let Some(s) = app.try_state::<VpnState>() { s.wanted.store(v, std::sync::atomic::Ordering::SeqCst); }
}
fn wanted(app: &AppHandle) -> bool {
    app.try_state::<VpnState>().map(|s| s.wanted.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(false)
}

// ---- проверка путей (26.09) ----
static BAD_PATHS: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
/// 29.09: когда в последний раз забирали подписку через туннель (переподключение на свежие настройки - не чаще раза в 30 мин)
static LAST_REFRESH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static CUR_PATH: Mutex<String> = Mutex::new(String::new());
fn mark_bad(tag: &str) {
    if tag.is_empty() { return; }
    let mut g = BAD_PATHS.lock().unwrap();
    g.retain(|(t, _)| t != tag);
    g.push((tag.to_string(), crate::now_ms()));
}
fn is_bad(tag: &str) -> bool {
    let now = crate::now_ms();
    BAD_PATHS.lock().unwrap().iter().any(|(t, ts)| t == tag && now.saturating_sub(*ts) < 30 * 60 * 1000)
}
fn set_cur_path(tag: &str) { *CUR_PATH.lock().unwrap() = tag.to_string(); }
pub(crate) fn cur_path() -> String { CUR_PATH.lock().unwrap().clone() }
static CUR_DESC: Mutex<String> = Mutex::new(String::new());
/// этап 7: выход, на который переключили балансировщик через API (общий для медленной проверки и быстрого сторожа)
static HOT_CUR: Mutex<String> = Mutex::new(String::new());
/// 27.09 (п.5): выходы, замёрзшие недавно (тег, до какого момента не брать)
static HOT_BAD: Mutex<Vec<(String, u64)>> = Mutex::new(Vec::new());
fn set_cur_desc(d: &str) { *CUR_DESC.lock().unwrap() = d.to_string(); }
pub(crate) fn cur_desc() -> String { CUR_DESC.lock().unwrap().clone() }
fn manual_choice(choice: &str) -> bool { choice == "reality" || choice == "xhttp" || choice == "hysteria2" || choice.starts_with("cfg:") }

/// Описание пути для центра диагностики: вид@адрес (xhttp@212.34.151.212); у балансировщика - "auto".
fn path_desc(c: &Value) -> String {
    let t = path_tag(c);
    if t == "auto" { return t; }
    let o = match c["outbounds"].as_array().and_then(|a| a.iter().find(|o| o["tag"].as_str() == Some(t.as_str()))) { Some(o) => o, None => return t };
    let kind = if is_hy(o) { "hy2" } else { match net_of(o).as_str() { "xhttp" => "xhttp", "grpc" => "grpc", _ => "reality" } };
    let addr = o.pointer("/settings/vnext/0/address").or_else(|| o.pointer("/settings/servers/0/address"))
        .or_else(|| o.pointer("/settings/address")).and_then(|v| v.as_str()).unwrap_or("");
    format!("{kind}@{addr}")
}

/// Проверка идёт строго через путь: vpn.insellers.su = IP сервера NL-1, а IP серверов идут напрямую (иначе петля) -
/// без этого правила проверка уходила бы мимо туннеля и «проходила» на мёртвом пути.
fn add_probe_rule(cfg: &mut Value) {
    let bal = cfg.pointer("/routing/balancers/0/tag").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let main = if bal.is_empty() { path_tag(cfg) } else { String::new() };
    if bal.is_empty() && main.is_empty() { return; }
    if cfg["routing"]["rules"].as_array().map(|a| a.iter().any(|r| r["inboundTag"] == json!(["probe-in"]) || r["inboundTag"] == json!(["probe-in", "page-in"]))).unwrap_or(false) { return; }
    // 30.09: page-in (запасной путь страницы окна) - тем же путём, что проверка
    let rule = if !bal.is_empty() { json!({"type": "field", "inboundTag": ["probe-in", "page-in"], "balancerTag": bal}) }
               else { json!({"type": "field", "inboundTag": ["probe-in", "page-in"], "outboundTag": main}) };
    if !cfg["routing"].is_object() { cfg["routing"] = json!({}); }
    cfg["api"] = json!({"tag": "api", "services": ["RoutingService"]});   // этап 7: xray api bo
    // 27.09 (п.5): счётчики по выходам для быстрого сторожа заморозки (только 127.0.0.1)
    cfg["stats"] = json!({});
    if !cfg["policy"].is_object() { cfg["policy"] = json!({}); }
    if !cfg["policy"]["system"].is_object() { cfg["policy"]["system"] = json!({}); }
    cfg["policy"]["system"]["statsOutboundUplink"] = json!(true);
    cfg["policy"]["system"]["statsOutboundDownlink"] = json!(true);
    cfg["metrics"] = json!({"tag": "metrics", "listen": format!("127.0.0.1:{METRICS_PORT}")});
    let old = cfg["routing"]["rules"].as_array().cloned().unwrap_or_default();
    let mut rules = vec![json!({"type": "field", "inboundTag": ["api-in"], "outboundTag": "api"}), rule];
    rules.extend(old);
    cfg["routing"]["rules"] = Value::Array(rules);
}

/// Этап 7 (26.09 ночь): путь «Автовыбора» умер - мгновенно на живой выход балансировщика через API ядра (без перезапуска:
/// системный прокси, TUN и открытые соединения других путей не трогаем). Каждый кандидат проверяем реальной загрузкой 32 КБ.
/// None - ядро без API / балансировщика или живых нет: тогда обычный перезапуск на следующий путь.
/// 29.09 (владелец, «липкость»): сервер горячего выхода - имя из тега srv:<сервер>:..., у "proxy" - по совпадению адреса
/// с выходом srv:* (иначе сам адрес). Адрес выхода для сайтов = сервер.
fn hot_servers(cfg: &Value) -> std::collections::HashMap<String, String> {
    let addr = |o: &Value| -> String {
        o.pointer("/settings/vnext/0/address").or_else(|| o.pointer("/settings/servers/0/address"))
            .or_else(|| o.pointer("/settings/address")).and_then(|v| v.as_str()).unwrap_or("").to_string()
    };
    let outs = cfg["outbounds"].as_array().cloned().unwrap_or_default();
    let mut by_addr = std::collections::HashMap::new();
    for o in &outs {
        if let Some(t) = o["tag"].as_str() { if t.starts_with("srv:") { by_addr.insert(addr(o), t.split(':').nth(1).unwrap_or("").to_string()); } }
    }
    let mut m = std::collections::HashMap::new();
    for o in &outs {
        let Some(t) = o["tag"].as_str() else { continue };
        if t.starts_with("srv:") { m.insert(t.to_string(), t.split(':').nth(1).unwrap_or("").to_string()); }
        else if t == "proxy" { let a = addr(o); m.insert(t.to_string(), by_addr.get(&a).cloned().unwrap_or(a)); }
    }
    m
}

async fn hot_switch(app: &AppHandle, dir: &PathBuf, cur: &str) -> Option<String> {
    let cfg: Value = serde_json::from_slice(&std::fs::read(dir.join("config.json")).ok()?).ok()?;
    let bal = cfg.pointer("/routing/balancers/0/tag").and_then(|v| v.as_str())?.to_string();
    let mut tags: Vec<String> = cfg["outbounds"].as_array()?.iter()
        .filter_map(|o| o["tag"].as_str().map(|t| t.to_string()))
        .filter(|t| (t == "proxy" || t.starts_with("srv:")) && t != cur && !hot_bad(t))
        .collect();
    // «липкость» (29.09): сначала другие протоколы ТОГО ЖЕ сервера (адрес выхода не меняется), другой сервер - только если
    // все протоколы сервера не прошли (sort_by_key устойчивая - внутри групп прежний порядок сервера)
    let srv = hot_servers(&cfg);
    let home = srv.get(cur).cloned().unwrap_or_default();
    tags.sort_by_key(|t| if srv.get(t).map(|x| *x == home).unwrap_or(false) { 0 } else { 1 });
    for t in tags {
        let args: Vec<String> = vec!["api".into(), "bo".into(), format!("--server=127.0.0.1:{API_PORT}"), "-b".into(), bal.clone(), t.clone()];
        let out = app.shell().sidecar("xray").ok()?.args(args).output().await.ok()?;
        if !out.status.success() { return None; }
        if probe_real_t("32k", 4).await.0 { return Some(t); }   // 27.09: проверка после переключения - 4 с, не 15
        hot_mark_bad(&t, 60_000);
    }
    None
}

fn hot_bad(t: &str) -> bool {
    let now = crate::now_ms();
    let mut b = HOT_BAD.lock().unwrap();
    b.retain(|(_, until)| *until > now);
    b.iter().any(|(x, _)| x == t)
}

fn hot_mark_bad(t: &str, ms: u64) {
    let mut b = HOT_BAD.lock().unwrap();
    b.retain(|(x, _)| x != t);
    b.push((t.to_string(), crate::now_ms() + ms));
}

/// 27.09 (владелец, п.5): быстрый сторож заморозки. Раз в секунду - счётчики ядра по выходам (proxy, srv:*).
/// ЗАМОРОЗКА = 2 с подряд приходит < 1,5 КБ/с, а запросы уходят (> 300 Б/с), и до этого за 5 с пришло >= 30 КБ (или за эти
/// 2 с ушло 2-60 КБ запросов; крупная отправка - не заморозка). Реакция - сразу следующий выход балансировщика через API ядра
/// (без перезапуска), проверка 32 КБ уже после переключения; не прошёл - следующий. Замёрзший не берём 2 мин.
fn freeze_now(hist: &std::collections::VecDeque<(u64, u64)>) -> bool {
    let n = hist.len();
    if n < 2 { return false; }
    let last2: Vec<&(u64, u64)> = hist.iter().skip(n - 2).collect();
    if !last2.iter().all(|(rx, tx)| *rx < 1_500 && *tx > 300) { return false; }
    let before: u64 = hist.iter().take(n - 2).rev().take(5).map(|(rx, _)| *rx).sum();
    let tx2: u64 = last2.iter().map(|(_, tx)| *tx).sum();
    before >= 30_000 || (2_000..=60_000).contains(&tx2)
}

async fn freeze_confirmed() -> bool {
    for seconds in [3, 4] {
        let r = probe_real_t("32k", seconds).await;
        if r.0 || r.3 == "core" || r.3.starts_with("http ") { return false; }
    }
    true
}

async fn freeze_watch(app: AppHandle, dir: PathBuf, gen: u32) {
    let client = match reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(800)).build() { Ok(c) => c, Err(_) => return };
    let url = format!("http://127.0.0.1:{METRICS_PORT}/debug/vars");
    let mut prev: Option<(u64, u64)> = None;
    let mut hist: std::collections::VecDeque<(u64, u64)> = std::collections::VecDeque::new();
    let mut stall_since = 0u64;
    let mut last_switch = 0u64;
    crate::tokio_sleep(10).await;
    loop {
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_millis(1000))).await.ok();
        if cur_gen(&app) != gen || !wanted(&app) { break; }
        let v: Value = match client.get(&url).send().await {
            Ok(r) => r.json().await.unwrap_or(Value::Null),
            Err(_) => { prev = None; hist.clear(); continue; }        // ядро перезапускается / без metrics (старый конфиг)
        };
        let (mut up, mut down) = (0u64, 0u64);
        if let Some(o) = v.pointer("/stats/outbound").and_then(|x| x.as_object()) {
            for (tag, c) in o {
                if tag == "proxy" || tag.starts_with("srv:") {
                    up += c["uplink"].as_u64().unwrap_or(0);
                    down += c["downlink"].as_u64().unwrap_or(0);
                }
            }
        } else { prev = None; continue; }
        let now = crate::now_ms();
        if let Some((pu, pd)) = prev {
            if up < pu || down < pd { hist.clear(); }                 // новое ядро - счётчики с нуля
            else {
                let (d_rx, d_tx) = (down - pd, up - pu);
                hist.push_back((d_rx, d_tx));
                while hist.len() > 8 { hist.pop_front(); }
                if d_rx < 1_500 && d_tx > 300 { if stall_since == 0 { stall_since = now.saturating_sub(1000); } } else { stall_since = 0; }
            }
        }
        prev = Some((up, down));
        if freeze_now(&hist) && now.saturating_sub(last_switch) > 4_000 {
            let t0 = if stall_since > 0 { stall_since } else { now };
            let cur = { let c = HOT_CUR.lock().unwrap().clone(); if c.is_empty() { "proxy".to_string() } else { c } };
            let confirmed = freeze_confirmed().await;
            if cur_gen(&app) != gen || !wanted(&app) { break; }
            if !confirmed || !direct_ok().await {
                hist.clear(); stall_since = 0; prev = None; last_switch = crate::now_ms();
                continue;
            }
            hot_mark_bad(&cur, 120_000);
            let from = cur_desc();
            if let Some(to) = hot_switch(&app, &dir, &cur).await {
                *HOT_CUR.lock().unwrap() = to.clone();
                crate::remote_log("vpn.hot_switch", crate::telemetry::switch_fields(json!({"from": from, "to": to, "how": "freeze",
                    "detect_ms": crate::now_ms().saturating_sub(t0), "gap_ms": crate::now_ms().saturating_sub(t0)}), "no_traffic"));
            } else {
                crate::remote_log("vpn.freeze", json!({"from": from, "cur": cur, "switched": false}));
            }
            last_switch = crate::now_ms();
            hist.clear(); stall_since = 0; prev = None;
        }
    }
}

/// Скачать `size` (256k | 32k) с нашего сервера ЧЕРЕЗ путь (вход probe-in): (ok, байт, мс, причина отказа:
/// core - ядро не слушает, timeout, short - оборвалось на середине = заморозка оператором, http <код>, io). До ~15 с.
async fn probe_real(size: &str) -> (bool, u64, u64, String) { probe_real_t(size, 15).await }

async fn probe_real_t(size: &str, secs: u64) -> (bool, u64, u64, String) {
    let want: u64 = if size == "32k" { 32_768 } else { 262_144 };
    let t0 = std::time::Instant::now();
    let ms = |t: std::time::Instant| t.elapsed().as_millis() as u64;
    let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{PROBE_PORT}"))
        .and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(secs)).build()) {
        Ok(c) => c, Err(_) => return (false, 0, 0, "io".into()),
    };
    let url = format!("{PROBE_URL}{size}?r={}", crate::now_ms());
    let mut resp = match client.get(&url).header("Cache-Control", "no-cache").send().await {
        Ok(r) => r,
        Err(e) => {
            let why = if e.is_connect() && t0.elapsed() < Duration::from_millis(500) { "core" } else if e.is_timeout() { "timeout" } else { "io" };
            return (false, 0, ms(t0), why.into());
        }
    };
    let code = resp.status().as_u16();
    if code != 200 { return (false, 0, ms(t0), format!("http {code}")); }
    let mut got: u64 = 0;
    loop {
        match resp.chunk().await {
            Ok(Some(b)) => { got += b.len() as u64; if got >= want { break; } }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    if got >= want { (true, got, ms(t0), String::new()) }
    else { (false, got, ms(t0), if got > 0 { "short".into() } else { "timeout".into() }) }
}
fn kbps(bytes: u64, ms: u64) -> u64 { if ms == 0 { 0 } else { bytes * 1000 / ms / 1024 } }

/// 29.09 (владелец: Mac после сна «Подключено», а интернета нет): проверка ЧЕРЕЗ туннель - (ok, мс, как). Xray - реальная
/// загрузка 32 КБ с нашего сервера через путь (вход probe-in) или generate_204 через локальный вход; AmneziaWG - generate_204
/// через локальный вход (у wireproxy нет входа проверки). До ~10 с. Её же вызывает страница: InsellersNative.probe().
pub async fn tunnel_check() -> (bool, u64, String) {
    let t0 = std::time::Instant::now();
    if cur_path() != "awg" {
        let (ok, _b, ms, why) = probe_real_t("32k", 6).await;
        if ok { return (true, ms, "real32k".into()); }
        if why == "core" { return (false, ms, "core".into()); }
    }
    let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{HTTP_PORT}"))
        .and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(4)).build()) { Ok(c) => c, Err(_) => return (false, 0, "io".into()) };
    for u in ["http://connectivitycheck.gstatic.com/generate_204", "http://cp.cloudflare.com/generate_204"] {
        if let Ok(r) = client.get(u).send().await {
            let s = r.status().as_u16();
            if s == 204 || s == 200 { return (true, t0.elapsed().as_millis() as u64, "204".into()); }
        }
    }
    if telegram_ok(&client).await { return (true, t0.elapsed().as_millis() as u64, "telegram_only".into()); }
    (false, t0.elapsed().as_millis() as u64, "fail".into())
}

/// 29.09 (владелец): ограниченный режим / гостевой доступ = «только Telegram»: generate_204 и наш сервер закрыты НАМЕРЕННО.
/// Telegram через туннель отвечает (любой HTTP-ответ) - связь есть, это не «нет интернета», переподключать нельзя.
async fn telegram_ok(client: &reqwest::Client) -> bool {
    for u in ["https://api.telegram.org/", "https://web.telegram.org/"] {
        if client.get(u).send().await.is_ok() { return true; }
    }
    false
}

static LAST_FORCED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Переподключение с повтором: сети ещё нет (сразу после сна) - не сдаёмся ошибкой, повтор раз в 30 с до 10 мин.
fn reconnect_retry(app: &AppHandle, t_ev: u64, reason: &'static str) {
    let b = app.clone();
    std::thread::spawn(move || {
        // первые 10 мин - раз в 30 с, дальше - раз в 2 мин, пока VPN включён (29.09: не сдаваться)
        for i in 0u32.. {
            if !wanted(&b) { return; }
            match tauri::async_runtime::block_on(start(b.clone())) {
                Ok(()) => {
                    let ok = tauri::async_runtime::block_on(tunnel_check()).0;
                    crate::remote_log("vpn.wake_ok", json!({"reason": reason, "secs": crate::now_ms().saturating_sub(t_ev) / 1000,
                        "how": "reconnect", "ok": ok, "try": i}));
                    notify(&b, "connected", "Соединение восстановлено");
                    return;
                }
                Err(e) if e == "CANCELLED" || e == "BUSY" => return,
                Err(e) => {
                    if i == 0 { crate::remote_log("vpn.reconnect_wait", json!({"reason": reason, "err": e.chars().take(120).collect::<String>()})); }
                    notify(&b, "connecting", "Нет сети - ждём и переподключаемся…");
                    std::thread::sleep(Duration::from_secs(if i < 20 { 30 } else { 120 }));
                }
            }
        }
    });
}

/// Пробуждение системы / смена сети: через 3 с проверка через туннель (2 попытки); не прошла - «Переподключаемся…» и полное
/// переподключение по Автовыбору (новое ядро и TUN), не чаще раза в 60 с. Итог - vpn.wake_ok / vpn.wake_reconnect (секунды от события).
fn wake_recover(app: &AppHandle, gen: u32, reason: &'static str) {
    let w = app.clone();
    let t_ev = crate::now_ms();
    tauri::async_runtime::spawn(async move {
        notify(&w, "connecting", "Проверяем связь…");       // 29.09: «Подключено» - только после прошедшей проверки
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(3))).await.ok();
        for i in 0..2 {
            if cur_gen(&w) != gen || !wanted(&w) { return; }
            let (ok, ms, how) = tunnel_check().await;
            if ok {
                crate::remote_log("vpn.wake_ok", json!({"reason": reason, "secs": crate::now_ms().saturating_sub(t_ev) / 1000, "ms": ms, "how": how, "try": i}));
                notify(&w, "connected", "");
                return;
            }
            tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(3))).await.ok();
        }
        if cur_gen(&w) != gen || !wanted(&w) { return; }
        let now = crate::now_ms();
        if now.saturating_sub(LAST_FORCED.load(std::sync::atomic::Ordering::SeqCst)) < 60_000 { return; }
        LAST_FORCED.store(now, std::sync::atomic::Ordering::SeqCst);
        crate::remote_log("vpn.wake_reconnect", json!({"reason": reason, "path": cur_path()}));
        notify(&w, "connecting", "Переподключаемся…");
        reconnect_retry(&w, t_ev, reason);
    });
}

/// Метка пути конфигурации: «auto» - если в ней балансировщик, иначе тег первого выхода-прокси.
fn path_tag(c: &Value) -> String {
    if c.pointer("/routing/balancers").and_then(|b| b.as_array()).map(|a| !a.is_empty()).unwrap_or(false) { return "auto".into(); }
    c["outbounds"].as_array().and_then(|a| a.iter().find(|o| is_proxy(o) || is_hy(o)))
        .and_then(|o| o["tag"].as_str()).unwrap_or("").to_string()
}

/// Конфигурация с одним путём `main` (остальные выходы-прокси убраны, правила перенаправлены на него).
fn single_from(c: &Value, main: &Value) -> Value {
    let mut c = c.clone();
    let all: Vec<Value> = c["outbounds"].as_array().cloned().unwrap_or_default();
    let tag = main["tag"].as_str().unwrap_or("").to_string();
    let others: Vec<String> = all.iter().filter(|o| (is_proxy(o) || is_hy(o)) && *o != main)
        .map(|o| o["tag"].as_str().unwrap_or("").to_string()).collect();
    let mut keep = vec![main.clone()];
    keep.extend(all.into_iter().filter(|o| !is_proxy(o) && !is_hy(o)));
    c["outbounds"] = Value::Array(keep);
    if let Some(obj) = c.as_object_mut() { obj.remove("observatory"); obj.remove("burstObservatory"); }
    if let Some(r) = c.get_mut("routing").and_then(|r| r.as_object_mut()) { r.remove("balancers"); }
    if let Some(rules) = c.pointer_mut("/routing/rules").and_then(|r| r.as_array_mut()) {
        for r in rules.iter_mut() {
            if let Some(o) = r.as_object_mut() {
                if o.remove("balancerTag").is_some() { o.insert("outboundTag".into(), json!(tag)); }
            }
            if r["outboundTag"].as_str().map(|t| others.iter().any(|x| x == t)).unwrap_or(false) { r["outboundTag"] = json!(tag); }
        }
    }
    c
}

/// Retry only transient delivery failures; never bypass an account/device denial.
fn subscription_mirror(url: &str) -> Option<String> {
    url.strip_prefix("https://direct.insellers.su/").map(|p| format!("https://n2.insellers.su/{p}"))
}
async fn subscription_text(client: &reqwest::Client, url: &str) -> Result<(String, bool), String> {
    let mut urls = vec![url.to_string()];
    if let Some(alt) = subscription_mirror(url) { urls.push(alt); }
    subscription_endpoints(client, urls).await
}
async fn subscription_endpoints(client: &reqwest::Client, urls: Vec<String>) -> Result<(String, bool), String> {
    for endpoint in urls {
        let response = match client.get(&endpoint).timeout(Duration::from_secs(8)).send().await {
            Ok(r) => r, Err(_) => continue,
        };
        let status = response.status();
        if status.is_server_error() || status.as_u16() == 408 || status.as_u16() == 429 { continue; }
        if !status.is_success() { return Err(format!("Сервер отклонил выдачу конфигурации (HTTP {})", status.as_u16())); }
        let manual_bad = response.headers().get("x-ins-manual").and_then(|v| v.to_str().ok()) == Some("bad");
        if let Ok(text) = response.text().await { return Ok((text, manual_bad)); }
    }
    Err("SUB_UNAVAILABLE".into())
}

/// Кандидаты для подключения: сначала выбор человека (или «Автовыбор» сервера), потом каждый путь по одному
/// в порядке сервера (TCP-пути, hy2 - последним). Пути, упавшие за последние 30 минут, - в конец. Не больше 5.
async fn xray_candidates(app: &AppHandle, client: &reqwest::Client, url: &str, offline: bool, choice: &str,
                         dir: &PathBuf, last: &PathBuf) -> Result<Vec<(String, Value)>, String> {
    notify(app, "connecting", if offline { "Читаем сохранённую конфигурацию…" } else { "Получаем конфигурацию VPN…" });
    let mut raw_cands: Vec<Value> = Vec::new();
    // 29.09: свежая подписка, забранная через туннель (см. h_refresh), - вместо старой сохранённой конфигурации, до 2 ч
    let fresh = dir.join("sub.fresh.json");
    let fresh_ok = std::fs::metadata(&fresh).ok().and_then(|m| m.modified().ok())
        .map(|t| t.elapsed().map(|e| e.as_secs() < 2 * 3600).unwrap_or(false)).unwrap_or(false);
    let fetched = if offline { if fresh_ok { std::fs::read_to_string(&fresh).ok() } else { None } } else {
        match subscription_text(client, url).await {
            // 27.09 (владелец): сервер (центр диагностики) видит, что ручной протокол у провайдера человека виснет (>= 50%) -
            // сразу «Автовыбор» на 15 мин с объяснением; через 15 мин - снова спросим сервер (путь ожил - вернётся выбор)
            Ok((_, true)) if manual_choice(choice) => {
                TEMP_AUTO_UNTIL.store(crate::now_ms() + 15 * 60 * 1000, std::sync::atomic::Ordering::SeqCst);
                crate::remote_log("vpn.manual_bad", json!({"manual": manual_name(choice)}));
                return Err(format!("RETRY_AUTO_BAD:{}", manual_name(choice)));
            }
            Ok((text, _)) => Some(text),
            Err(e) if e == "SUB_UNAVAILABLE" && fresh_last(last) => None,
            Err(e) if e == "SUB_UNAVAILABLE" => return Err("Не удалось получить конфигурацию через основной и резервный адрес. Проверьте сеть и повторите попытку".into()),
            Err(e) => return Err(e),
        }
    };
    let mut prepared = true;
    if let Some(txt) = fetched {
        let raw: Value = serde_json::from_str(&txt).map_err(|_| "Сервер ещё не отдаёт конфигурацию для приложения".to_string())?;
        let list: Vec<Value> = match raw.clone() { Value::Array(a) => a, v => vec![v] };
        // hy2 (UDP) первым - только если человек сам выбрал «Для Wi-Fi»
        raw_cands.push(pick_config(raw, choice));
        let mut hys = Vec::new();
        // ручной выбор протокола - только он (26.09, владелец: при ручном выборе сами не переключаем, только сообщаем)
        for c in if manual_choice(choice) { &list[..0] } else { &list[..] } {
            for o in c["outbounds"].as_array().cloned().unwrap_or_default() {
                if is_proxy(&o) { raw_cands.push(single_from(c, &o)); } else if is_hy(&o) { hys.push(single_from(c, &o)); }
            }
        }
        raw_cands.extend(hys);
        prepared = false;
    } else {
        let b = std::fs::read(last).map_err(|_| "Нет связи с сервером".to_string())?;
        raw_cands.push(serde_json::from_slice(&b).map_err(|_| "Нет связи с сервером".to_string())?);
    }
    let geo = if prepared { true } else { ensure_geo(app, dir).await };
    let mut out: Vec<(String, Value)> = Vec::new();
    for mut cfg in raw_cands {
        if cfg.is_null() { continue; }
        let tag = path_tag(&cfg);
        if out.iter().any(|(t, _)| *t == tag) { continue; }
        if !prepared {
            tune(&mut cfg);
            cfg["inbounds"] = local_inbounds();
            cfg["log"] = json!({"loglevel": "warning"});
            if !geo { strip_geo_rules(&mut cfg); }
        }
        if prepared { cfg["inbounds"] = local_inbounds(); }   // config.last.json прежних версий - без входа проверки
        add_probe_rule(&mut cfg);
        out.push((tag, cfg));
    }
    if out.is_empty() { return Err("Сервер ещё не отдаёт конфигурацию для приложения".into()); }
    // упавшие недавно - в конец (порядок остальных - как у сервера)
    let (good, bad): (Vec<_>, Vec<_>) = out.into_iter().partition(|(t, _)| !is_bad(t));
    let mut all = good; all.extend(bad); all.truncate(5);
    Ok(all)
}

/// Запуск ядра (xray или wireproxy) + наблюдение за процессом: упал сам - переподключаемся или сообщаем.
fn launch(app: &AppHandle, bin: &str, run_args: Vec<String>, dir: &PathBuf) -> Result<(), String> {
    notify(app, "connecting", "Запускаем VPN-ядро…");
    let (mut rx, child) = app.shell().sidecar(bin).map_err(|e| e.to_string())?
        .env("XRAY_LOCATION_ASSET", dir.to_string_lossy().to_string())
        .args(run_args)
        .spawn().map_err(|e| format!("Не удалось запустить ядро: {e}"))?;
    let my_pid = child.pid();
    app.state::<VpnState>().child.lock().unwrap().replace(child);
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CommandEvent::Terminated(tp) = ev {
                // это наш процесс? Если его уже забрали (отключили, сменили путь) - ничего не делаем
                let mine = {
                    let st = a.state::<VpnState>();
                    let mut g = st.child.lock().unwrap();
                    if g.as_ref().map(|c| c.pid()) == Some(my_pid) { g.take(); true } else { false }
                };
                if !mine { break; }
                if !wanted(&a) { break; }   // ещё проверяем путь или уже отключились - решает start()
                crate::telemetry::core_panic("ядро завершилось", tp.code);   // 01.10: ядро упало само, пока VPN нужен
                crate::telemetry::set_stop_reason("core_crash");
                let ks = crate::pref("killswitch");
                if !ks { crate::tun::down(); set_proxy(false); }   // Kill Switch: прокси остаётся на мёртвом порту - интернет на паузе
                if crate::pref("reconnect") {
                    let n = a.state::<VpnState>().retries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    notify(&a, "connecting", if ks { "Соединение прервано - интернет на паузе, переподключаемся…" } else { "Соединение прервано - переподключаемся…" });
                    let b = a.clone();
                    std::thread::spawn(move || {
                        std::thread::sleep(Duration::from_secs([2u64, 5, 10, 20, 30][(n as usize).min(4)]));
                        if !wanted(&b) { return; }
                        match tauri::async_runtime::block_on(start(b.clone())) {
                            Ok(()) => { b.state::<VpnState>().retries.store(0, std::sync::atomic::Ordering::SeqCst); notify(&b, "connected", "Соединение восстановлено"); }
                            Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                            Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                        }
                    });
                } else {
                    notify(&a, if ks { "error" } else { "disconnected" }, if ks { "Соединение прервано - интернет на паузе (Kill Switch)" } else { "Соединение прервано" });
                }
                break;
            }
        }
    });
    Ok(())
}
fn kill_child(app: &AppHandle) {
    let c = app.state::<VpnState>().child.lock().unwrap().take();
    if let Some(c) = c { let _ = c.kill(); }
    let r = app.state::<VpnState>().router.lock().unwrap().take();
    if let Some(r) = r { let _ = r.kill(); }
}

/// 29.09 вечер (ревизия рекламы): хосты ПОКАЗА наших рекламных сетей - напрямую, с IP человека (копия OUR_AD_NETWORKS из sub.py,
/// менять вместе). До этого при AmneziaWG вся реклама шла через туннель: сети видели адрес нашего сервера - Adsterra отвечала
/// 403 на скрипт (журнал: banner.nofill why=script), Kadam/OnClickA/HilltopAds - «нет рекламы»; без VPN на том же Mac - показ.
/// gigapub.tech здесь НЕТ: его хосты на Hetzner (в РФ заблокирован) - остаётся в туннеле.
const AD_DIRECT: &[&str] = &[
    // 30.09 14:50: MyBid (баннер) - скрипт/ставки/креативы (AS39572); mbdippex/rtbrenab/zivroq на Hetzner - через туннель
    "mbidadm.com", "mbidtg.com", "cabnnr.com",
    // 30.09 15:10: AdsBitvex (ролики) - Cloudflare, только по имени
    "adsbitvex.com",
    // 30.09 17:00: то, что было только в ad-extra.json (HilltopAds), и новые хосты показа: Adsterra Native
    // (profitableratecpmnetwork.com), ролик MyBid (xml.galaxypush.com, adskeeper.com - Cloudflare, по имени), Kadam (viipqnqi.com)
    "quizzical-topic.com",
    "profitableratecpmnetwork.com", "galaxypush.com", "adskeeper.com", "viipqnqi.com",
    // 30.09 17:40: EVADAV Native - скрипт curoax.com, реклама blolma.com
    "curoax.com", "blolma.com",
    "sad.adsgram.ai", "api.adsgram.ai", "tma.adsgram.ai", "image.adsgram.ai", "images.adsgram.ai", "adsgram.me",
    "libtl.com", "onclckvd.com", "onclckstr.com", "onclckmetrics.com", "richinfo.co", "adx1.com", "4armn.com",
    "convers.link", "7ool.net", "adp3.net", "munqu.com", "cdn.giga.pub", "mndx1.com", "mvdomnd.com", "pebblepilot.com",
    "onclckmn.com", "onclcktg.com", "onclckpp.com", "onclckpop.com", "onclckinp.com", "onclmng.com", "yomeno.xyz",
    "canstrm.com", "capndr.com", "korlumo.com", "w.tads.me", "api.tads.me", "backend.tads.me", "a-ads.com",
    "highrevenueformat.com", "realizationnewestfangs.com", "zog.link", "tubecup.net", "ntvpwpush.com", "physicaldad.com", "untimely-hello.com", "decisive-wait.com", "softsign.pro",
    "silent-basis.pro", "overdue-share.pro", "phoroglopsu.com", "onclckbnr.com", "onclckbn.net", "drimquop.com",
    "metricswpsh.com", "adspector.io", "gstcpx.site", "afrdtech.com", "ad-score.com", "bartcons.com",
    "netdeliveryservice.com", "mcpuwpsh.com", "favorit.work", "hdbkome.com", "hdacode.com", "uuidksinc.net",
];

/// 28.09 (владелец, tasks/00000c): конфиг маршрутизатора перед AmneziaWG. Российское (.ru/.su/.рф, geosite category-ru и
/// банков/госуслуг/магазинов, geoip:ru, платёжки и антифрод вне .ru) - напрямую с IP человека, остальное - в wireproxy (AWG).
/// Без DNS-запросов в обход туннеля: domainStrategy AsIs (домены - по geosite, адреса - по geoip). insellers.su - всегда в
/// туннель (иначе проверка связи через наш /probe прошла бы мимо мёртвого AWG).
fn router_config(dir: &PathBuf) -> Value {
    let geo = dir.join("geoip.dat").exists() && dir.join("geosite.dat").exists();
    let mut ru: Vec<String> = ["domain:ru", "domain:su", "domain:xn--p1ai", "domain:sberbank.com", "domain:tbank-online.com",
        "domain:payture.com", "domain:robokassa.com", "domain:rbk.money", "domain:qiwi.com", "domain:online-metrix.net",
        "domain:threatmetrix.com", "domain:cardinalcommerce.com", "domain:fpjs.io", "domain:group-ib.com",
        "domain:vkuser.net", "domain:userapi.com", "domain:mycdn.me", "domain:vk-cdn.net"].iter().map(|x| x.to_string()).collect();
    if geo {
        for g in ["geosite:category-ru", "geosite:category-gov-ru", "geosite:category-bank-ru", "geosite:category-ecommerce-ru"] { ru.push(g.into()); }
    }
    // 30.09 17:40 (владелец: «реклама нигде не через туннель»): к вшитому AD_DIRECT - список сервера (ad-hosts.json, /api/app/ad-hosts):
    // новые хосты показа без сборки; tunnel - хосты рекламы на Hetzner (напрямую из РФ не открываются) - выше «напрямую»
    let srv: Value = std::fs::read(dir.join("ad-hosts.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or(Value::Null);
    let names = |k: &str| -> Vec<String> { srv[k].as_array().map(|a| a.iter().filter_map(|x| x.as_str())
        .filter(|d| !d.is_empty() && d.len() < 100 && d.chars().all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .map(|d| d.to_string()).collect()).unwrap_or_default() };
    let mut ads: Vec<String> = AD_DIRECT.iter().map(|d| format!("domain:{d}")).collect();
    for d in names("direct") { let x = format!("domain:{d}"); if !ads.contains(&x) { ads.push(x); } }
    let tun: Vec<String> = names("tunnel").iter().map(|d| format!("domain:{d}")).collect();
    let mut rules = vec![
        json!({"type": "field", "ip": ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"], "outboundTag": "direct"}),
        json!({"type": "field", "domain": ["domain:insellers.su"], "outboundTag": "awg"}),
    ];
    if !tun.is_empty() { rules.push(json!({"type": "field", "domain": tun, "outboundTag": "awg"})); }
    rules.extend([
        json!({"type": "field", "domain": ads, "outboundTag": "direct"}),
        json!({"type": "field", "domain": ru, "outboundTag": "direct"}),
    ]);
    if geo { rules.push(json!({"type": "field", "ip": ["geoip:ru"], "outboundTag": "direct"})); }
    let sniff = json!({"enabled": true, "destOverride": ["http", "tls"], "routeOnly": true});
    json!({
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": "socks", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks", "settings": {"udp": true}, "sniffing": sniff},
            {"tag": "http", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http", "sniffing": sniff},
            {"tag": "page-in", "listen": "127.0.0.1", "port": PAGE_PORT, "protocol": "http", "sniffing": sniff}
        ],
        "outbounds": [
            {"tag": "awg", "protocol": "socks", "settings": {"servers": [{"address": "127.0.0.1", "port": AWG_INNER_PORT}]}},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}
        ],
        "routing": {"domainStrategy": "AsIs", "rules": rules}
    })
}

/// 30.09 17:40: список рекламы с сервера в ad-hosts.json (не пришёл за 4 с - остаётся прошлый / только вшитый AD_DIRECT).
async fn fetch_ad_hosts(client: &reqwest::Client, dir: &PathBuf) {
    let r = client.get(format!("{}/api/app/ad-hosts", crate::BASE)).timeout(Duration::from_secs(4)).send().await;
    if let Ok(r) = r {
        if r.status().is_success() {
            if let Ok(v) = r.json::<Value>().await {
                if v["direct"].is_array() { let _ = std::fs::write(dir.join("ad-hosts.json"), serde_json::to_vec(&v).unwrap_or_default()); }
            }
        }
    }
}

/// Запустить маршрутизатор (свой слот, не трогает основной процесс wireproxy).
fn launch_router(app: &AppHandle, dir: &PathBuf) -> Result<(), String> {
    let p = dir.join("router.json");
    std::fs::write(&p, serde_json::to_vec(&router_config(dir)).unwrap()).map_err(|e| e.to_string())?;
    let (mut rx, child) = app.shell().sidecar("xray").map_err(|e| e.to_string())?
        .env("XRAY_LOCATION_ASSET", dir.to_string_lossy().to_string())
        .args(["run", "-c", &p.to_string_lossy()])
        .spawn().map_err(|e| format!("маршрутизатор: {e}"))?;
    let pid = child.pid();
    app.state::<VpnState>().router.lock().unwrap().replace(child);
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CommandEvent::Terminated(t) = ev {
                crate::remote_log("vpn.router_exit", json!({"pid": pid, "code": t.code}));
                break;
            }
        }
    });
    Ok(())
}

/// Открывается ли внешний сайт ЧЕРЕЗ наш локальный вход (путь реально пропускает трафик). До ~9 с.
async fn link_ok() -> bool { link_ok_within(9).await }
async fn link_ok_within(secs: u64) -> bool {
    let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{HTTP_PORT}"))
        .and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(4)).build()) { Ok(c) => c, Err(_) => return false };
    let t0 = std::time::Instant::now();
    tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_millis(700))).await.ok();
    while t0.elapsed() < Duration::from_secs(secs) {
        for u in ["http://cp.cloudflare.com/generate_204", "http://connectivitycheck.gstatic.com/generate_204", "https://vpn.insellers.su/probe/204"] {
            let remaining = Duration::from_secs(secs).saturating_sub(t0.elapsed());
            if remaining.is_zero() { return false; }
            if let Ok(r) = client.get(u).timeout(remaining.min(Duration::from_secs(4))).send().await {
                let s = r.status().as_u16();
                if s == 204 || s == 200 { return true; }
            }
        }
        let wait = Duration::from_millis(800).min(Duration::from_secs(secs).saturating_sub(t0.elapsed()));
        if wait.is_zero() { break; }
        tauri::async_runtime::spawn_blocking(move || std::thread::sleep(wait)).await.ok();
    }
    false
}
/// Есть ли интернет вообще, без VPN (чтобы не менять путь, когда пропала сама сеть).
async fn direct_ok() -> bool {
    if crate::tun::active() {
        return tauri::async_runtime::spawn_blocking(crate::tun::net_ok_stored).await.unwrap_or(false);
    }
    let client = match reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build() { Ok(c) => c, Err(_) => return false };
    for u in ["http://connectivitycheck.gstatic.com/generate_204", "http://ya.ru/"] {
        if let Ok(r) = client.get(u).send().await { if r.status().as_u16() < 500 { return true; } }
    }
    false
}

fn http() -> Result<reqwest::Client, String> {
    let mut h = reqwest::header::HeaderMap::new();
    let os = if cfg!(target_os = "macos") { "macOS" } else if cfg!(target_os = "windows") { "Windows" } else { "Linux" };
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("ins-{}", crate::install_id())) { h.insert("x-hwid", v); }
    if let Ok(v) = reqwest::header::HeaderValue::from_str(os) { h.insert("x-device-os", v); }
    if let Ok(v) = reqwest::header::HeaderValue::from_str(&crate::host_model()) { h.insert("x-device-model", v); }
    reqwest::Client::builder()
        .default_headers(h)
        .timeout(Duration::from_secs(20))
        .user_agent(format!("InsellersVPN/desktop-{}", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| e.to_string())
}

fn data_dir(app: &AppHandle) -> Result<PathBuf, String> {
    let d = app.path().app_data_dir().map_err(|e| e.to_string())?;
    std::fs::create_dir_all(&d).map_err(|e| e.to_string())?;
    Ok(d)
}

static GEO_UPDATING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn usable_geo(p: &std::path::Path) -> bool {
    std::fs::metadata(p).map(|m| m.is_file() && m.len() > 1024).unwrap_or(false)
}
async fn refresh_geo(dir: PathBuf) {
    struct Done;
    impl Drop for Done { fn drop(&mut self) { GEO_UPDATING.store(false, std::sync::atomic::Ordering::SeqCst); } }
    let _done = Done;
    let client = match http() { Ok(c) => c, Err(_) => return };
    for f in ["geoip.dat", "geosite.dat"] {
        let p = dir.join(f);
        let fresh = std::fs::metadata(&p).ok().and_then(|m| m.modified().ok())
            .and_then(|t| t.elapsed().ok()).map(|a| a.as_secs() < 7 * 86400).unwrap_or(false);
        if usable_geo(&p) && fresh { continue; }
        if let Ok(r) = client.get(format!("{}/app/geo/{}", crate::BASE, f)).send().await {
            if r.status().is_success() {
                if let Ok(b) = r.bytes().await {
                    if b.len() > 1024 { let _ = crate::private_file::write_private_bytes(&p, &b); }
                }
            }
        }
    }
}
async fn ensure_geo(_app: &AppHandle, dir: &PathBuf) -> bool {
    let available = ["geoip.dat", "geosite.dat"].iter().all(|f| usable_geo(&dir.join(f)));
    if !GEO_UPDATING.swap(true, std::sync::atomic::Ordering::SeqCst) {
        if available { tauri::async_runtime::spawn(refresh_geo(dir.clone())); }
        else { refresh_geo(dir.clone()).await; }
    }
    ["geoip.dat", "geosite.dat"].iter().all(|f| usable_geo(&dir.join(f)))
}

/// Убираем правила с geoip:/geosite:, если гео-файлов нет — иначе Xray не стартует.
fn strip_geo_rules(cfg: &mut Value) {
    if let Some(rules) = cfg.pointer_mut("/routing/rules").and_then(|r| r.as_array_mut()) {
        rules.retain(|r| {
            let s = r.to_string();
            !(s.contains("geoip:") || s.contains("geosite:"))
        });
    }
    // 26.09: и DNS-серверы с geosite: в domains - без geosite.dat ядро с ними не стартует (сервер держит их отдельной записью)
    if let Some(servers) = cfg.pointer_mut("/dns/servers").and_then(|r| r.as_array_mut()) {
        servers.retain(|v| {
            let s = v.to_string();
            !v.is_object() || !(s.contains("geoip:") || s.contains("geosite:"))
        });
    }
}

fn local_inbounds() -> Value {
    json!([
        {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
         "settings": {"udp": true}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}},
        {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http",
         "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}},
        {"tag": "probe-in", "listen": "127.0.0.1", "port": PROBE_PORT, "protocol": "http"},
        {"tag": "page-in", "listen": "127.0.0.1", "port": PAGE_PORT, "protocol": "http"},
        // этап 7 (26.09 ночь): API ядра только с этого компьютера - переключение пути без перезапуска (xray api bo)
        {"tag": "api-in", "listen": "127.0.0.1", "port": API_PORT, "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1"}}
    ])
}

fn set_proxy(enable: bool) {
    #[cfg(target_os = "macos")]
    { if enable { mac::enable(HTTP_PORT, SOCKS_PORT); } else { mac::disable(HTTP_PORT, SOCKS_PORT); } }
    #[cfg(not(target_os = "macos"))]
    {
        let p = sysproxy::Sysproxy {
            enable,
            host: "127.0.0.1".into(),
            port: HTTP_PORT,
            bypass: "localhost;127.*;10.*;172.16.*;192.168.*;<local>".into(),
        };
        let _ = p.set_system_proxy();
        // проверка: не снялся — ещё раз (бывает, если настройки заняты другой программой)
        if !enable && proxy_left_on() { std::thread::sleep(Duration::from_millis(300)); let _ = p.set_system_proxy(); }
    }
}

pub fn notify(app: &AppHandle, state: &str, msg: &str) { notify_code(app, state, msg, ""); }

pub fn notify_code(app: &AppHandle, state: &str, msg: &str, code: &str) {
    // 30.09: сбой подключения - воронка связи мимо туннеля (если сервер её включил этому человеку), не чаще раза в 15 мин
    if state == "error" && code != "guest_expired" {
        if let Ok(d) = data_dir(app) {
            tauri::async_runtime::spawn(async move { crate::probe::after_failure(d).await; });
        }
    }
    if let Some(w) = app.get_webview_window("main") {
        let js = format!(
            "window.__INS_VPN={s};if({s}==='connected'&&!window.__INS_CONN_AT)window.__INS_CONN_AT=Date.now();if({s}==='disconnected')window.__INS_CONN_AT=0;window.dispatchEvent(new CustomEvent('ins:vpn',{{detail:{{state:{s},msg:{m},code:{c}}}}}))",
            s = serde_json::to_string(state).unwrap_or_default(),
            m = serde_json::to_string(msg).unwrap_or_default(),
            c = serde_json::to_string(code).unwrap_or_default()
        );
        let _ = w.eval(&js);
    }
}

pub fn stop(app: &AppHandle) {
    crate::telemetry::disconnect();   // 01.10: vpn.disconnect (сколько был подключён, байты, причина)
    set_wanted(app, false);   // любая остановка из приложения — не переподключаемся
    bump_gen(app);            // незаконченный запуск, сторож и гостевой таймер старого подключения больше не действуют
    crate::tun::down();       // TUN (26.09): весь трафик системы снова идёт как без VPN
    set_proxy(false);
    if let Some(st) = app.try_state::<VpnState>() {
        let child = st.child.lock().unwrap().take();
        if let Some(child) = child { let _ = child.kill(); }
    }
    kill_own_xray(None);      // и «потерянные» Xray, если были
}

static CONNECT_MSG: Mutex<String> = Mutex::new(String::new());
/// Сообщение последнего подключения (временный «Автовыбор» вместо ручного протокола) - один раз.
pub fn take_connect_msg() -> String { std::mem::take(&mut *CONNECT_MSG.lock().unwrap()) }

pub async fn start(app: AppHandle) -> Result<(), String> {
    // 26.09 (владелец): ручной протокол не пропустил трафик при подключении - второй заход на временном «Автовыборе»
    match start_once(app.clone()).await {
        Err(e) if e.starts_with("RETRY_AUTO:") => {
            let name = e.trim_start_matches("RETRY_AUTO:").to_string();
            notify(&app, "connecting", "Связь слабая - пробуем другие пути…");
            let r = start_once(app.clone()).await;
            if r.is_ok() {
                let m = format!("Выбранный протокол («{name}») сейчас не работает в Вашей сети - временно подключили через «Автовыбор»");
                *CONNECT_MSG.lock().unwrap() = m.clone();   // кнопка «Подключить» (main.rs) покажет его вместо пустого
                notify(&app, "connected", &m);
            }
            r
        }
        Err(e) if e.starts_with("RETRY_AUTO_BAD:") => {
            let name = e.trim_start_matches("RETRY_AUTO_BAD:").to_string();
            notify(&app, "connecting", "Подключаем через «Автовыбор»…");
            let r = start_once(app.clone()).await;
            if r.is_ok() {
                let m = format!("Ваш выбор («{name}») не работает в этой сети - подключили через «Автовыбор»");
                *CONNECT_MSG.lock().unwrap() = m.clone();
                notify(&app, "connected", &m);
            }
            r
        }
        r => r,
    }
}

async fn start_once(app: AppHandle) -> Result<(), String> {
    if STARTING.swap(true, std::sync::atomic::Ordering::SeqCst) { return Err("BUSY".into()); }
    let _guard = StartGuard;
    stop(&app);
    let my_gen = cur_gen(&app);   // нажали «Отключить» во время подключения — поколение сменится, всё отменяем
    // 0) закрываем чужие VPN-клиенты
    #[allow(unused_mut)]
    let (mut killed, failed) = kill_other_vpns();
    #[cfg(target_os = "macos")]
    for n in stop_other_ne_vpns() { if !killed.contains(&n) { killed.push(n); } }
    if !killed.is_empty() { notify(&app, "connecting", &format!("Отключаем другой VPN: {}…", killed.join(", "))); }
    if !failed.is_empty() {
        return Err(format!("OTHER_VPN:Не получилось закрыть {} - закройте его вручную и нажмите «Включить» ещё раз", failed.join(", ")));
    }
    if !killed.is_empty() { std::thread::sleep(Duration::from_millis(800)); }
    let token = crate::load_token();
    let guest = crate::guest_load();
    if token.is_empty() && guest.is_none() { return Err("Войдите через Telegram".into()); }
    let guest_sub0: Option<String> = guest.as_ref().map(|(u, _)| u.rsplit('/').next().unwrap_or("").to_string());
    let client = http()?;
    let dir = data_dir(&app)?;
    // 26.09: последняя рабочая конфигурация. Если наш сервер напрямую недоступен (сеть режет vpn.insellers.su или Мак
    // ещё не отошёл после закрытия другого VPN) - подключаемся по ней, а не пишем «Нет связи с сервером», пока Happ работает.
    let last = dir.join("config.last.json");
    // 1) ссылка на свою подписку (или гостевая - ограниченный режим до входа / пока подписки нет)
    notify(&app, "connecting", "Запрашиваем настройки доступа…");
    let bootstrap_started = std::time::Instant::now();
    let (subscription, requested_choice) = if !token.is_empty() {
        let choice_client = client.clone(); let choice_token = token.clone();
        let choice_job = tauri::async_runtime::spawn(async move { transport_choice(&choice_client, &choice_token).await });
        let sub = sub_url(&client, &token).await;
        (sub, choice_job.await.unwrap_or_default())
    } else { (Err("guest".to_string()), String::new()) };
    let (url, until) = if !token.is_empty() {
        match subscription {
            Ok(u) => (u, 0u64),
            Err(e) => match guest {
                Some(g) => g,
                None => {
                    if (e == "Нет связи с сервером" || e == "Сервер ответил неверно") && fresh_last(&last) { (String::new(), 0u64) } else { return Err(e) }
                }
            },
        }
    } else {
        guest.ok_or("Гостевой доступ закончился - войдите через Telegram")?
    };
    crate::remote_log("vpn.bootstrap", json!({"ms":bootstrap_started.elapsed().as_millis() as u64,"stage":"metadata"}));
    let offline = url.is_empty();   // сервер недоступен - едем по сохранённой конфигурации
    if offline {
        notify(&app, "connecting", "Подключаемся…");   // 29.09: не пугаем - после подключения свежие настройки подтянутся через туннель
        crate::remote_log("vpn.cached_config", json!({}));
    }
    let choice = if token.is_empty() || offline { String::new() } else { requested_choice };
    // 26.09 (владелец): ручной протокол не пропускал трафик - ВРЕМЕННО «Автовыбор» (сервер по ?auto=1 отдаёт все пути),
    // выбор человека не трогаем; через 15 мин снова пробуем его (проверка пути ниже переподключит)
    let temp_auto = manual_choice(&choice) && crate::now_ms() < TEMP_AUTO_UNTIL.load(std::sync::atomic::Ordering::SeqCst);
    let (choice, url) = if temp_auto && !url.is_empty() {
        (String::new(), format!("{}{}auto=1", url, if url.contains('?') { "&" } else { "?" }))
    } else { (choice, url) };
    // Протокол выбирают на уровне аккаунта: «AmneziaWG» с телефона приходит и сюда. Не получили ключ AWG (нет доступа,
    // лимит, сервер AWG недоступен) - подключаемся через Xray как при «Автовыборе», а не отказываем (26.09: раньше Мак
    // переставал подключаться из-за выбора на телефоне)
    // гость без входа (ограниченный режим) - тоже сначала AmneziaWG (27.09)
    let guest_sub = if token.is_empty() { guest_sub0.clone() } else { None };
    let awg_path = if (choice == "amneziawg" || guest_sub.is_some()) && !awg_off(&dir) && (!token.is_empty() || guest_sub.is_some()) {
        let got = if token.is_empty() { awg_conf_guest(&client, guest_sub.as_deref().unwrap_or("")).await } else { awg_conf(&client, &token).await };
        match got {
            Ok(conf) => {
                let p = dir.join("awg.conf");
                std::fs::write(&p, &conf).map_err(|e| e.to_string())?;
                // 28.09 (00000c): с маршрутизатором wireproxy слушает только внутренний SOCKS, вход 38808/38809 - у маршрутизатора
                let _ = std::fs::write(dir.join("awg-inner.conf"), awg_inner(&conf));
                Some(p)
            }
            Err(e) => {
                // нет доступа (402) / лимит устройств (409) - не отказ AWG: центр диагностики не должен штрафовать путь
                let ev = if e.starts_with("Нет активной") || e.starts_with("Достигнут лимит") { "vpn.awg_unavailable" } else { "vpn.awg_fallback" };
                crate::remote_log(ev, json!({"err": e})); None
            }
        }
    } else { None };
    // 26.09 (владелец: «приложение врёт»): «Подключено» - только когда через туннель реально открылся внешний сайт.
    // Путь не пропускает трафик - сами пробуем следующий (порядок путей от сервера = выбор центра диагностики для
    // провайдера), системный прокси ставим только на проверенный путь. Не прошёл ни один - честная ошибка.
    let mut is_awg = false;
    if let Some(path) = awg_path {
        notify(&app, "connecting", "Подключаемся через AmneziaWG…");
        let inner = dir.join("awg-inner.conf");
        let mut routed = false;
        if AWG_ROUTER && inner.exists() {
            let _ = ensure_geo(&app, &dir).await;      // geosite/geoip для российского мимо туннеля (без них - только по зонам)
            fetch_ad_hosts(&client, &dir).await;       // 30.09: хосты показа рекламы - напрямую / Hetzner - туннель (список сервера)
            launch(&app, "wireproxy", vec!["-c".into(), inner.to_string_lossy().to_string()], &dir)?;
            match launch_router(&app, &dir) {
                Ok(()) => routed = true,
                Err(e) => { crate::remote_log("vpn.router_fail", json!({"err": e})); kill_child(&app); }
            }
        }
        if !routed {
            launch(&app, "wireproxy", vec!["-c".into(), path.to_string_lossy().to_string()], &dir)?;
        }
        crate::remote_log("vpn.awg_router", json!({"on": routed}));
        if cur_gen(&app) != my_gen { kill_child(&app); return Err("CANCELLED".into()); }
        // 29.09 (владелец): на слабой сети рукопожатие AWG съедало треть из 9 с - AWG даём 15 с
        if link_ok_within(15).await { is_awg = true; set_cur_path("awg"); }
        else {
            kill_child(&app);
            set_awg_off(&dir);
            crate::remote_log("vpn.awg_fallback", json!({"err": "no traffic at start"}));
            notify(&app, "connecting", "Связь слабая - пробуем другие пути…");
        }
        if cur_gen(&app) != my_gen { kill_child(&app); return Err("CANCELLED".into()); }
    }
    if !is_awg {
        let cands = xray_candidates(&app, &client, &url, offline, &choice, &dir, &last).await?;
        let path = dir.join("config.json");
        let total = cands.len();
        let mut ok_cfg: Option<Vec<u8>> = None;
        let mut soft: Option<(usize, String, String, Vec<u8>)> = None;   // прошёл 204, но не загрузку
        let n_cands = cands.len();
        for (i, (tag, cfg)) in cands.into_iter().enumerate() {
            if cur_gen(&app) != my_gen { kill_child(&app); return Err("CANCELLED".into()); }
            if i > 0 { notify(&app, "connecting", &format!("Путь не отвечает - пробуем другой ({}/{})…", i + 1, total)); }
            let bytes = serde_json::to_vec(&cfg).unwrap();
            std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
            launch(&app, "xray", vec!["run".into(), "-c".into(), path.to_string_lossy().to_string()], &dir)?;
            if cur_gen(&app) != my_gen { kill_child(&app); return Err("CANCELLED".into()); }
            let desc = path_desc(&cfg);
            if link_ok().await {
                // 26.09 этап 2: 204 проходит и по «замороженному» оператором пути (ТСПУ режет TCP после ~16-25 КБ) -
                // проверяем ещё реальной загрузкой 32 КБ через этот путь
                let (rok, rb, rms, why) = probe_real("32k").await;
                if rok || why == "core" || why.starts_with("http ") {
                    crate::remote_log("vpn.path_ok", json!({"path": tag, "desc": desc, "try": i + 1, "kbps": kbps(rb, rms), "how": "real32k"}));
                    set_cur_path(&tag); set_cur_desc(&desc);
                    ok_cfg = Some(bytes);
                    break;
                }
                crate::remote_log("vpn.path_dead", json!({"path": tag, "desc": desc, "try": i + 1, "reason": why, "kb": rb / 1024, "ms": rms, "stage": "start"}));
                if soft.is_none() { soft = Some((i, tag.clone(), desc.clone(), bytes.clone())); }
            } else {
                crate::remote_log("vpn.path_dead", json!({"path": tag, "desc": desc, "try": i + 1, "reason": "no204", "stage": "start"}));
            }
            mark_bad(&tag);
            kill_child(&app);
        }
        // загрузку не прошёл ни один путь, а 204 прошёл - скорее сбой нашего сервера проверки, чем всех путей: подключаемся
        // по первому такому (как до 26.09), не оставляем человека без связи
        if ok_cfg.is_none() {
            if let Some((i, tag, desc, bytes)) = soft {
                if cur_gen(&app) != my_gen { return Err("CANCELLED".into()); }
                std::fs::write(&path, &bytes).map_err(|e| e.to_string())?;
                launch(&app, "xray", vec!["run".into(), "-c".into(), path.to_string_lossy().to_string()], &dir)?;
                if link_ok().await {
                    crate::remote_log("vpn.path_ok", json!({"path": tag, "desc": desc, "try": i + 1, "how": "204only", "of": n_cands}));
                    set_cur_path(&tag); set_cur_desc(&desc);
                    ok_cfg = Some(bytes);
                } else { kill_child(&app); }
            }
        }
        match ok_cfg {
            Some(b) => { if !token.is_empty() { let _ = std::fs::write(&last, &b); } }   // запасная копия - только проверенная
            // 26.09 (владелец): ручной протокол не пропускает - временно «Автовыбор» (15 мин), выбор человека не трогаем
            None if manual_choice(&choice) && !url.is_empty() => {
                TEMP_AUTO_UNTIL.store(crate::now_ms() + 15 * 60 * 1000, std::sync::atomic::Ordering::SeqCst);
                crate::remote_log("vpn.manual_fallback", json!({"manual": manual_name(&choice), "at": "connect"}));
                return Err(format!("RETRY_AUTO:{}", manual_name(&choice)));
            }
            None if manual_choice(&choice) => return Err("Связь слабая - включите «Автовыбор» в настройках: он подберёт другой путь".into()),
            None => return Err("Связь не установилась - проверьте интернет и нажмите «Включить» ещё раз".into()),
        }
    }
    if cur_gen(&app) != my_gen { kill_child(&app); return Err("CANCELLED".into()); }

    // 4) путь проверен. 26.09 (владелец): весь трафик системы - через TUN (ssh, терминал, любые программы), как у Happ.
    // Помощника нет - ставим (один раз, пароль администратора / UAC); отказ или сбой - системный прокси, как раньше.
    let mut tun_on = false;
    if crate::tun::supported() && !crate::pref("tun_off") {
        let cfg_text = if is_awg { std::fs::read_to_string(dir.join("awg.conf")).unwrap_or_default() }
                       else { std::fs::read_to_string(dir.join("config.json")).unwrap_or_default() };
        let bypass = crate::tun::bypass_ips(&cfg_text);
        let dns = if is_awg { "tcp" } else { "udp" };
        let d2 = dir.clone();
        let r = tauri::async_runtime::spawn_blocking(move || {
            crate::tun::install(&d2)?;
            crate::tun::up(SOCKS_PORT, &bypass, dns)
        }).await.unwrap_or_else(|e| Err(e.to_string()));
        if cur_gen(&app) != my_gen { crate::tun::down(); kill_child(&app); return Err("CANCELLED".into()); }
        match r {
            Ok(()) => {
                // TUN встал - проверяем, что через него реально идёт трафик (запрос без прокси = через TUN). 26.09: на Mac
                // сразу после включения помощник меняет DNS служб и перезапускает mDNSResponder - первая попытка падала
                // (1.0.113 у владельца). Три попытки за ~15 с; причина провала - в журнал.
                let mut ok = false;
                let mut why = String::new();
                if let Ok(c) = reqwest::Client::builder().no_proxy().timeout(Duration::from_secs(5)).build() {
                    for i in 0..3u64 {
                        tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_millis(1000 + 1500 * i))).await.ok();
                        match c.get("http://cp.cloudflare.com/generate_204").send().await {
                            Ok(r) if r.status().as_u16() == 204 => { ok = true; break; }
                            Ok(r) => why = format!("ответ {}", r.status().as_u16()),
                            Err(e) => why = format!("{}{}", if e.is_timeout() { "таймаут: " } else if e.is_connect() { "соединение: " } else { "" }, e),
                        }
                    }
                }
                if ok { tun_on = true; crate::remote_log("vpn.tun_on", json!({"dns": dns})); }
                else {
                    let st = tauri::async_runtime::spawn_blocking(crate::tun::status).await.unwrap_or_default();
                    crate::tun::down();
                    crate::remote_log("vpn.tun_fallback", json!({"reason": "нет трафика через TUN", "err": why, "helper": st}));
                }
            }
            Err(e) => crate::remote_log("vpn.tun_fallback", json!({"reason": e})),
        }
    }
    if !tun_on {
        set_proxy(true);
        if !proxy_is_ours() { std::thread::sleep(Duration::from_millis(300)); set_proxy(true); }
        if !proxy_is_ours() {
            crate::remote_log("vpn.proxy_not_applied", json!({}));
            if !proxy_left_on() { kill_child(&app); return Err("Не удалось включить VPN для этой сети. Переподключите Wi-Fi или перезапустите приложение".into()); }
        }
    }
    set_wanted(&app, true);
    UP_AT.store(crate::now_ms(), std::sync::atomic::Ordering::SeqCst);
    arm_guest_timer(&app, until);
    let watch_gen = cur_gen(&app);

    // 5) сторож: каждые 5 с закрываем чужие VPN (процессы и туннели системных расширений на Mac),
    // и если кто-то перехватил системный прокси — возвращаем свой
    let w = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut told: Vec<String> = Vec::new();
        // 26.09 ночь: сон/пробуждение и смена сети - в журнал (утром проверяем, как VPN поднимается после них).
        // Сон = часы ушли вперёд больше чем на 30 с между 5-секундными шагами; сеть = сменился шлюз по умолчанию (раз в 30 с).
        let mut last_tick = crate::now_ms();
        let mut last_gw = String::new();
        let mut tick = 0u32;
        loop {
            tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(5))).await.ok();
            let now = crate::now_ms();
            if now.saturating_sub(last_tick) > 30_000 {
                crate::remote_log("sys.wake", json!({"gap_s": now.saturating_sub(last_tick) / 1000, "tun": crate::tun::active()}));
                wake_recover(&w, watch_gen, "wake");          // 29.09: после сна - сразу проверка через туннель
            }
            last_tick = now;
            tick += 1;
            if tick % 6 == 1 {
                let gw = tauri::async_runtime::spawn_blocking(default_gateway).await.unwrap_or_default();
                if !last_gw.is_empty() && gw != last_gw {
                    crate::remote_log("sys.net", json!({"gw_changed": true, "has_gw": !gw.is_empty(), "tun": crate::tun::active()}));
                    if !gw.is_empty() { wake_recover(&w, watch_gen, "net"); }   // 29.09: сменилась сеть - проверка через туннель
                }
                if !gw.is_empty() || !last_gw.is_empty() { last_gw = gw; }
            }
            let is_running = |w: &AppHandle| w.try_state::<VpnState>().map(|s| s.child.lock().unwrap().is_some()).unwrap_or(false);
            let mut running = is_running(&w);
            if !running {   // горячая замена ядра (этап 3) - child пуст на миг: перепроверяем через 2 с
                tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(2))).await.ok();
                running = is_running(&w);
            }
            if !running || cur_gen(&w) != watch_gen { break; }   // отключились или это уже другое подключение
            let closed = tauri::async_runtime::spawn_blocking(enforce_exclusive).await.unwrap_or_default();
            if cur_gen(&w) != watch_gen || !wanted(&w) { break; }
            let fresh: Vec<String> = closed.into_iter().filter(|n| !told.contains(n)).collect();
            if !fresh.is_empty() {
                told.extend(fresh.iter().cloned());
                notify(&w, "connected", &format!("Закрыли {} - два VPN одновременно мешают друг другу", fresh.join(", ")));
            }
            if crate::tun::active() {
                // «пульс» (помощник снимает TUN, если приложение молчит 60 с); TUN пропал (помощник снял) - переподключаемся
                if !tauri::async_runtime::spawn_blocking(crate::tun::ping).await.unwrap_or(true) && wanted(&w) && cur_gen(&w) == watch_gen {
                    crate::remote_log("vpn.tun_lost", json!({}));
                    let b = w.clone();
                    std::thread::spawn(move || { let _ = tauri::async_runtime::block_on(start(b)); });
                    break;
                }
            } else if !proxy_is_ours() {
                let (k, _) = kill_other_vpns();
                if cur_gen(&w) != watch_gen || !wanted(&w) { break; }   // пока проверяли — нажали «Отключить»
                set_proxy(true);
                if !k.is_empty() {
                    notify(&w, "connected", &format!("{} пытался перехватить подключение - защита восстановлена", k.join(", ")));
                }
            }
        }
    });

    // 5б) замеры связи для центра диагностики (26.09): через 2 мин и раз в час, мимо туннеля, пока живо это подключение
    let pr = app.clone();
    tauri::async_runtime::spawn(async move {
        crate::tokio_sleep(120).await;
        loop {
            if cur_gen(&pr) != watch_gen || !wanted(&pr) { break; }
            if let Ok(d) = data_dir(&pr) {
                if crate::probe::due(&d) {
                    crate::probe::run_once(crate::load_token(), d.clone()).await;
                }
                // 26.09 ночь: замер вариантов конфигурации для диагностической машины (раз в час, ~0.5 МБ)
                if crate::probe::variants_due(&d) {
                    crate::probe::run_variants(&pr, &d, crate::load_token()).await;
                }
            }
            crate::tokio_sleep(300).await;
        }
    });

    // 6а) 27.09 (п.5): быстрый сторож заморозки - счётчики ядра раз в секунду, мгновенное переключение пути
    {
        let (fa, fd) = (app.clone(), dir.clone());
        tauri::async_runtime::spawn(async move { freeze_watch(fa, fd, watch_gen).await; });
    }
    *HOT_CUR.lock().unwrap() = String::new();
    HOT_BAD.lock().unwrap().clear();

    // 6) честный статус и проверка пути (26.09 этап 2). Раз в 30 с - дешёвый 204 через туннель (признак); раз в 150 с и
    // сразу при отказе 204 - РЕАЛЬНАЯ загрузка 256 КБ с нашего сервера через путь (204 проходит и по «замороженному»
    // оператором пути). Два отказа загрузки подряд при работающем интернете без VPN = путь мёртв: при «Автовыборе» -
    // отметка на 30 мин и за 10-20 с переход на следующий (свежая конфигурация, порядок центра диагностики); при ручном
    // выборе протокола - только сообщение человеку. Интернета нет вообще - только статус.
    let h = app.clone();
    let h_choice = choice.clone();
    let h_temp_auto = temp_auto;
    // 28.09 (владелец): тихий возврат на AmneziaWG - человек выбрал AWG, а мы на Xray из-за паузы после сбоя AWG (awg_off, 30 мин);
    // пауза кончилась - переподключаемся (снова попробуем AWG; не пойдёт - опять Xray на 30 мин)
    let h_awg_paused = !is_awg && choice == "amneziawg" && awg_off(&dir);
    let (h_url, h_dir, h_last) = (if offline { String::new() } else { url.clone() }, dir.clone(), last.clone());
    // 29.09: подключились по сохранённой конфигурации - как только путь рабочий, забираем подписку ЧЕРЕЗ туннель и переподключаемся
    // один раз на свежие настройки (раньше Мак мог днями ехать на старых)
    let mut h_refresh = offline && !token.is_empty();
    let h_token = token.clone();
    tauri::async_runtime::spawn(async move {
        let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{HTTP_PORT}"))
            .and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(7)).build()) {
            Ok(c) => c, Err(_) => return,
        };
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(8))).await.ok();
        let mut fails = 0u32;
        let mut degraded = false;
        let mut n = 0u32;
        let mut last_ok_log = 0u64;
        let mut manual_warned = 0u64;
        loop {
            if cur_gen(&h) != watch_gen || !wanted(&h) { break; }
            let mut ok = false;
            for u in ["http://cp.cloudflare.com/generate_204", "http://connectivitycheck.gstatic.com/generate_204", "https://vpn.insellers.su/probe/204"] {
                if let Ok(r) = client.get(u).send().await {
                    let s = r.status().as_u16();
                    if s == 204 || s == 200 { ok = true; break; }
                }
            }
            if cur_gen(&h) != watch_gen || !wanted(&h) { break; }
            // 29.09: ограниченный режим / гость - 204 и наш сервер закрыты намеренно; Telegram отвечает - связь в порядке, дальше не проверяем
            if !ok && telegram_ok(&client).await {
                if degraded { degraded = false; notify(&h, "connected", ""); }
                fails = 0; mark(&h, 1);
                tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(30))).await.ok();
                continue;
            }
            n += 1;
            // реальная загрузка (не для AmneziaWG: у wireproxy нет входа проверки)
            let mut path_ok = ok;
            let mut dead_why = String::from("no204");
            let (mut got, mut took) = (0u64, 0u64);
            if !is_awg && (!ok || n % 5 == 0) {
                let (mut rok, mut rb, mut rms, mut why) = probe_real("256k").await;
                if !rok && why != "core" && !why.starts_with("http ") {
                    tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_millis(1500))).await.ok();
                    (rok, rb, rms, why) = probe_real("256k").await;
                }
                if cur_gen(&h) != watch_gen || !wanted(&h) { break; }
                got = rb; took = rms;
                if why == "core" || why.starts_with("http ") { path_ok = ok; }   // вход проверки/наш сервер - не путь
                else { path_ok = rok; dead_why = why; }
                if rok && crate::now_ms().saturating_sub(last_ok_log) > 15 * 60 * 1000 {
                    last_ok_log = crate::now_ms();
                    crate::remote_log("vpn.path_ok", json!({"path": cur_path(), "desc": cur_desc(), "kbps": kbps(rb, rms), "ms": rms, "how": "real256k"}));
                }
            }
            mark(&h, if path_ok { 1 } else { 0 });
            if h_refresh && path_ok && crate::now_ms().saturating_sub(LAST_REFRESH.load(std::sync::atomic::Ordering::SeqCst)) > 30 * 60 * 1000 {
                h_refresh = false;
                LAST_REFRESH.store(crate::now_ms(), std::sync::atomic::Ordering::SeqCst);
                let mut hd = reqwest::header::HeaderMap::new();
                if let Ok(v) = reqwest::header::HeaderValue::from_str(&format!("ins-{}", crate::install_id())) { hd.insert("x-hwid", v); }
                let via = reqwest::Proxy::all(format!("http://127.0.0.1:{HTTP_PORT}"))
                    .and_then(|p| reqwest::Client::builder().proxy(p).default_headers(hd).timeout(Duration::from_secs(15)).build());
                let mut body: Option<String> = None;
                if let Ok(pc) = via {
                    if let Ok(u) = sub_url(&pc, &h_token).await {
                        if let Ok(r) = pc.get(&u).header("User-Agent", format!("InsellersVPN/desktop-{}", env!("CARGO_PKG_VERSION"))).send().await {
                            if r.status().is_success() { body = r.text().await.ok().filter(|t| t.trim_start().starts_with(['[', '{'])); }
                        }
                    }
                }
                if let Some(t) = body {
                    let _ = std::fs::write(h_dir.join("sub.fresh.json"), t);
                    if cur_gen(&h) == watch_gen && wanted(&h) {
                        crate::remote_log("vpn.config_refresh", json!({"via": "tunnel"}));
                        let b = h.clone();
                        std::thread::spawn(move || { let _ = tauri::async_runtime::block_on(start(b)); });
                        break;
                    }
                }
            }
            if h_awg_paused && path_ok && !awg_off(&h_dir) {
                crate::remote_log("vpn.awg_return", json!({}));
                let b = h.clone();
                std::thread::spawn(move || { let _ = tauri::async_runtime::block_on(start(b)); });
                break;
            }
            if path_ok {
                if degraded { degraded = false; notify(&h, "connected", "Соединение восстановлено"); }
                fails = 0;
                // временный «Автовыбор» вместо ручного протокола истёк - переподключаемся на выбор человека (не пройдёт
                // проверку - снова «Автовыбор» ещё на 15 мин)
                if h_temp_auto && crate::now_ms() >= TEMP_AUTO_UNTIL.load(std::sync::atomic::Ordering::SeqCst) {
                    crate::remote_log("vpn.manual_back", json!({}));
                    let b = h.clone();
                    std::thread::spawn(move || {
                        if !wanted(&b) { return; }
                        match tauri::async_runtime::block_on(start(b.clone())) {
                            Ok(()) => {}
                            Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                            Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                        }
                    });
                    break;
                }
                // этап 3: раз в 15 мин - не сменил ли сервер конфигурацию (центр диагностики - порядок путей для провайдера,
                // серверы). Сменил - горячая замена ядра: системный прокси и порты те же, человек не переподключается.
                if !is_awg && !h_url.is_empty() && n % 30 == 0 {
                    let fresh = match http() {
                        Ok(c) => xray_candidates(&h, &c, &h_url, false, &h_choice, &h_dir, &h_last).await.ok()
                            .and_then(|v| v.into_iter().next()),
                        Err(_) => None,
                    };
                    if let Some((tag, cfg)) = fresh {
                        let bytes = serde_json::to_vec(&cfg).unwrap_or_default();
                        let p = h_dir.join("config.json");
                        let cur = std::fs::read(&p).unwrap_or_default();
                        if !bytes.is_empty() && bytes != cur && cur_gen(&h) == watch_gen && wanted(&h) && std::fs::write(&p, &bytes).is_ok() {
                            let from = cur_desc();
                            let desc = path_desc(&cfg);
                            kill_child(&h);
                            let up = launch(&h, "xray", vec!["run".into(), "-c".into(), p.to_string_lossy().to_string()], &h_dir).is_ok();
                            if up && link_ok().await {
                                set_cur_path(&tag); set_cur_desc(&desc);
                                let _ = std::fs::write(&h_last, &bytes);
                                crate::remote_log("vpn.path_order", json!({"from": from, "to": desc}));
                            } else {
                                // новая не поднялась - полное переподключение (оно же вернёт рабочий путь)
                                let b = h.clone();
                                std::thread::spawn(move || {
                                    if !wanted(&b) { return; }
                                    match tauri::async_runtime::block_on(start(b.clone())) {
                                        Ok(()) => notify(&b, "connected", "Соединение восстановлено"),
                                        Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                                        Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                                    }
                                });
                                break;
                            }
                        }
                    }
                }
            } else {
                fails += 1;
                // AmneziaWG: ключ получен, а трафика нет 2 проверки подряд - уходим на Xray и 6 часов AWG здесь не пробуем
                // 30.09 (самопочинка Г): только если интернет без VPN есть (иначе менять путь бесполезно) и не чаще раза в 30 с;
                // в центр - vpn.path_dead how=awg_live; 3 раза за час - понятная строка человеку
                let nowg = crate::now_ms();
                if is_awg && fails >= 2 && nowg.saturating_sub(LAST_AWG_SW.load(std::sync::atomic::Ordering::SeqCst)) >= 30_000 && direct_ok().await {
                    LAST_AWG_SW.store(nowg, std::sync::atomic::Ordering::SeqCst);
                    let mut n1h = 1usize;
                    if let Ok(d) = data_dir(&h) {
                        set_awg_off(&d);
                        let hp = d.join("awg_live_hist");
                        let mut hist: Vec<u64> = std::fs::read_to_string(&hp).unwrap_or_default().split(',')
                            .filter_map(|x| x.trim().parse::<u64>().ok()).filter(|t| nowg.saturating_sub(*t) < 3_600_000).collect();
                        hist.push(nowg);
                        n1h = hist.len();
                        let _ = std::fs::write(&hp, hist.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(","));
                    }
                    crate::remote_log("vpn.awg_fallback", json!({"err": "no traffic", "fails": fails}));
                    crate::remote_log("vpn.path_dead", json!({"path": "awg", "reason": "no204", "how": "awg_live", "n1h": n1h}));
                    notify(&h, "connecting", if n1h >= 3 { "Сеть сейчас плохо пропускает VPN - работаем через запасной путь" } else { "Связь слабая - пробуем другие пути…" });
                    let b = h.clone();
                    // отдельный поток + block_on, как при переподключении после падения ядра (future start() не Send)
                    std::thread::spawn(move || {
                        if !wanted(&b) { return; }
                        match tauri::async_runtime::block_on(start(b.clone())) {
                            Ok(()) => notify(&b, "connected", "Подключено через Xray"),
                            Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                            Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                        }
                    });
                    break;
                }
                // реальная загрузка не прошла дважды (или 204 - трижды), а интернет без VPN есть: путь умер
                let real_dead = !is_awg && dead_why != "no204";
                if (real_dead || (!is_awg && fails >= 3)) && direct_ok().await {
                    let dead = cur_path();
                    let dead_desc = cur_desc();
                    crate::remote_log("vpn.path_dead", json!({"path": dead, "desc": dead_desc, "reason": dead_why, "kb": got / 1024,
                        "ms": took, "kbps": kbps(got, took), "manual": manual_choice(&h_choice)}));
                    crate::check::maybe_run("path_dead");        // 29.09: замер адресов проверки напрямую -> /api/check/result
                    if manual_choice(&h_choice) && !h_url.is_empty() {
                        // 26.09 (владелец): ручной протокол не пропускает трафик - временно «Автовыбор» на 15 мин
                        TEMP_AUTO_UNTIL.store(crate::now_ms() + 15 * 60 * 1000, std::sync::atomic::Ordering::SeqCst);
                        let name = manual_name(&h_choice);
                        crate::remote_log("vpn.manual_fallback", json!({"from": dead_desc, "manual": name}));
                        notify(&h, "connecting", "Связь слабая - пробуем другие пути…");
                        let b = h.clone();
                        std::thread::spawn(move || {
                            if !wanted(&b) { return; }
                            match tauri::async_runtime::block_on(start(b.clone())) {
                                Ok(()) => notify(&b, "connected", &format!("Выбранный протокол («{name}») сейчас не работает в Вашей сети - временно подключили через «Автовыбор»")),
                                Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                                Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                            }
                        });
                        break;
                    } else if manual_choice(&h_choice) {
                        if crate::now_ms().saturating_sub(manual_warned) > 30 * 60 * 1000 {
                            manual_warned = crate::now_ms();
                            degraded = true; mark(&h, 2);
                            notify(&h, "degraded", "Связь слабая - включите «Автовыбор» в настройках: он подберёт другой путь");
                        }
                    } else if let Some(to) = { let t0 = crate::now_ms(); let hc = HOT_CUR.lock().unwrap().clone(); hot_switch(&h, &h_dir, &hc).await.map(|t| (t, t0)) } {
                        // этап 7: без перезапуска ядра
                        crate::remote_log("vpn.hot_switch", crate::telemetry::switch_fields(json!({"from": dead_desc, "to": to.0, "gap_ms": crate::now_ms().saturating_sub(to.1)}), "handshake_fail"));
                        *HOT_CUR.lock().unwrap() = to.0;
                        fails = 0;
                        if degraded { degraded = false; }
                        notify(&h, "connected", "Соединение восстановлено");
                    } else {
                        mark_bad(&dead);
                        notify(&h, "connecting", "Связь слабая - пробуем другие пути…");
                        let b = h.clone();
                        let t_fail = crate::now_ms();
                        std::thread::spawn(move || {
                            if !wanted(&b) { return; }
                            match tauri::async_runtime::block_on(start(b.clone())) {
                                Ok(()) => {
                                    crate::remote_log("vpn.path_switch", crate::telemetry::switch_fields(json!({"from": dead, "from_desc": dead_desc, "to": cur_path(),
                                        "to_desc": cur_desc(), "secs": crate::now_ms().saturating_sub(t_fail) / 1000}), "handshake_fail"));
                                    notify(&b, "connected", "Соединение восстановлено");
                                }
                                Err(e) if e == "CANCELLED" || e == "BUSY" => {}
                                Err(e) => { if !crate::pref("killswitch") && wanted(&b) { set_proxy(false); } if wanted(&b) { notify(&b, "error", &e); } }
                            }
                        });
                        break;
                    }
                }
                if fails >= 3 && !degraded { degraded = true; mark(&h, 2); notify(&h, "degraded", "Нет ответа от сервера - восстанавливаем соединение"); }
                // 29.09 (владелец: Mac после сна «Подключено» без интернета): в режиме TUN «интернет без VPN» берётся у помощника
                // и после сна бывает устаревшим - путь тогда не менялся никогда. 4 отказа подряд (~20 с) - полное переподключение
                // (новое ядро и TUN), не чаще раза в 2 мин.
                let nowf = crate::now_ms();
                if fails >= 4 && nowf.saturating_sub(LAST_FORCED.load(std::sync::atomic::Ordering::SeqCst)) > 120_000 {
                    LAST_FORCED.store(nowf, std::sync::atomic::Ordering::SeqCst);
                    crate::remote_log("vpn.nonet", json!({"how": "health", "fails": fails, "path": cur_path(), "awg": is_awg}));
                    notify(&h, "connecting", "Переподключаемся…");
                    reconnect_retry(&h, nowf, "health");
                    break;
                }
            }
            // 30.09 (самопочинка Г): при AmneziaWG проверяем чаще - раз в 15 с (Xray - как было, 30 с)
            let secs = if fails > 0 { 5 } else if is_awg { 15 } else { 30 };
            tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_secs(secs))).await.ok();
        }
    });
    Ok(())
}
