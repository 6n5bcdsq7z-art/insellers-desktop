// VPN-режим на компьютере: Xray (sidecar) + системный прокси.
// Конфигурацию человека отдаёт наш сервер подписок (Xray JSON по User-Agent InsellersVPN/…),
// здесь мы только подменяем входы на локальные 127.0.0.1:10808 (SOCKS) / :10809 (HTTP).
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
        if !name.contains("xray") { continue; }
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

const SOCKS_PORT: u16 = 10808;
const HTTP_PORT: u16 = 10809;

#[derive(Default)]
pub struct VpnState {
    pub child: Mutex<Option<CommandChild>>,
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

const GUEST_END_MSG: &str = "Гостевые 5 минут закончились. Бесплатный час за рекламу, +3 дня за друга или подписка — в приложении";

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
/// AmneziaWG (25.09): ключ этого компьютера с сервера и конфиг для wireproxy-awg — он поднимает AWG и отдаёт
/// его как локальные SOCKS/HTTP-прокси на тех же портах, что Xray. Прав администратора не нужно.
async fn awg_conf(client: &reqwest::Client, token: &str) -> Result<String, String> {
    let r = client.post(format!("{}/api/app/awg/config", crate::BASE)).header("X-App-Token", token)
        .json(&json!({"hwid": format!("ins-{}", crate::install_id())})).send().await
        .map_err(|_| "Сервер AmneziaWG недоступен".to_string())?;
    match r.status().as_u16() {
        200..=299 => {}
        402 => return Err("Нет активной подписки".into()),
        409 => return Err("Достигнут лимит устройств — отключите лишнее в «Устройствах»".into()),
        _ => return Err("AmneziaWG сейчас недоступен — выберите другой протокол".into()),
    }
    let v: Value = r.json().await.map_err(|_| "AmneziaWG: неверный ответ сервера".to_string())?;
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
        for k in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"] {
            let v = match a.get(k) { Some(Value::String(x)) => x.clone(), Some(Value::Number(n)) => n.to_string(), _ => continue };
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
    let r = client.get(format!("{}/api/transport", crate::BASE)).header("X-App-Token", token).send().await;
    match r {
        Ok(r) => r.json::<Value>().await.ok().and_then(|v| v["choice"].as_str().map(|s| s.to_string())).unwrap_or_default(),
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

/// ОДИН путь, как у Happ (2026-09-24). Автовыбор leastLoad почти всегда уводил на XHTTP, а тот открывает
/// сотни соединений в минуту к одному адресу — оператор это душит, сайты «не грузятся». Теперь:
/// «Стабильный» → XHTTP, «Для Wi-Fi» → hy2, остальное → Reality; балансировщик и проверки путей убираем.
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

/// Ссылка на подписку человека по токену входа.
async fn sub_url(client: &reqwest::Client, token: &str) -> Result<String, String> {
    let sub: Value = client.get(format!("{}/api/app/sub", crate::BASE))
        .header("X-App-Token", token).send().await.map_err(|_| "Нет связи с сервером".to_string())?
        .json().await.map_err(|_| "Сервер ответил неверно".to_string())?;
    Ok(sub["sub"].as_str().ok_or("Нет активной подписки")?.to_string())
}

pub fn set_wanted(app: &AppHandle, v: bool) {
    if let Some(s) = app.try_state::<VpnState>() { s.wanted.store(v, std::sync::atomic::Ordering::SeqCst); }
}
fn wanted(app: &AppHandle) -> bool {
    app.try_state::<VpnState>().map(|s| s.wanted.load(std::sync::atomic::Ordering::SeqCst)).unwrap_or(false)
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

async fn ensure_geo(app: &AppHandle, dir: &PathBuf) -> bool {
    let client = match http() { Ok(c) => c, Err(_) => return false };
    let mut ok = true;
    for f in ["geoip.dat", "geosite.dat"] {
        let p = dir.join(f);
        let fresh = std::fs::metadata(&p).ok()
            .and_then(|m| m.modified().ok())
            .map(|t| t.elapsed().map(|e| e.as_secs() < 7 * 86400).unwrap_or(false))
            .unwrap_or(false);
        if fresh { continue; }
        let url = format!("{}/app/geo/{}", crate::BASE, f);
        match client.get(&url).send().await {
            Ok(r) if r.status().is_success() => match r.bytes().await {
                Ok(b) if b.len() > 1024 => { let _ = std::fs::write(&p, &b); }
                _ => ok = p.exists() && ok,
            },
            _ => ok = p.exists() && ok,
        }
    }
    let _ = app;
    ok
}

/// Убираем правила с geoip:/geosite:, если гео-файлов нет — иначе Xray не стартует.
fn strip_geo_rules(cfg: &mut Value) {
    if let Some(rules) = cfg.pointer_mut("/routing/rules").and_then(|r| r.as_array_mut()) {
        rules.retain(|r| {
            let s = r.to_string();
            !(s.contains("geoip:") || s.contains("geosite:"))
        });
    }
}

fn local_inbounds() -> Value {
    json!([
        {"tag": "socks-in", "listen": "127.0.0.1", "port": SOCKS_PORT, "protocol": "socks",
         "settings": {"udp": true}, "sniffing": {"enabled": true, "destOverride": ["http", "tls", "quic"]}},
        {"tag": "http-in", "listen": "127.0.0.1", "port": HTTP_PORT, "protocol": "http",
         "sniffing": {"enabled": true, "destOverride": ["http", "tls"]}}
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
    set_wanted(app, false);   // любая остановка из приложения — не переподключаемся
    bump_gen(app);            // незаконченный запуск, сторож и гостевой таймер старого подключения больше не действуют
    set_proxy(false);
    if let Some(st) = app.try_state::<VpnState>() {
        let child = st.child.lock().unwrap().take();
        if let Some(child) = child { let _ = child.kill(); }
    }
    kill_own_xray(None);      // и «потерянные» Xray, если были
}

pub async fn start(app: AppHandle) -> Result<(), String> {
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
        return Err(format!("OTHER_VPN:Не получилось закрыть {} — закройте его вручную и нажмите «Подключить» ещё раз", failed.join(", ")));
    }
    if !killed.is_empty() { std::thread::sleep(Duration::from_millis(800)); }
    let token = crate::load_token();
    let guest = crate::guest_load();
    if token.is_empty() && guest.is_none() { return Err("Войдите через Telegram".into()); }
    let client = http()?;
    // 1) ссылка на свою подписку (или гостевая на 5 минут — вошёл, а подписки ещё нет)
    let (url, until) = if !token.is_empty() {
        match sub_url(&client, &token).await {
            Ok(u) => (u, 0u64),
            Err(e) => match guest { Some(g) => g, None => return Err(e) },
        }
    } else {
        guest.ok_or("Гостевой доступ закончился — войдите через Telegram")?
    };
    let choice = if token.is_empty() { String::new() } else { transport_choice(&client, &token).await };
    let dir = data_dir(&app)?;
    let (bin, run_args): (&str, Vec<String>) = if choice == "amneziawg" && !token.is_empty() {
        let path = dir.join("awg.conf");
        std::fs::write(&path, awg_conf(&client, &token).await?).map_err(|e| e.to_string())?;
        ("wireproxy", vec!["-c".into(), path.to_string_lossy().to_string()])
    } else {
    // 2) готовая конфигурация Xray
    let txt = client.get(&url).send().await.map_err(|_| "Сервер подписок недоступен".to_string())?
        .text().await.map_err(|e| e.to_string())?;
    let raw: Value = serde_json::from_str(&txt).map_err(|_| "Сервер ещё не отдаёт конфигурацию для приложения".to_string())?;
    // hy2 (UDP) — только если человек сам выбрал «Для Wi-Fi» (у операторов РФ он «подключается», но трафик
    // не идёт). Гостю и при неизвестном выборе — без hy2.
    let mut cfg = pick_config(raw, &choice);
    tune(&mut cfg);
    cfg["inbounds"] = local_inbounds();
    cfg["log"] = json!({"loglevel": "warning"});
    if !ensure_geo(&app, &dir).await { strip_geo_rules(&mut cfg); }
    let path = dir.join("config.json");
    std::fs::write(&path, serde_json::to_vec(&cfg).unwrap()).map_err(|e| e.to_string())?;
    ("xray", vec!["run".into(), "-c".into(), path.to_string_lossy().to_string()])
    };

    // 3) запуск Xray
    if cur_gen(&app) != my_gen { return Err("CANCELLED".into()); }
    let (mut rx, child) = app.shell().sidecar(bin).map_err(|e| e.to_string())?
        .env("XRAY_LOCATION_ASSET", dir.to_string_lossy().to_string())
        .args(run_args)
        .spawn().map_err(|e| format!("Не удалось запустить ядро: {e}"))?;
    let my_pid = child.pid();
    app.state::<VpnState>().child.lock().unwrap().replace(child);

    // следим за процессом: упал — выключаем прокси и сообщаем странице
    let a = app.clone();
    tauri::async_runtime::spawn(async move {
        while let Some(ev) = rx.recv().await {
            if let CommandEvent::Terminated(_) = ev {
                // это наш процесс? Если его уже забрал stop() (человек отключил) или его сменило новое
                // подключение — ничего не делаем, иначе старый процесс гасил бы новое подключение
                let mine = {
                    let st = a.state::<VpnState>();
                    let mut g = st.child.lock().unwrap();
                    if g.as_ref().map(|c| c.pid()) == Some(my_pid) { g.take(); true } else { false }
                };
                if !mine { break; }
                if !wanted(&a) { set_proxy(false); notify(&a, "disconnected", ""); break; }
                // ядро упало само
                let ks = crate::pref("killswitch");
                if !ks { set_proxy(false); }   // Kill Switch: прокси остаётся на мёртвом порту — интернет на паузе
                if crate::pref("reconnect") {
                    let n = a.state::<VpnState>().retries.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    notify(&a, "connecting", if ks { "Соединение прервано - интернет на паузе, переподключаемся…" } else { "Соединение прервано - переподключаемся…" });
                    let b = a.clone();
                    // отдельный поток + block_on: рекурсивный start() нельзя отдать в spawn (future не Send)
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

    // 4) даём ядру подняться и включаем системный прокси — если за это время не нажали «Отключить»
    std::thread::sleep(Duration::from_millis(700));
    if cur_gen(&app) != my_gen {
        let c = app.state::<VpnState>().child.lock().unwrap().take();
        if let Some(c) = c { let _ = c.kill(); }
        set_proxy(false);
        return Err("CANCELLED".into());
    }
    set_proxy(true);
    set_wanted(&app, true);
    UP_AT.store(crate::now_ms(), std::sync::atomic::Ordering::SeqCst);
    arm_guest_timer(&app, until);
    let watch_gen = cur_gen(&app);

    // 5) сторож: каждые 5 с закрываем чужие VPN (процессы и туннели системных расширений на Mac),
    // и если кто-то перехватил системный прокси — возвращаем свой
    let w = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut told: Vec<String> = Vec::new();
        loop {
            tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(5))).await.ok();
            let running = w.try_state::<VpnState>().map(|s| s.child.lock().unwrap().is_some()).unwrap_or(false);
            if !running || cur_gen(&w) != watch_gen { break; }   // отключились или это уже другое подключение
            let closed = tauri::async_runtime::spawn_blocking(enforce_exclusive).await.unwrap_or_default();
            if cur_gen(&w) != watch_gen || !wanted(&w) { break; }
            let fresh: Vec<String> = closed.into_iter().filter(|n| !told.contains(n)).collect();
            if !fresh.is_empty() {
                told.extend(fresh.iter().cloned());
                notify(&w, "connected", &format!("Закрыли {} — два VPN одновременно мешают друг другу", fresh.join(", ")));
            }
            if !proxy_is_ours() {
                let (k, _) = kill_other_vpns();
                if cur_gen(&w) != watch_gen || !wanted(&w) { break; }   // пока проверяли — нажали «Отключить»
                set_proxy(true);
                if !k.is_empty() {
                    notify(&w, "connected", &format!("{} пытался перехватить подключение — защита восстановлена", k.join(", ")));
                }
            }
        }
    });

    // 6) честный статус: раз в 30 с проверяем, что через VPN реально открывается внешний сайт. Раньше
    // приложение писало «Защищено», даже когда трафик не шёл. Нет ответа 2 раза — «восстанавливаем»,
    // на 3-й — полный перезапуск со свежей конфигурацией с сервера.
    let h = app.clone();
    tauri::async_runtime::spawn(async move {
        let client = match reqwest::Proxy::all(format!("http://127.0.0.1:{HTTP_PORT}"))
            .and_then(|p| reqwest::Client::builder().proxy(p).timeout(Duration::from_secs(7)).build()) {
            Ok(c) => c, Err(_) => return,
        };
        tauri::async_runtime::spawn_blocking(|| std::thread::sleep(Duration::from_secs(8))).await.ok();
        let mut fails = 0u32;
        let mut degraded = false;
        loop {
            if cur_gen(&h) != watch_gen || !wanted(&h) { break; }
            let mut ok = false;
            for u in ["http://cp.cloudflare.com/generate_204", "http://connectivitycheck.gstatic.com/generate_204"] {
                if let Ok(r) = client.get(u).send().await {
                    let s = r.status().as_u16();
                    if s == 204 || s == 200 { ok = true; break; }
                }
            }
            if cur_gen(&h) != watch_gen || !wanted(&h) { break; }
            mark(&h, if ok { 1 } else { 0 });
            if ok {
                if degraded { degraded = false; notify(&h, "connected", "Соединение восстановлено"); }
                fails = 0;
            } else {
                fails += 1;
                if fails >= 3 && !degraded { degraded = true; mark(&h, 2); notify(&h, "degraded", "Нет ответа от сервера — восстанавливаем соединение"); }
                // 2026-09-24 ХОТФИКС: без автоматического перезапуска — при ложной тревоге он рвал рабочее
                // подключение (стоп → системный прокси снят). Только честный статус на экране.
            }
            let secs = if fails > 0 { 5 } else { 30 };
            tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_secs(secs))).await.ok();
        }
    });
    Ok(())
}
