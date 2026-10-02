//! TUN - весь трафик системы через VPN, как у Happ (26.09.2026, владелец). Вместо системного прокси (его обходят ssh, Termius,
//! терминал и любые программы без поддержки прокси) - помощник с правами администратора `ins-helper` (Go, desktop/helper)
//! держит TUN на sing-box: весь трафик -> SOCKS-вход нашего ядра (xray / wireproxy) на 127.0.0.1:38808, DNS перехватывается и
//! идёт в ядро (без утечки), IPv6 блокируется, IP серверов и само ядро - мимо TUN (без петли). Маршрутизация (RU-сайты напрямую,
//! реклама по фильтрам) - в ядре, как в make_insapp.
//! Права - ОДИН раз: Mac - пароль администратора (osascript), помощник ставится LaunchDaemon'ом; Windows - UAC, задача
//! планировщика при запуске от SYSTEM. Отказался или не вышло - работаем как раньше через системный прокси (vpn.tun_fallback).
//! Сеть не остаётся мёртвой: при «Отключить»/выходе - down; упало приложение (нет «пульса» 60 с) или ядро - помощник снимает сам.
//! Kill switch не включаем (владелец не решил).
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub const HELPER_VERSION: &str = "2";   // 02.10: ключ 600 + down с ключом - переустановка помощника (один запрос пароля)
const HELPER_ADDR: &str = "127.0.0.1:38811";
static ACTIVE: AtomicBool = AtomicBool::new(false);
static BYPASS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

/// Помощник поставлен (есть его папка) - наш sing-box оттуда не считаем «чужим VPN».
pub fn installed() -> bool { helper_dir().join("token").exists() }

pub fn active() -> bool { ACTIVE.load(Ordering::SeqCst) }

fn helper_dir() -> PathBuf {
    if cfg!(target_os = "windows") {
        PathBuf::from(std::env::var("ProgramFiles").unwrap_or_else(|_| "C:\\Program Files".into())).join("INSELLERS VPN Helper")
    } else {
        PathBuf::from("/Library/PrivilegedHelperTools/su.insellers.helper")
    }
}

/// Один запрос помощнику: строка JSON туда, строка JSON обратно.
fn call(req: &Value, timeout_s: u64) -> Option<Value> {
    let addr: std::net::SocketAddr = HELPER_ADDR.parse().ok()?;
    let mut s = TcpStream::connect_timeout(&addr, Duration::from_secs(2)).ok()?;
    s.set_read_timeout(Some(Duration::from_secs(timeout_s))).ok()?;
    s.set_write_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut line = req.to_string();
    line.push('\n');
    s.write_all(line.as_bytes()).ok()?;
    let mut out = String::new();
    BufReader::new(s).read_line(&mut out).ok()?;
    serde_json::from_str(&out).ok()
}

/// Помощник поставлен и нужной версии.
pub fn helper_ok() -> bool {
    call(&json!({"cmd": "version"}), 5).and_then(|v| v["version"].as_str().map(|x| x == HELPER_VERSION)).unwrap_or(false)
}

/// Поддерживается ли TUN на этой системе (Linux - пока только системный прокси).
pub fn supported() -> bool { cfg!(target_os = "macos") || cfg!(target_os = "windows") }

/// Человек отказался дать права - не спрашиваем снова 7 дней (файл tun_declined в папке данных).
fn declined(dir: &PathBuf) -> bool {
    std::fs::read_to_string(dir.join("tun_declined")).ok().and_then(|t| t.trim().parse::<u64>().ok())
        .map(|t| crate::now_ms().saturating_sub(t) < 7 * 86400 * 1000).unwrap_or(false)
}

/// Поставить помощника (один раз, с правами администратора). Ok(()) - стоит и отвечает.
pub fn install(dir: &PathBuf) -> Result<(), String> {
    if helper_ok() { return Ok(()); }
    if declined(dir) { return Err("права администратора не даны (спросим снова через 7 дней)".into()); }
    let exe_dir = std::env::current_exe().map_err(|e| e.to_string())?.parent().map(|p| p.to_path_buf()).ok_or("нет папки приложения")?;
    let hd = helper_dir();
    let res = if cfg!(target_os = "macos") { install_mac(&exe_dir, &hd, dir) } else { install_win(&exe_dir, &hd, dir) };
    if let Err(e) = res {
        if e.contains("-128") || e.to_lowercase().contains("cancel") || e.contains("отмен") {
            let _ = std::fs::write(dir.join("tun_declined"), crate::now_ms().to_string());
        }
        return Err(e);
    }
    for _ in 0..20 {
        if helper_ok() { return Ok(()); }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err("помощник не запустился".into())
}

fn install_mac(exe_dir: &PathBuf, hd: &PathBuf, dir: &PathBuf) -> Result<(), String> {
    let script = format!(
        r#"set -e
D='{hd}'
mkdir -p "$D"
cp -f '{src}/ins-helper' '{src}/sing-box' "$D/"
chown -R root:wheel "$D"; chmod 755 "$D" "$D/ins-helper" "$D/sing-box"
[ -s "$D/token" ] || /usr/bin/openssl rand -hex 16 > "$D/token"
# 02.10 (безопасность): ключ помощника читает только тот, кто сидит за компьютером (раньше 644 - любой процесс любого пользователя
# мог приказать помощнику от root поднять TUN на свой SOCKS и увести трафик). Пользователь консоли, не root из osascript.
U=$(/usr/bin/stat -f %Su /dev/console 2>/dev/null || echo root)
chown "$U" "$D/token"; chmod 600 "$D/token"
cat > /Library/LaunchDaemons/su.insellers.helper.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>su.insellers.helper</string>
<key>ProgramArguments</key><array><string>{hd}/ins-helper</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
EOF
chown root:wheel /Library/LaunchDaemons/su.insellers.helper.plist; chmod 644 /Library/LaunchDaemons/su.insellers.helper.plist
launchctl bootout system/su.insellers.helper 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/su.insellers.helper.plist
"#,
        hd = hd.display(), src = exe_dir.display());
    let sp = dir.join("install-helper.sh");
    std::fs::write(&sp, script).map_err(|e| e.to_string())?;
    let apple = format!(
        "do shell script \"/bin/sh '{}'\" with administrator privileges with prompt \"INSELLERS VPN: разрешите один раз, чтобы весь трафик компьютера шёл через VPN (как в Happ).\"",
        sp.display());
    let out = std::process::Command::new("/usr/bin/osascript").arg("-e").arg(apple).output().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&sp);
    if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).to_string()) }
}

fn install_win(exe_dir: &PathBuf, hd: &PathBuf, dir: &PathBuf) -> Result<(), String> {
    let ps = format!(
        r#"$ErrorActionPreference = 'Stop'
$D = '{hd}'
New-Item -ItemType Directory -Force -Path $D | Out-Null
Stop-ScheduledTask -TaskName 'INSELLERS VPN Helper' -ErrorAction SilentlyContinue
Get-Process ins-helper -ErrorAction SilentlyContinue | Stop-Process -Force
Copy-Item -Force '{src}\ins-helper.exe','{src}\sing-box.exe' $D
if (!(Test-Path "$D\token")) {{ [guid]::NewGuid().ToString('N') | Out-File -Encoding ascii "$D\token" }}
# 02.10 (безопасность): ключ помощника - только пользователю за компьютером и SYSTEM/Администраторам (раньше наследовал права папки:
# читал любой пользователь). Пользователь - кто вошёл в систему, а не кто ввёл пароль администратора в UAC.
$U = (Get-CimInstance Win32_ComputerSystem).UserName
if ($U) {{ icacls "$D\token" /inheritance:r /grant:r "${{U}}:R" "SYSTEM:F" "*S-1-5-32-544:F" | Out-Null }}
$a = New-ScheduledTaskAction -Execute "$D\ins-helper.exe"
$t = New-ScheduledTaskTrigger -AtStartup
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
Register-ScheduledTask -TaskName 'INSELLERS VPN Helper' -Action $a -Trigger $t -Settings $s -Principal $p -Force | Out-Null
Start-ScheduledTask -TaskName 'INSELLERS VPN Helper'
"#,
        hd = hd.display(), src = exe_dir.display());
    let sp = dir.join("install-helper.ps1");
    std::fs::write(&sp, ps).map_err(|e| e.to_string())?;
    // UAC один раз: Start-Process -Verb RunAs; отказ в окне UAC - ошибка «отменена пользователем»
    let arg = format!(
        "try {{ $p = Start-Process powershell -Verb RunAs -Wait -PassThru -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','{}'; exit $p.ExitCode }} catch {{ Write-Error 'cancel'; exit 1223 }}",
        sp.display());
    let mut cmd = std::process::Command::new("powershell");
    cmd.args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &arg]);
    #[cfg(target_os = "windows")]
    { use std::os::windows::process::CommandExt; cmd.creation_flags(0x08000000); }   // без окна консоли
    let out = cmd.output().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&sp);
    if out.status.success() { Ok(()) } else {
        let e = String::from_utf8_lossy(&out.stderr).to_string();
        Err(if out.status.code() == Some(1223) { format!("cancel {e}") } else { e })
    }
}

/// Поднять TUN на SOCKS-вход ядра. dns: "udp" (xray - DNS-модуль с фильтрами) или "tcp" (wireproxy).
pub fn up(socks: u16, bypass: &[String], dns: &str) -> Result<(), String> {
    let token = std::fs::read_to_string(helper_dir().join("token")).map_err(|_| "нет ключа помощника".to_string())?;
    let r = call(&json!({"cmd": "up", "token": token.trim(), "socks": socks, "bypass": bypass, "dns": dns}), 20)
        .ok_or("помощник не ответил")?;
    if r["ok"].as_bool().unwrap_or(false) {
        *BYPASS.lock().unwrap() = bypass.to_vec();
        ACTIVE.store(true, Ordering::SeqCst);
        Ok(())
    } else {
        Err(r["error"].as_str().unwrap_or("ошибка помощника").to_string())
    }
}

pub fn down() {
    if ACTIVE.swap(false, Ordering::SeqCst) || helper_running() {
        // 02.10 (безопасность): down тоже с ключом - чужой процесс не должен снимать TUN (трафик мимо VPN без ведома человека)
        let token = std::fs::read_to_string(helper_dir().join("token")).unwrap_or_default();
        let _ = call(&json!({"cmd": "down", "token": token.trim()}), 10);
    }
}

/// Состояние помощника для журнала (работает ли sing-box, последняя ошибка).
pub fn status() -> Value { call(&json!({"cmd": "status"}), 3).unwrap_or(Value::Null) }

fn helper_running() -> bool {
    call(&json!({"cmd": "status"}), 3).and_then(|v| v["running"].as_bool()).unwrap_or(false)
}

/// «Пульс» раз в 20 с: помощник снимает TUN сам, если приложение молчит 60 с. false - TUN уже не работает.
pub fn ping() -> bool {
    call(&json!({"cmd": "ping"}), 5).and_then(|v| v["running"].as_bool()).unwrap_or(false)
}

/// Есть ли сеть без VPN при включённом TUN: IP серверов идут мимо TUN - TCP до сервера = физическая сеть жива.
pub fn net_ok(bypass: &[String]) -> bool {
    bypass.iter().any(|ip| format!("{ip}:443").parse::<std::net::SocketAddr>().ok()
        .map(|a| TcpStream::connect_timeout(&a, Duration::from_secs(4)).is_ok()).unwrap_or(false))
}

pub fn net_ok_stored() -> bool {
    let b = BYPASS.lock().unwrap().clone();
    net_ok(&b)
}

/// IPv4 серверов из конфигурации ядра (xray: адреса выходов; wireproxy: Endpoint) - в обход TUN. Имена резолвим.
pub fn bypass_ips(cfg_text: &str) -> Vec<String> {
    use std::net::ToSocketAddrs;
    let mut hosts: Vec<String> = Vec::new();
    if let Ok(v) = serde_json::from_str::<Value>(cfg_text) {
        for o in v["outbounds"].as_array().cloned().unwrap_or_default() {
            for p in ["/settings/vnext/0/address", "/settings/servers/0/address", "/settings/address"] {
                if let Some(a) = o.pointer(p).and_then(|x| x.as_str()) { hosts.push(a.to_string()); }
            }
        }
    } else {
        for l in cfg_text.lines() {
            if let Some(e) = l.trim().strip_prefix("Endpoint") {
                let e = e.trim_start_matches([' ', '=']).trim();
                if let Some((h, _)) = e.rsplit_once(':') { hosts.push(h.to_string()); }
            }
        }
    }
    let mut out: Vec<String> = Vec::new();
    for h in hosts {
        let ips: Vec<String> = if h.parse::<std::net::Ipv4Addr>().is_ok() { vec![h.clone()] } else {
            (h.as_str(), 443).to_socket_addrs().map(|it| it.filter(|a| a.is_ipv4()).map(|a| a.ip().to_string()).collect()).unwrap_or_default()
        };
        for ip in ips { if !out.contains(&ip) { out.push(ip); } }
    }
    out
}
