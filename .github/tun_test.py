#!/usr/bin/env python3
"""Проверка механизма TUN на раннере (macOS/Windows): ядро xray с конфигурацией тестового ключа + ins-helper + sing-box.
Секрет TUN_TEST_CONFIG - клиентская конфигурация (как у приложения: socks 38808, http 38809). Печатает итог, код 1 - провал.
Что НЕ проверить на раннере: сон/пробуждение, смена Wi-Fi, реальный пароль администратора / окно UAC."""
import atexit, ipaddress, json, os, platform, socket, subprocess, sys, tempfile, threading, time

WIN = platform.system() == "Windows"
HD = r"C:\Program Files\INSELLERS VPN Helper" if WIN else "/Library/PrivilegedHelperTools/su.insellers.helper"
SERVERS = set()
results = []


def ok(name, cond, info=""):
    results.append((name, bool(cond), info))
    print(("PASS " if cond else "FAIL ") + name, flush=True)
    print(("::notice" if cond else "::error") + " title=TUN acceptance::" + name, flush=True)


def helper(req, t=25):
    with socket.create_connection(("127.0.0.1", 38811), 5) as s:
        s.settimeout(t)
        s.sendall((json.dumps(req) + "\n").encode()); d = b""
        while not d.endswith(b"\n"):
            x = s.recv(4096)
            if not x: break
            d += x
    return json.loads(d or b"{}")


def curl(url, extra=(), t=15):
    r = subprocess.run(["curl", "-fsS", "--proto", "=https", "--connect-timeout", "5", "-m", str(t)] + list(extra) + [url], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()

def valid_ip(value):
    try:
        return ipaddress.ip_address(value).is_global
    except ValueError:
        return False


def xlog():
    try:
        return open("xray-access.log", encoding="utf-8", errors="replace").read()
    except OSError:
        return ""


cfg = json.load(open("client.json"))
for o in cfg["outbounds"]:
    for p in (("settings", "vnext"), ("settings", "servers")):
        a = o.get(p[0], {}).get(p[1])
        if a and a[0].get("address"):
            h = a[0]["address"]
            try:
                SERVERS.update(i[4][0] for i in socket.getaddrinfo(h, 443, socket.AF_INET))
            except OSError:
                pass
baselines = []
for source in ("https://api.ipify.org", "https://ifconfig.me"):
    rc, base = curl(source)
    _, base6 = curl(source, ["-6"], 8)
    if rc == 0 and valid_ip(base):
        baselines.append((source, base, base6))
if not baselines or not SERVERS:
    print("::error title=TUN acceptance blocked::Baseline public IP or VPN endpoint resolution is unavailable.")
    sys.exit(1)


def resolver_ip():
    """IP рекурсивного резолвера, который реально спросил (whoami.akamai.net отвечает адресом спросившего резолвера)."""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo("whoami.akamai.net", 80, socket.AF_INET)})
    except OSError:
        return []


base_res = resolver_ip()
token = open(os.path.join(HD, "token")).read().strip()
heartbeat_stop = threading.Event()
def cleanup():
    heartbeat_stop.set()
    try:
        helper({"cmd": "down", "token": token})
    except Exception:
        print("::warning title=TUN cleanup::Could not confirm helper shutdown; runner watchdog still applies.")
atexit.register(cleanup)
def heartbeat():
    while not heartbeat_stop.wait(10):
        try:
            helper({"cmd": "ping"}, 5)
        except Exception:
            pass
threading.Thread(target=heartbeat, daemon=True).start()

# Establish a working core/profile before testing OS routes. A stale test key or
# unreachable endpoint must not be reported as a TUN/DNS implementation failure.
proxy_identity = False
IP_URL, base_ip, base_ip6 = baselines[0]
for source, base, base6 in baselines:
    rc, proxy_ip = curl(source, ["--proxy", "http://127.0.0.1:38812"])
    changed = rc == 0 and valid_ip(proxy_ip) and proxy_ip not in (base, base6)
    facts = {"source":source,"curl_exit":rc,"valid_ip":valid_ip(proxy_ip),"changed":changed}
    print("::notice title=Core probe evidence::" + json.dumps(facts))
    if changed:
        proxy_identity = True
        IP_URL, base_ip, base_ip6 = source, base, base6
        break
ok("preflight: forced remote core changes public IP before TUN", proxy_identity)
with tempfile.TemporaryDirectory() as payload_dir:
    probe = subprocess.run([
        "curl", "-fsS", "--proto", "=https", "--connect-timeout", "5", "-m", "15",
        "--proxy", "http://127.0.0.1:38812", "-o", os.path.join(payload_dir, "probe.bin"),
        "-w", "%{http_code}:%{size_download}", "https://vpn.insellers.su/probe/32k",
    ], capture_output=True, text=True)
    parts = probe.stdout.split(":")
    payload_ok = probe.returncode == 0 and len(parts) == 2 and parts[0] == "200" and float(parts[1]) >= 32768
ok("preflight: forced remote core transfers 32 KiB before TUN", payload_ok)
if not proxy_identity or not payload_ok:
    # Publish categories only, never the test key, endpoint or raw configuration.
    try:
        log = open("xray.out", encoding="utf-8", errors="replace").read().lower()
    except OSError:
        log = ""
    categories = {
        "timeout": ("timeout", "timed out", "deadline exceeded"),
        "refused": ("connection refused", "actively refused"),
        "dns": ("no such host", "failed to lookup"),
        "auth": ("invalid user", "invalid authentication", "rejected user"),
        "config": ("failed to load config", "failed to build config"),
        "tls": ("tls handshake", "certificate"),
    }
    found = [name for name, terms in categories.items() if any(t in log for t in terms)]
    print("::error title=TUN acceptance blocked::Core/profile fails before TUN; error categories: " + (", ".join(found) or "not available"))
    sys.exit(1)

r = helper({"cmd": "up", "token": token, "socks": 38808, "bypass": sorted(SERVERS), "dns": "udp"})
ok("helper up", r.get("ok"), json.dumps(r, ensure_ascii=False))
time.sleep(5)
rc, ip = curl(IP_URL)
# выход через туннель = адрес сервера (IPv4 или IPv6 сервера - сервер сам выходит по IPv6), не адрес раннера
ok("1. curl ifconfig.me без прокси = другой подтверждённый IP", rc == 0 and valid_ip(ip) and ip not in (base_ip, base_ip6))
try:
    socket.getaddrinfo("t%d.example.org" % int(time.time()), 443)   # новое имя - без кеша
except OSError:
    pass
try:
    socket.getaddrinfo("example.com", 443)
    dns_ok = True
except OSError:
    dns_ok = False
ok("3a. DNS через TUN работает", dns_ok)
# Read a public SSH banner only; no credentials, host-key bypass or login.
try:
    with socket.create_connection(("github.com", 22), 10) as s:
        s.settimeout(10)
        banner_ok = s.recv(128).startswith(b"SSH-")
except OSError:
    banner_ok = False
time.sleep(1)
lg = xlog()
ok("2. SSH banner (github.com:22) идёт через ядро VPN", banner_ok and ":22 [socks-in" in lg,
   next((l[:160] for l in lg.splitlines() if ":22 [socks-in" in l), "нет строки в журнале ядра"))
time.sleep(2)
lg = xlog()
ok("3b. DNS-запросы системы уходят в ядро (dns-out), не мимо", "-> dns-out]" in lg or ">> dns-out]" in lg,
   f"строк dns-out: {lg.count('dns-out]')}")
tun_res = resolver_ip()
ok("3c. резолвер в TUN отличается от исходного (не полная проверка утечек)", bool(tun_res) and not (set(tun_res) & set(base_res)),
   f"до {base_res} -> в TUN {tun_res}")
try:
    ya = sorted({i[4][0] for i in socket.getaddrinfo("ya.ru", 443, socket.AF_INET)})
except OSError:
    ya = []
curl("https://ya.ru/")
time.sleep(2)
lg = xlog()
ok("4. RU-сайт (ya.ru) - через ядро, напрямую (RU-direct)",
   any(("ya.ru:443 [socks-in" in l or any(f"{a}:443 [socks-in" in l for a in ya)) and "direct]" in l for l in lg.splitlines()), str(ya))
rc6, ip6 = curl(IP_URL, ["-6"], 8)
ok("5. IPv6 мимо туннеля не утекает (нет своего IPv6 раннера)", rc6 != 0 or not ip6 or ip6 != base_ip6, f"rc={rc6} {ip6}")
r = helper({"cmd": "down", "token": token})
ok("helper down authorized", r.get("ok"))
time.sleep(3)
rc, ip = curl(IP_URL)
ok("6. «Отключить»: снова свой IP, интернет работает", rc == 0 and ip == base_ip, ip)
# ядро упало - помощник сам снимает TUN (3 проверки по 5 с), интернет не остаётся мёртвым
r = helper({"cmd": "up", "token": token, "socks": 38808, "bypass": sorted(SERVERS), "dns": "udp"})
time.sleep(4)
if WIN:
    subprocess.run(["taskkill", "/F", "/IM", "xray.exe"], capture_output=True)
else:
    subprocess.run(["pkill", "-x", "xray"], capture_output=True)
time.sleep(25)
st = helper({"cmd": "status"})
rc, ip = curl(IP_URL)
ok("7. ядро упало - помощник снял TUN, интернет работает", (not st.get("running")) and rc == 0 and ip == base_ip, f"{st} {ip}")
print("\n=== ИТОГ ===")
for n, c, i in results:
    print(("✅ " if c else "❌ ") + n)
sys.exit(0 if all(c for _, c, _ in results) else 1)
