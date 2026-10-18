#!/usr/bin/env python3
"""Проверка механизма TUN на раннере (macOS/Windows): ядро xray с конфигурацией тестового ключа + ins-helper + sing-box.
Секрет TUN_TEST_CONFIG - клиентская конфигурация (как у приложения: socks 38808, http 38809). Печатает итог, код 1 - провал.
Что НЕ проверить на раннере: сон/пробуждение, смена Wi-Fi, реальный пароль администратора / окно UAC."""
import atexit, ipaddress, json, os, platform, socket, subprocess, sys, threading, time

WIN = platform.system() == "Windows"
HD = r"C:\Program Files\INSELLERS VPN Helper" if WIN else "/Library/PrivilegedHelperTools/su.insellers.helper"
SERVERS = set()
results = []


def ok(name, cond, info=""):
    results.append((name, bool(cond), info))
    print(("PASS " if cond else "FAIL ") + name + (" - " + info if info else ""), flush=True)


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
    # CI proxy variables must not bypass the path being tested; explicit -x still works.
    env = {k: v for k, v in os.environ.items()
           if k.lower() not in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}}
    r = subprocess.run(["curl", "-s", "-m", str(t)] + list(extra) + [url],
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stdout.strip()


def valid_ip(value, version=None):
    try:
        parsed = ipaddress.ip_address(value)
        return version is None or parsed.version == version
    except ValueError:
        return False


def proxy_ready(base_ip):
    rc, ip = curl("https://ifconfig.me", ["--socks5-hostname", "127.0.0.1:38808"])
    return rc == 0 and valid_ip(ip) and ip != base_ip


def keepalive(stop, errors, interval=10):
    while not stop.wait(interval):
        try:
            r = helper({"cmd": "ping"}, t=5)
            if not r.get("ok"):
                errors.append("helper rejected ping")
        except (OSError, ValueError):
            errors.append("helper ping failed")


def cleanup(stop, worker, token):
    stop.set()
    worker.join(timeout=11)
    try:
        helper({"cmd": "down", "token": token}, t=5)
    except (OSError, ValueError):
        pass  # Best effort after failure; normal down below has a mandatory assertion.


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
print("servers:", SERVERS)
base_rc, base_ip = curl("https://ifconfig.me", ["-4"])
_, base_ip6 = curl("https://ifconfig.me", ["-6"], 8)
print("runner ip:", base_ip, "ipv6:", base_ip6 or "нет")
ok("preflight: valid direct IPv4", base_rc == 0 and valid_ip(base_ip, 4))
ok("preflight: IPv6 response is IPv6", not base_ip6 or valid_ip(base_ip6, 6))
ok("preflight: test profile carries traffic before TUN", proxy_ready(base_ip))
if not all(c for _, c, _ in results):
    print("TUN NOT STARTED: test profile or runner baseline is unavailable; core regression cannot be assessed.")
    sys.exit(1)


def resolver_ip():
    """IP рекурсивного резолвера, который реально спросил (whoami.akamai.net отвечает адресом спросившего резолвера)."""
    try:
        return sorted({i[4][0] for i in socket.getaddrinfo("whoami.akamai.net", 80, socket.AF_INET)})
    except OSError:
        return []


base_res = resolver_ip()
print("resolver до TUN:", base_res)
if not WIN:
    print(subprocess.run(["scutil", "--dns"], capture_output=True, text=True).stdout[:1500])
token = open(os.path.join(HD, "token")).read().strip()

r = helper({"cmd": "up", "token": token, "socks": 38808, "bypass": sorted(SERVERS), "dns": "udp"})
ok("helper up", r.get("ok"), json.dumps(r, ensure_ascii=False))
if not r.get("ok"):
    sys.exit(1)
stop_ping = threading.Event()
ping_errors = []
ping_worker = threading.Thread(target=keepalive, args=(stop_ping, ping_errors), daemon=True)
ping_worker.start()
atexit.register(cleanup, stop_ping, ping_worker, token)
time.sleep(5)
rc, ip = curl("https://ifconfig.me")
# выход через туннель = адрес сервера (IPv4 или IPv6 сервера - сервер сам выходит по IPv6), не адрес раннера
ok("1. curl ifconfig.me без прокси = выход через сервер VPN", rc == 0 and valid_ip(ip) and ip not in (base_ip, base_ip6), f"{ip} (раннер {base_ip})")
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
subprocess.run(["ssh", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-T", "git@github.com"],
               capture_output=True, text=True, timeout=30)
time.sleep(1)
lg = xlog()
ok("2. ssh (github.com:22) идёт через ядро VPN", ":22 [socks-in" in lg,
   next((l[:160] for l in lg.splitlines() if ":22 [socks-in" in l), "нет строки в журнале ядра"))
time.sleep(2)
lg = xlog()
ok("3b. DNS-запросы системы уходят в ядро (dns-out), не мимо", "-> dns-out]" in lg or ">> dns-out]" in lg,
   f"строк dns-out: {lg.count('dns-out]')}")
tun_res = resolver_ip()
ok("3c. нет утечки DNS: резолвер в TUN не резолвер раннера", bool(tun_res) and not (set(tun_res) & set(base_res)),
   f"до {base_res} -> в TUN {tun_res}")
ya = sorted({i[4][0] for i in socket.getaddrinfo("ya.ru", 443, socket.AF_INET)})
curl("https://ya.ru/")
time.sleep(2)
lg = xlog()
ok("4. RU-сайт (ya.ru) - через ядро, напрямую (RU-direct)",
   any(("ya.ru:443 [socks-in" in l or any(f"{a}:443 [socks-in" in l for a in ya)) and "direct]" in l for l in lg.splitlines()), str(ya))
rc6, ip6 = curl("https://ifconfig.me", ["-6"], 8)
ok("5. IPv6 мимо туннеля не утекает (нет своего IPv6 раннера)", rc6 != 0 or not ip6 or (valid_ip(ip6, 6) and ip6 != base_ip6), f"rc={rc6} {ip6}")
r = helper({"cmd": "down", "token": token})
ok("helper down authenticated", r.get("ok"))
time.sleep(3)
rc, ip = curl("https://ifconfig.me")
ok("6. «Отключить»: снова свой IP, интернет работает", rc == 0 and ip == base_ip, ip)
# ядро упало - помощник сам снимает TUN (3 проверки по 5 с), интернет не остаётся мёртвым
r = helper({"cmd": "up", "token": token, "socks": 38808, "bypass": sorted(SERVERS), "dns": "udp"})
ok("helper restart for crash recovery", r.get("ok"))
time.sleep(4)
if WIN:
    subprocess.run(["taskkill", "/F", "/IM", "xray.exe"], capture_output=True)
else:
    subprocess.run(["pkill", "-x", "xray"], capture_output=True)
time.sleep(25)
st = helper({"cmd": "status"})
rc, ip = curl("https://ifconfig.me")
ok("7. ядро упало - помощник снял TUN, интернет работает", (not st.get("running")) and rc == 0 and ip == base_ip, f"{st} {ip}")
cleanup(stop_ping, ping_worker, token)
atexit.unregister(cleanup)
ok("helper heartbeat requests succeeded", not ping_errors, "; ".join(ping_errors[:2]))
print("\n=== ИТОГ ===")
for n, c, i in results:
    print(("✅ " if c else "❌ ") + n + (" - " + i if i else ""))
sys.exit(0 if all(c for _, c, _ in results) else 1)
