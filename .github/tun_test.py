#!/usr/bin/env python3
"""Проверка механизма TUN на раннере (macOS/Windows): ядро xray с конфигурацией тестового ключа + ins-helper + sing-box.
Секрет TUN_TEST_CONFIG - клиентская конфигурация (как у приложения: socks 38808, http 38809). Печатает итог, код 1 - провал.
Что НЕ проверить на раннере: сон/пробуждение, смена Wi-Fi, реальный пароль администратора / окно UAC."""
import json, os, platform, socket, subprocess, sys, time

WIN = platform.system() == "Windows"
HD = r"C:\Program Files\INSELLERS VPN Helper" if WIN else "/Library/PrivilegedHelperTools/su.insellers.helper"
SERVERS = set()
results = []


def ok(name, cond, info=""):
    results.append((name, bool(cond), info))
    print(("PASS " if cond else "FAIL ") + name + (" - " + info if info else ""), flush=True)


def helper(req, t=25):
    s = socket.create_connection(("127.0.0.1", 38811), 5); s.settimeout(t)
    s.sendall((json.dumps(req) + "\n").encode()); d = b""
    while not d.endswith(b"\n"):
        x = s.recv(4096)
        if not x: break
        d += x
    return json.loads(d or b"{}")


def curl(url, extra=(), t=15):
    r = subprocess.run(["curl", "-s", "-m", str(t)] + list(extra) + [url], capture_output=True, text=True)
    return r.returncode, r.stdout.strip()


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
_, base_ip = curl("https://ifconfig.me")
print("runner ip:", base_ip)
token = open(os.path.join(HD, "token")).read().strip()

r = helper({"cmd": "up", "token": token, "socks": 38808, "bypass": sorted(SERVERS), "dns": "udp"})
ok("helper up", r.get("ok"), json.dumps(r, ensure_ascii=False))
time.sleep(5)
rc, ip = curl("https://ifconfig.me")
ok("1. curl ifconfig.me без прокси = IP сервера VPN", ip in SERVERS, f"{ip} (раннер {base_ip})")
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
ok("3b. DNS-запросы системы уходят в ядро (dns-out), не мимо", "-> dns-out]" in lg or ">> dns-out]" in lg)
curl("https://ya.ru/")
time.sleep(1)
lg = xlog()
ok("4. RU-сайт (ya.ru) - напрямую через ядро (правило RU-direct)",
   any("ya.ru:443 [socks-in" in l and "direct]" in l for l in lg.splitlines()))
rc6, ip6 = curl("https://ifconfig.me", ["-6"], 8)
ok("5. IPv6 мимо туннеля не утекает", rc6 != 0 or not ip6, f"rc={rc6} {ip6}")
r = helper({"cmd": "down"})
time.sleep(3)
rc, ip = curl("https://ifconfig.me")
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
rc, ip = curl("https://ifconfig.me")
ok("7. ядро упало - помощник снял TUN, интернет работает", (not st.get("running")) and rc == 0 and ip == base_ip, f"{st} {ip}")
print("\n=== ИТОГ ===")
for n, c, i in results:
    print(("✅ " if c else "❌ ") + n + (" - " + i if i else ""))
sys.exit(0 if all(c for _, c, _ in results) else 1)
