// ins-helper - помощник INSELLERS VPN с правами администратора (26.09.2026, владелец: «весь трафик системы через VPN, как Happ»).
//
// Ставится ОДИН раз (Mac - LaunchDaemon /Library/LaunchDaemons/su.insellers.helper.plist, Windows - задача планировщика при
// запуске от SYSTEM) и держит TUN: запускает sing-box рядом с собой (root-каталог, приложение туда писать не может), весь трафик
// системы -> SOCKS-вход ядра приложения (xray или wireproxy) на 127.0.0.1. Конфигурацию sing-box собирает САМ по проверенным
// параметрам (порт, IP серверов, вид DNS) - приложение не передаёт root-процессу произвольный файл.
//
// Протокол: TCP 127.0.0.1:38811, одна строка JSON на запрос, ответ - одна строка JSON.
//
//	{"cmd":"version"} | {"cmd":"status"} | {"cmd":"ping"} | {"cmd":"down"} |
//	{"cmd":"up","token":"…","socks":38808,"bypass":["176.124.198.72"],"dns":"udp"|"tcp"}
//
// token - из файла token рядом с помощником (создаётся при установке, права 600 владельцу консоли с 02.10): без него команды up/down
// не принимаются - иначе любой локальный процесс мог бы увести трафик компьютера на свой SOCKS от root или снять TUN.
// Сам снимает TUN (сеть не остаётся мёртвой): приложение молчит > 60 с (упало, закрыто без «Отключить») или SOCKS-вход ядра
// не отвечает 3 проверки подряд (ядро упало). sing-box при остановке сам убирает маршруты.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Version = "2" // 02.10: down требует ключ; ключ 600
	Listen  = "127.0.0.1:38811"
)

type req struct {
	Cmd    string   `json:"cmd"`
	Token  string   `json:"token"`
	Socks  int      `json:"socks"`
	Bypass []string `json:"bypass"`
	DNS    string   `json:"dns"`
}

type state struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	socks    int
	lastPing time.Time
	lastErr  string
	gen      int
	done     chan struct{} // закрывается, когда текущий sing-box завершился (Wait - один раз, в горутине up)
}

var st state
var dir string

func sbPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(dir, "sing-box.exe")
	}
	return filepath.Join(dir, "sing-box")
}

func token() string {
	b, err := os.ReadFile(filepath.Join(dir, "token"))
	if err != nil {
		return ""
	}
	s := string(b)
	for len(s) > 0 && (s[len(s)-1] == '\n' || s[len(s)-1] == '\r' || s[len(s)-1] == ' ') {
		s = s[:len(s)-1]
	}
	return s
}

// config - конфигурация sing-box (формат 1.12+; проверено sing-box check 1.14.2).
func config(socks int, bypass []string, dns string) ([]byte, error) {
	cidr := []string{}
	for _, b := range bypass {
		ip := net.ParseIP(b)
		if ip == nil || ip.To4() == nil {
			continue
		}
		cidr = append(cidr, ip.String()+"/32")
	}
	if len(cidr) == 0 {
		return nil, fmt.Errorf("нет IP серверов")
	}
	if dns != "tcp" {
		dns = "udp"
	}
	tun := map[string]any{
		"type": "tun", "tag": "tun-in",
		"address": []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
		"mtu":     1500, "auto_route": true, "strict_route": true, "stack": "mixed",
	}
	if runtime.GOOS == "windows" {
		tun["interface_name"] = "INSELLERS VPN"
	}
	c := map[string]any{
		"log": map[string]any{"level": "warn", "timestamp": true},
		"dns": map[string]any{
			// udp - DNS-модуль ядра (фильтры рекламы, RU-домены через Яндекс); tcp - wireproxy (AmneziaWG) UDP через SOCKS не умеет
			"servers":  []any{map[string]any{"type": dns, "tag": "via-core", "server": "1.1.1.1", "detour": "core"}},
			"final":    "via-core",
			"strategy": "ipv4_only",
		},
		"inbounds": []any{tun},
		"outbounds": []any{
			map[string]any{"type": "socks", "tag": "core", "server": "127.0.0.1", "server_port": socks, "version": "5"},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{
			"auto_detect_interface": true,
			"rules": []any{
				map[string]any{"action": "sniff"},
				map[string]any{"protocol": "dns", "action": "hijack-dns"},
				// само ядро и помощник - мимо TUN (иначе петля): ядро ходит к серверам и «напрямую» (RU-сайты) с физической сети
				map[string]any{"process_name": []string{"xray", "xray.exe", "wireproxy", "wireproxy.exe", "ins-helper", "ins-helper.exe"},
					"outbound": "direct"},
				map[string]any{"ip_cidr": cidr, "outbound": "direct"},
				// IPv6 наружу не выпускаем: сервер его не отдаёт, мимо туннеля - утечка
				map[string]any{"ip_version": 6, "action": "reject"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
			},
			"final": "core",
		},
	}
	return json.MarshalIndent(c, "", "  ")
}

// macOS: DNS роутера (192.168.x.1) в своей подсети - маршрут к ней точнее маршрутов TUN, и запросы шли мимо туннеля (проверка
// на раннере: whoami.akamai.net - тот же резолвер). Маршрутом «в TUN» чинить нельзя: DNS роутера обычно и шлюз - ломается вся
// сеть. Поэтому на время TUN DNS каждой сетевой службы = 172.19.0.2 (внутри TUN, дальше hijack-dns), прежние - в dns-saved.json,
// возврат при down и при запуске помощника после сбоя. Windows: утечку закрывает strict_route (проверено на раннере).
const tunDNS = "172.19.0.2"

func macServices() []string {
	out, err := exec.Command("/usr/sbin/networksetup", "-listallnetworkservices").Output()
	if err != nil {
		return nil
	}
	var res []string
	for i, l := range strings.Split(string(out), "\n") {
		l = strings.TrimSpace(l)
		if i == 0 || l == "" || strings.HasPrefix(l, "*") { // первая строка - пояснение, «*» - выключенная служба
			continue
		}
		res = append(res, l)
	}
	return res
}

func macSetDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	saved := map[string][]string{}
	sp := filepath.Join(dir, "dns-saved.json")
	if b, err := os.ReadFile(sp); err == nil { // прошлый раз не вернули (сбой) - сохранённое не затираем
		_ = json.Unmarshal(b, &saved)
	} else {
		for _, svc := range macServices() {
			out, _ := exec.Command("/usr/sbin/networksetup", "-getdnsservers", svc).Output()
			var cur []string
			for _, f := range strings.Fields(string(out)) {
				if net.ParseIP(f) != nil {
					cur = append(cur, f)
				}
			}
			saved[svc] = cur // пусто = DNS от DHCP
		}
		b, _ := json.Marshal(saved)
		_ = os.WriteFile(sp, b, 0600)
	}
	for svc := range saved {
		_ = exec.Command("/usr/sbin/networksetup", "-setdnsservers", svc, tunDNS).Run()
	}
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

func macRestoreDNS() {
	if runtime.GOOS != "darwin" {
		return
	}
	sp := filepath.Join(dir, "dns-saved.json")
	b, err := os.ReadFile(sp)
	if err != nil {
		return
	}
	saved := map[string][]string{}
	if json.Unmarshal(b, &saved) != nil {
		_ = os.Remove(sp)
		return
	}
	for svc, cur := range saved {
		args := []string{"-setdnsservers", svc}
		if len(cur) == 0 {
			args = append(args, "empty")
		} else {
			args = append(args, cur...)
		}
		_ = exec.Command("/usr/sbin/networksetup", args...).Run()
	}
	_ = os.Remove(sp)
	_ = exec.Command("/usr/bin/dscacheutil", "-flushcache").Run()
	_ = exec.Command("/usr/bin/killall", "-HUP", "mDNSResponder").Run()
}

func socksAlive(port int) bool {
	c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 2*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func down(reason string) {
	st.mu.Lock()
	st.gen++
	cmd, done := st.cmd, st.done
	st.cmd, st.done = nil, nil
	st.mu.Unlock()
	defer macRestoreDNS()
	if cmd == nil || cmd.Process == nil {
		return
	}
	log.Printf("down: %s", reason)
	if runtime.GOOS == "windows" {
		_ = cmd.Process.Kill()
	} else {
		_ = cmd.Process.Signal(os.Interrupt) // sing-box сам убирает маршруты и TUN
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-done
	}
}

func up(r req) error {
	if r.Socks < 1024 || r.Socks > 65535 {
		return fmt.Errorf("неверный порт")
	}
	if !socksAlive(r.Socks) {
		return fmt.Errorf("SOCKS-вход ядра не отвечает")
	}
	cfg, err := config(r.Socks, r.Bypass, r.DNS)
	if err != nil {
		return err
	}
	down("перезапуск")
	p := filepath.Join(dir, "tun.json")
	if err := os.WriteFile(p, cfg, 0600); err != nil {
		return err
	}
	cmd := exec.Command(sbPath(), "run", "-c", p, "-D", dir)
	lf, _ := os.OpenFile(filepath.Join(dir, "sing-box.log"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	cmd.Stdout, cmd.Stderr = lf, lf
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan struct{})
	st.mu.Lock()
	st.cmd, st.done, st.socks, st.lastPing, st.lastErr = cmd, done, r.Socks, time.Now(), ""
	st.gen++
	g := st.gen
	st.mu.Unlock()
	go func() {
		err := cmd.Wait()
		close(done)
		st.mu.Lock()
		if st.gen == g {
			st.cmd, st.done = nil, nil
			st.lastErr = fmt.Sprintf("sing-box завершился: %v", err)
		}
		st.mu.Unlock()
	}()
	// дать TUN подняться: процесс жив через 2 с - считаем, что встал (маршруты ставит сам sing-box)
	time.Sleep(2 * time.Second)
	st.mu.Lock()
	alive := st.cmd == cmd
	le := st.lastErr
	st.mu.Unlock()
	if !alive {
		return fmt.Errorf("sing-box не запустился: %s", le)
	}
	macSetDNS()
	return nil
}

func watchdog() {
	fails := 0
	for range time.Tick(5 * time.Second) {
		st.mu.Lock()
		running, port, lp := st.cmd != nil, st.socks, st.lastPing
		st.mu.Unlock()
		if !running {
			fails = 0
			continue
		}
		if time.Since(lp) > 60*time.Second {
			down("приложение молчит больше 60 с")
			continue
		}
		if socksAlive(port) {
			fails = 0
		} else if fails++; fails >= 3 {
			down("SOCKS-вход ядра не отвечает")
			fails = 0
		}
	}
}

func handle(c net.Conn) {
	defer c.Close()
	if a, ok := c.RemoteAddr().(*net.TCPAddr); !ok || !a.IP.IsLoopback() {
		return
	}
	_ = c.SetDeadline(time.Now().Add(30 * time.Second))
	line, err := bufio.NewReader(c).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return
	}
	var r req
	out := map[string]any{"ok": true, "version": Version}
	if json.Unmarshal(line, &r) != nil {
		out = map[string]any{"ok": false, "error": "bad json"}
	} else {
		switch r.Cmd {
		case "version":
		case "status", "ping":
			st.mu.Lock()
			if r.Cmd == "ping" && st.cmd != nil {
				st.lastPing = time.Now()
			}
			out["running"] = st.cmd != nil
			out["error"] = st.lastErr
			st.mu.Unlock()
		case "down":
			// 02.10 (безопасность): без ключа - отказ; раньше любой локальный процесс мог снять TUN (трафик мимо VPN).
			if t := token(); t == "" || r.Token != t {
				out = map[string]any{"ok": false, "error": "bad token"}
			} else {
				down("по команде приложения")
			}
		case "up":
			if t := token(); t == "" || r.Token != t {
				out = map[string]any{"ok": false, "error": "bad token"}
			} else if err := up(r); err != nil {
				out = map[string]any{"ok": false, "error": err.Error()}
			}
		default:
			out = map[string]any{"ok": false, "error": "unknown cmd"}
		}
	}
	b, _ := json.Marshal(out)
	_, _ = c.Write(append(b, '\n'))
}

func main() {
	exe, _ := os.Executable()
	dir = filepath.Dir(exe)
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(Version)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "--print-config" { // для проверки: ins-helper --print-config 38808 1.2.3.4
		port, _ := strconv.Atoi(os.Args[2])
		b, err := config(port, os.Args[3:], "udp")
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Println(string(b))
		return
	}
	lf, err := os.OpenFile(filepath.Join(dir, "helper.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err == nil {
		log.SetOutput(lf)
	}
	ln, err := net.Listen("tcp", Listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("ins-helper %s слушает %s", Version, Listen)
	macRestoreDNS() // помощник перезапущен после сбоя - DNS как был до TUN
	go watchdog()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}
