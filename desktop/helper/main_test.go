package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// Evaluate routing predicates for traffic already identified by sniffing.
// Runtime sing-box replay separately verifies that TLS supplies this name.
func testRoute(t *testing.T, raw []byte, domain, ip, process string, protocol ...string) string {
	t.Helper()
	var c struct {
		Route struct {
			Rules []struct {
				Domain   []string `json:"domain"`
				Process  []string `json:"process_name"`
				CIDR     []string `json:"ip_cidr"`
				Protocol string   `json:"protocol"`
				Version  int      `json:"ip_version"`
				Private  bool     `json:"ip_is_private"`
				Action   string   `json:"action"`
				Outbound string   `json:"outbound"`
			} `json:"rules"`
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	contains := func(v []string, s string) bool {
		for _, x := range v {
			if x == s {
				return true
			}
		}
		return false
	}
	addr := net.ParseIP(ip)
	for _, r := range c.Route.Rules {
		if r.Action == "sniff" {
			continue
		}
		if r.Protocol != "" && (len(protocol) == 0 || r.Protocol != protocol[0]) {
			continue
		}
		if len(r.Domain) > 0 && !contains(r.Domain, domain) {
			continue
		}
		if len(r.Process) > 0 && !contains(r.Process, process) {
			continue
		}
		if len(r.CIDR) > 0 {
			hit := false
			for _, x := range r.CIDR {
				_, n, e := net.ParseCIDR(x)
				if e == nil && n.Contains(addr) {
					hit = true
				}
			}
			if !hit {
				continue
			}
		}
		if r.Version == 6 && addr.To4() != nil {
			continue
		}
		if r.Private && !addr.IsPrivate() {
			continue
		}
		if r.Action != "" && r.Action != "route" {
			return r.Action
		}
		return r.Outbound
	}
	return c.Route.Final
}

func TestCoreDNSDoesNotReenterResolver(t *testing.T) {
	for _, dns := range []string{"udp", "tcp"} {
		raw, err := config(38808, []string{"212.34.151.212"}, dns)
		if err != nil {
			t.Fatal(err)
		}
		for _, process := range []string{"xray", "xray.exe", "wireproxy", "wireproxy.exe", "ins-helper", "ins-helper.exe"} {
			if got := testRoute(t, raw, "yandex.ru", "77.88.8.8", process, "dns"); got != "direct" {
				t.Errorf("%s resolver request loops through %s", process, got)
			}
		}
		// Other processes still use the configured resolver and its filters.
		for _, ip := range []string{"77.88.8.8", "1.1.1.1", "192.168.1.1"} {
			if got := testRoute(t, raw, "example.com", ip, "browser", "dns"); got != "hijack-dns" {
				t.Errorf("application DNS to %s escaped interception: %s", ip, got)
			}
		}
	}
}

func TestSharedIngressPreservesSitesAndEndpointSafety(t *testing.T) {
	for _, dns := range []string{"udp", "tcp"} {
		raw, err := config(38808, []string{"212.34.151.212", "176.124.198.72"}, dns)
		if err != nil {
			t.Fatal(err)
		}
		for _, host := range []string{"insellers.su", "vpn.insellers.su", "cdn.insellers.su", "bot.insellers.su", "elcode.insellers.su", "hochu.insellers.su", "hochutusit.insellers.su", "sub.insellers.su"} {
			if got := testRoute(t, raw, host, "2606:4700:4700::1111", "curl"); got != "reject" {
				t.Errorf("IPv6 guard bypassed for %s: %s", host, got)
			}
			if got := testRoute(t, raw, host, "192.168.1.1", "curl"); got != "direct" {
				t.Errorf("LAN guard changed for %s: %s", host, got)
			}
			for _, ip := range []string{"212.34.151.212", "176.124.198.72"} {
				if got := testRoute(t, raw, host, ip, "curl"); got != "core" {
					t.Errorf("%s %s %s: got %s, want core", dns, host, ip, got)
				}
				for _, process := range []string{"xray", "xray.exe", "wireproxy", "wireproxy.exe", "ins-helper", "ins-helper.exe"} {
					if got := testRoute(t, raw, host, ip, process); got != "direct" {
						t.Errorf("core process %s loop risk: %s", process, got)
					}
				}
			}
		}
		for _, host := range []string{"", "direct.insellers.su", "n2.insellers.su", "unknown.insellers.su", "insellers.su.example.org"} {
			if got := testRoute(t, raw, host, "212.34.151.212", "curl"); got != "direct" {
				t.Errorf("endpoint %q changed to %s", host, got)
			}
		}
		if got := testRoute(t, raw, "example.com", "93.184.215.14", "curl"); got != "core" {
			t.Errorf("default route %s", got)
		}
		if got := testRoute(t, raw, "", "192.168.1.1", "curl"); got != "direct" {
			t.Errorf("LAN route %s", got)
		}
	}
}

func TestExportRuntimeFixture(t *testing.T) {
	dir := os.Getenv("INSELLERS_HELPER_FIXTURE_DIR")
	if dir == "" {
		t.Skip("runtime fixture export not requested")
	}
	raw, err := config(10808, []string{"212.34.151.212", "176.124.198.72"}, "udp")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "helper.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
}
