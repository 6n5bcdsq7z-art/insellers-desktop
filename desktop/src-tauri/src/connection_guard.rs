//! Inspect other connections without stopping another application's VPN.
pub fn foreign_proxy(enabled: bool, host: &str, port: u16, own_http: u16, own_socks: u16) -> bool {
    enabled && !(matches!(host, "127.0.0.1" | "localhost") && (port == own_http || port == own_socks))
}

pub fn connected_network_extensions(list: &str) -> Vec<String> {
    let mut names = Vec::new();
    for line in list.lines() {
        if !line.contains("(Connected)") && !line.contains("(Connecting)") { continue; }
        if let Some(name) = line.split('"').nth(1).filter(|name| !name.is_empty()) {
            if !name.to_lowercase().contains("insellers") && !names.iter().any(|n| n == name) {
                names.push(name.to_owned());
            }
        }
    }
    names
}

/// macOS command-line TUN clients need not appear in scutil --nc.
/// Inspect only IPv4 default/split-default routes, not the mere existence of utun.
pub fn routed_tunnel(table: &str) -> Option<String> {
    let mut halves = std::collections::HashMap::<String, u8>::new();
    for line in table.lines() {
        let columns: Vec<_> = line.split_whitespace().collect();
        let Some(destination) = columns.first() else { continue };
        let Some(interface) = columns.iter().find(|v| v.starts_with("utun")
            && v[4..].chars().all(|c| c.is_ascii_digit()) && v.len() > 4) else { continue };
        if matches!(*destination, "default" | "0.0.0.0/0") { return Some(interface.to_string()); }
        let bit = match *destination {
            "0/1" | "0.0.0.0/1" => 1,
            "128.0/1" | "128.0.0.0/1" => 2,
            _ => 0,
        };
        let seen = halves.entry(interface.to_string()).or_default();
        *seen |= bit;
        if *seen == 3 { return Some(interface.to_string()); }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn only_active_other_tunnels_are_conflicts() {
        assert_eq!(connected_network_extensions("* (Connected) A VPN \"Happ\"\n* (Disconnected) B \"INCY\"\n* (Connected) C \"INSELLERS VPN\"\n* (Connecting) D \"WireGuard\"\n* (Connected) A VPN \"Happ\""), vec!["Happ", "WireGuard"]);
    }
    #[test] fn preserve_foreign_proxy_but_recognize_our_ports() {
        assert!(foreign_proxy(true, "localhost", 1234, 38809, 38808));
        assert!(foreign_proxy(true, "proxy.example", 38809, 38809, 38808));
        assert!(!foreign_proxy(true, "127.0.0.1", 38809, 38809, 38808));
        assert!(!foreign_proxy(true, "localhost", 38808, 38809, 38808));
        assert!(!foreign_proxy(false, "proxy.example", 443, 38809, 38808));
    }
    #[test] fn tun_default_is_a_conflict_without_network_extension() {
        assert_eq!(routed_tunnel("default 10.0.0.1 UGSc utun4"), Some("utun4".into()));
        assert_eq!(routed_tunnel("default 192.168.1.1 UGSc en0\n0/1 10.0.0.1 UGSc utun6\n128.0/1 10.0.0.1 UGSc utun6"), Some("utun6".into()));
        assert_eq!(routed_tunnel("default 192.168.1.1 UGSc en0\n10.90.0/24 link#20 UCS utun3"), None);
        assert_eq!(routed_tunnel("0/1 link#20 UCS utun3\n128.0/1 link#21 UCS utun4"), None);
    }
}
