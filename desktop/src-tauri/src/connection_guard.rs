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
}
