//! Naive is a separate Chromium executable. Xray supplies TUN-facing DNS/SOCKS.
use serde_json::{json, Value};

pub const INNER: u16 = 38819;

pub fn available() -> bool { available_protocol("naive") }

pub fn available_protocol(kind: &str) -> bool {
    if !matches!(kind, "naive" | "tuic" | "mieru") { return false; }
    if cfg!(target_os = "windows") { return false; } // no pinned Windows engine yet
    if cfg!(target_os = "macos") {
        let major = std::process::Command::new("/usr/bin/sw_vers").arg("-productVersion").output().ok()
            .filter(|o| o.status.success()).and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|v| v.trim().split('.').next()?.parse::<u32>().ok()).unwrap_or(0);
        if major < match kind { "tuic" => 26, "mieru" => 12, _ => 13 } { return false; }
    }
    std::env::current_exe().ok().and_then(|p| p.parent().map(|p| p.join(kind))).map(|p| p.is_file()).unwrap_or(false)
}

pub fn subscription_url(raw: &str) -> Result<String, String> { subscription_url_for(raw, "naive") }

pub fn subscription_url_for(raw: &str, kind: &str) -> Result<String, String> {
    if !matches!(kind, "naive" | "tuic" | "mieru") { return Err("Неверный протокол".into()); }
    let mut u = url::Url::parse(raw).map_err(|_| "Неверная ссылка подписки")?;
    if u.scheme() != "https" || !u.username().is_empty() || u.password().is_some() || u.fragment().is_some() {
        return Err("Подписка требует HTTPS".into());
    }
    let pairs: Vec<(String,String)> = u.query_pairs().filter(|(k,_)| k != "format").map(|(k,v)|(k.into_owned(),v.into_owned())).collect();
    u.query_pairs_mut().clear().extend_pairs(pairs).append_pair("format", &format!("ins{kind}"));
    Ok(u.into())
}

pub fn engine(profile: &Value, port: u16, now: u64) -> Result<Value, String> {
    let invalid = || "Неверный или истёкший профиль Naive".to_string();
    let host = profile["server"].as_str().ok_or_else(invalid)?;
    let user = profile["username"].as_str().ok_or_else(invalid)?;
    let pass = profile["password"].as_str().ok_or_else(invalid)?;
    let remote_port = profile["server_port"].as_u64().filter(|p| (1..=65535).contains(p)).ok_or_else(invalid)?;
    let label = host.strip_suffix(".insellers.su").ok_or_else(invalid)?;
    let hex = |s: &str| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let user_ok = if profile["protocol"] == "mieru" { user.strip_prefix("m_").map(|s| s.len()==62 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))).unwrap_or(false) } else { user.strip_prefix("n_").map(hex).unwrap_or(false) };
    if !matches!(profile["protocol"].as_str(), Some("naive" | "tuic" | "mieru")) || profile["expires_ms"].as_u64().unwrap_or(0) <= now || port < 1024
        || label.is_empty() || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || !user_ok || !hex(pass) { return Err(invalid()); }
    let dns = &profile["dns"];
    let u = url::Url::parse(dns["url"].as_str().ok_or_else(invalid)?).map_err(|_| invalid())?;
    if u.scheme() != "https" || u.host_str() != dns["host"].as_str() || !u.username().is_empty()
        || u.password().is_some() || u.fragment().is_some() || u.port_or_known_default() != Some(443)
        || dns["ip"].as_str().and_then(|s| s.parse::<std::net::Ipv4Addr>().ok()).is_none() { return Err(invalid()); }
    match profile["protocol"].as_str().unwrap() {
        "tuic" => {
            let id=profile["uuid"].as_str().ok_or_else(invalid)?;
            if id.len()!=36 || !id.bytes().enumerate().all(|(i,b)| if [8,13,18,23].contains(&i) { b==b'-' } else { b.is_ascii_hexdigit() }) { return Err(invalid()); }
            Ok(json!({"log":{"level":"error"},
                "inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":port}],
                "outbounds":[{"type":"tuic","tag":"proxy","server":host,"server_port":remote_port,
                    "uuid":id,"password":pass,"congestion_control":"cubic","zero_rtt_handshake":false,
                    "udp_relay_mode":"native","tls":{"enabled":true,"server_name":host,"alpn":["h3"]}}]}))
        },
        "mieru" => Ok(json!({"profiles":[{"profileName":"INSELLERS","user":{"name":user,"password":pass},
            "servers":[{"domainName":host,"portBindings":[{"port":remote_port,"protocol":"TCP"}]}]}],
            "activeProfile":"INSELLERS","rpcPort":0,"socks5Port":port,"socks5ListenLAN":false,"loggingLevel":"ERROR"})),
        _ => Ok(json!({"listen":format!("socks://127.0.0.1:{port}"),"proxy":format!("https://{user}:{pass}@{host}:{remote_port}")})),
    }
}

pub fn router(profile: &Value, now: u64) -> Result<Value, String> {
    engine(profile, INNER, now)?;
    let host = profile["dns"]["host"].as_str().unwrap();
    let mut config=json!({
        "log":{"loglevel":"warning"},
        "dns":{"queryStrategy":"UseIPv4","hosts":{host:profile["dns"]["ip"]},"servers":[profile["dns"]["url"]]},
        "inbounds":[
            {"tag":"socks-in","listen":"127.0.0.1","port":38808,"protocol":"socks","settings":{"udp":true}},
            {"tag":"http-in","listen":"127.0.0.1","port":38809,"protocol":"http"},
            {"tag":"probe-in","listen":"127.0.0.1","port":38810,"protocol":"http"},
            {"tag":"page-in","listen":"127.0.0.1","port":38815,"protocol":"http"}
        ],
        "outbounds":[
            {"tag":"proxy","protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":INNER}]}},
            {"tag":"dns-out","protocol":"dns"},{"tag":"block","protocol":"blackhole"}
        ],
        "routing":{"domainStrategy":"AsIs","rules":[
            {"type":"field","inboundTag":["socks-in","http-in"],"network":"tcp,udp","port":"53","outboundTag":"dns-out"},
            {"type":"field","network":"udp","outboundTag":"block"},
            {"type":"field","ip":["::/0"],"outboundTag":"block"}
        ]}
    });
    if profile["protocol"]!="naive" { config["routing"]["rules"].as_array_mut().unwrap().remove(1); }
    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value { json!({"protocol":"naive","server":"r1.insellers.su","server_port":26443,
        "username":format!("n_{}","a".repeat(64)),"password":"b".repeat(64),"expires_ms":2000,
        "dns":{"url":"https://vpn.insellers.su/dns-query/fixture","host":"vpn.insellers.su","ip":"89.110.97.227"}}) }
    #[test] fn actual_engine_and_dns_preserve_tls_and_credentials() {
        let p=fixture();let c=engine(&p,INNER,1000).unwrap();
        assert!(c["proxy"].as_str().unwrap().starts_with("https://n_"));
        assert!(c.get("insecure").is_none());
        let r=router(&p,1000).unwrap();
        assert_eq!(r["dns"]["servers"][0],p["dns"]["url"]);
        assert_eq!(r["dns"]["hosts"]["vpn.insellers.su"],"89.110.97.227");
        assert_eq!(r["routing"]["rules"][0]["network"],"tcp,udp");
        assert_eq!(r["routing"]["rules"][1]["outboundTag"],"block");
        assert!(!r.to_string().contains("freedom"));
    }
    #[test] fn expiry_and_untrusted_profile_fail_before_launch() {
        assert!(engine(&fixture(),INNER,2000).is_err());
        for (field,value) in [("server",json!("localhost")),("server_port",json!(65536)),("password",json!("bad@injection")),("protocol",json!("http"))] {
            let mut p=fixture();p[field]=value;assert!(engine(&p,INNER,1000).is_err());
        }
        let mut p=fixture();p["dns"]["url"]=json!("http://vpn.insellers.su/query");assert!(router(&p,1000).is_err());
    }
    #[test] fn url_retains_subscription_and_replaces_only_format() {
        assert_eq!(subscription_url("https://direct.insellers.su/sub/fixture?format=insapp&cf=1").unwrap(),
            "https://direct.insellers.su/sub/fixture?cf=1&format=insnaive");
        assert!(subscription_url("http://direct.insellers.su/sub/fixture").is_err());
    }
    #[test] fn real_tuic_and_mieru_configs_have_protocol_specific_auth() {
        let mut p=fixture();p["protocol"]=json!("tuic");p["uuid"]=json!("00000000-0000-4000-8000-000000000001");
        let c=engine(&p,INNER,1000).unwrap();
        assert_eq!(c["outbounds"][0]["type"],"tuic");
        assert_eq!(c["outbounds"][0]["tls"]["enabled"],true);
        assert!(c["outbounds"][0]["tls"].get("insecure").is_none());
        p["uuid"]=json!("invalid");assert!(engine(&p,INNER,1000).is_err());
        p["protocol"]=json!("mieru");assert!(engine(&p,INNER,1000).is_err());
        p["username"]=json!(format!("m_{}","a".repeat(62)));
        let c=engine(&p,INNER,1000).unwrap();
        assert_eq!(c["profiles"][0]["user"]["name"].as_str().unwrap().len(),64);
        assert_eq!(c["profiles"][0]["servers"][0]["portBindings"][0]["protocol"],"TCP");
        assert_eq!(c["socks5ListenLAN"],false);
        assert_eq!(c["rpcPort"],0);
    }
}
