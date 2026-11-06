//! Bounded, private connection history that survives offline exits. Never store profiles or raw errors.
use serde_json::{json, Value};
use std::{path::Path, sync::Mutex, io::Write};
static LOCK: Mutex<String> = Mutex::new(String::new());
const LIMIT: u64 = 1_048_576;
fn protocol(v: &str) -> &str {
    let p = if v.starts_with("cfg:") { v.split('|').nth(1).unwrap_or("") } else { v.split(['@', '~']).next().unwrap_or("") };
    if ["auto","proxy","reality","vless","xhttp","hysteria","hysteria2","hy2","awg","amneziawg","naive","naiveproxy","tuic","mieru","anytls","trojan","vmess","ss","shadowsocks"].contains(&p) { p } else { "unknown" }
}
/// Only fixed categories leave the process reader; engine output may contain credentials.
pub fn engine_error(bytes: &[u8]) -> Option<&'static str> {
    let text = String::from_utf8_lossy(&bytes[..bytes.len().min(8192)]).to_ascii_lowercase();
    let has = |items: &[&str]| items.iter().any(|item| text.contains(item));
    if has(&["authentication failed", "invalid password", "invalid user", "unauthorized"]) { Some("ENGINE_AUTH") }
    else if has(&["certificate verify failed", "certificate has expired", "certificate is not valid", "unknown authority", "tls handshake timeout", "tls handshake failed"]) { Some("ENGINE_TLS") }
    else if has(&["no such host", "dns lookup failed", "failed to lookup", "failed to resolve"]) { Some("ENGINE_DNS") }
    else if has(&["network is unreachable", "no route to host"]) { Some("ENGINE_ROUTE") }
    else if has(&["connection reset", "broken pipe", "connection refused"]) { Some("ENGINE_CONNECTION") }
    else if has(&["i/o timeout", "context deadline exceeded", "operation timed out", "connection timed out"]) { Some("ENGINE_TIMEOUT") }
    else { None }
}
fn reason(v: &str) -> &'static str {
    if v == "ENGINE_AUTH" { "Движок отклонил реквизиты доступа" }
    else if v == "ENGINE_TLS" { "Ошибка защищённого соединения движка" }
    else if v == "ENGINE_DNS" { "Движок не смог определить адрес сайта" }
    else if v == "ENGINE_ROUTE" { "Движку недоступен сетевой маршрут" }
    else if v == "ENGINE_CONNECTION" { "Соединение движка прервано или отклонено" }
    else if v == "ENGINE_TIMEOUT" { "Движок не получил ответ вовремя" }
    else if v == "CANCELLED" { "Отменено пользователем" }
    else if v == "BUSY" { "Предыдущее подключение ещё выполняется" }
    else if v.contains("TUN_FAILED") { "Системный туннель не передаёт данные" }
    else if v.contains("OTHER_VPN") { "Другое VPN-подключение" }
    else if v.contains("timeout") || v.contains("не отвечает") { "Нет ответа в отведённое время" }
    else if v.contains("BOOTSTRAP") || v.contains("конфигурац") || v.contains("настройк") { "Не удалось получить настройки" }
    else if v.contains("не передаёт") || v.contains("нет трафика") { "Через туннель не проходят данные" }
    else if v.is_empty() { "" } else { "Ошибка подключения; подробности в серверной диагностике" }
}
fn safe(ev: &str, data: &Value, attempt: &str) -> Value {
    let mut out = json!({"ts":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs(), "event":ev,"version":env!("CARGO_PKG_VERSION"),"attempt":attempt});
    for key in ["ms", "bytes", "kb", "try", "connected_ms", "manual", "ok"] {
        if data[key].is_boolean() || data[key].is_u64() { out[key]=data[key].clone(); }
    }
    for key in ["protocol", "path", "choice"] { if let Some(v)=data[key].as_str() {out[key]=json!(protocol(v));} }
    if let Some(v)=data["result"].as_str().filter(|v|["connected","failed","cancelled"].contains(v)) {out["result"]=json!(v);}
    if let Some(v)=data["failure_stage"].as_str().filter(|v|["config","tunnel","handshake"].contains(v)) {out["stage"]=json!(v);}
    if let Some(v)=data["err"].as_str().or(data["error_code"].as_str()).or(data["reason"].as_str()) {out["reason"]=json!(reason(v));}
    if let Some(v)=data["component"].as_str().filter(|v|["engine","router"].contains(v)) {out["component"]=json!(v);}
    if let Some(v)=data["error_code"].as_str().filter(|v|["ENGINE_AUTH","ENGINE_TLS","ENGINE_DNS","ENGINE_ROUTE","ENGINE_CONNECTION","ENGINE_TIMEOUT"].contains(v)) {out["error_code"]=json!(v);}
    out
}
pub fn record(path: &Path, ev: &str, data: &Value) {
    if !(ev.starts_with("vpn.") || ev=="proto.pick") || ev.len()>64 || !ev.bytes().all(|c|c.is_ascii_lowercase()||c==b'.'||c==b'_') {return;}
    let Ok(mut attempt)=LOCK.lock() else {return};
    if ev=="vpn.attempt" { if let Some(id)=data["attempt_id"].as_str().filter(|s|s.len()<=64 && s.bytes().all(|c|c.is_ascii_hexdigit()||c==b'-')) {*attempt=id.into();} }
    let line=safe(ev,data,&attempt).to_string()+"\n";
    let _=append(path,&line);
}
fn append(path:&Path,line:&str)->std::io::Result<()> {
    if let Ok(m)=path.symlink_metadata() {if !m.is_file() || m.file_type().is_symlink(){return Err(std::io::Error::other("not regular"));}}
    if path.metadata().map(|m|m.len()>=LIMIT).unwrap_or(false) {std::fs::rename(path,path.with_extension("previous.jsonl"))?;}
    let mut o=std::fs::OpenOptions::new();o.create(true).append(true);
    #[cfg(unix)] {use std::os::unix::fs::OpenOptionsExt;o.mode(0o600);
        #[cfg(target_os="macos")] o.custom_flags(0x100);
        #[cfg(target_os="linux")] o.custom_flags(0x20000);}
    let mut f=o.open(path)?;f.write_all(line.as_bytes())?;f.flush()
}
#[cfg(test)]mod tests {
 use super::*;
 #[test]fn excludes_credentials_urls_ip_and_arbitrary_error_text(){let x=safe("vpn.result",&json!({"err":"https://user:password@example.test/sub/secret token=SECRET","token":"SECRET","path":"trojan@192.0.2.1","attempt_id":"SECRET","helper":{"token":"SECRET"}}),"abc").to_string();assert!(!x.contains("SECRET")&&!x.contains("password")&&!x.contains("192.0.2.1")&&!x.contains("example.test"));assert!(x.contains("trojan"));}
 #[test]fn classifies_failures_without_copying_payload(){assert_eq!(reason("timeout at secret"),"Нет ответа в отведённое время");assert_eq!(protocol("unexpected-secret"),"unknown");}
 #[test]fn engine_errors_are_fixed_categories_only(){
  for (raw,code) in [("TLS handshake failed at https://user:SECRET@example.test", "ENGINE_TLS"),("dial tcp: i/o timeout token=SECRET", "ENGINE_TIMEOUT"),("authentication failed password=SECRET", "ENGINE_AUTH"),("DNS lookup failed example.test", "ENGINE_DNS"),("network is unreachable", "ENGINE_ROUTE"),("read: connection reset by peer", "ENGINE_CONNECTION")] {
   let found=engine_error(raw.as_bytes()).unwrap();assert_eq!(found,code);
   let row=safe("vpn.engine_error",&json!({"component":"engine","error_code":found}),"abc").to_string();
   assert!(!row.contains("SECRET")&&!row.contains("example.test"));assert!(row.contains(code));
  }
  assert_eq!(engine_error(b"TLS started successfully"),None);
  assert_eq!(engine_error(&[255,254,0]),None);
  assert!(safe("vpn.engine_error",&json!({"component":"SECRET","error_code":"SECRET"}),"abc").get("error_code").is_none());
 }
 #[test]fn persists_and_rotates(){let p=std::env::temp_dir().join(format!("vpn-journal-{}",std::process::id()));let _=std::fs::remove_file(&p);append(&p,"one\n").unwrap();append(&p,"two\n").unwrap();assert_eq!(std::fs::read_to_string(&p).unwrap(),"one\ntwo\n");std::fs::OpenOptions::new().write(true).open(&p).unwrap().set_len(LIMIT).unwrap();append(&p,"new\n").unwrap();assert_eq!(std::fs::read_to_string(&p).unwrap(),"new\n");assert!(p.with_extension("previous.jsonl").exists());std::fs::remove_file(&p).unwrap();std::fs::remove_file(p.with_extension("previous.jsonl")).unwrap();}
}
