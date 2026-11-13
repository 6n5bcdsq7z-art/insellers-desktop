//! Startup complaint delivery survives process restarts. No credentials in the outbox.
use std::sync::Mutex;
use serde_json::{Value,json};
static LOCK: Mutex<()> = Mutex::new(());
static AUTO_LOCK: Mutex<()> = Mutex::new(());
static SENDING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn owner(token: &str) -> String {
    ring::digest::digest(&ring::digest::SHA256, token.as_bytes()).as_ref().iter().map(|b|format!("{b:02x}")).collect()
}
pub fn enqueue(mut body: Value) -> bool {
    let Ok(_guard)=LOCK.lock() else {return false};
    let Some(path)=crate::data_path("pending-failure.json") else {return false};
    if path.exists() {return std::fs::read_to_string(&path).ok().and_then(|v|serde_json::from_str::<Value>(&v).ok()).map(|v|v["owner"]==owner(&crate::load_token())).unwrap_or(false)}
    let Ok(id)=crate::new_bridge_nonce() else {return false};
    body["request_id"]=json!(id);
    body["diag"]["occurred_at"]=json!(crate::now_ms()/1000);
    body["diag"]["events"]=json!(crate::LOG_QUEUE.lock().map(|q|q.iter().rev().take(60).map(|e|json!({"ts":e["ts"],"ev":e["ev"],"n":e["n"]})).collect::<Vec<_>>()).unwrap_or_default());
    if body.to_string().len()>56000{return false}
    crate::write_private(&path,&json!({"owner":owner(&crate::load_token()),"body":body}).to_string())
}
/// Keep the existing receipt unchanged and limit automatic incidents per account/version/kind.
pub fn enqueue_automatic(kind: &str, body: Value) -> Option<bool> {
    let Ok(_guard) = AUTO_LOCK.lock() else {return Some(false)};
    let Some(path) = crate::data_path("failure-cooldown.json") else {return Some(false)};
    let mut times: serde_json::Map<String, Value> = std::fs::read_to_string(&path).ok()
        .and_then(|s| serde_json::from_str(&s).ok()).unwrap_or_default();
    let key = owner(&format!("{}:{}:{kind}", crate::load_token(), env!("CARGO_PKG_VERSION")));
    let now = crate::now_ms();
    let before = times.get(&key).and_then(Value::as_u64).unwrap_or(0);
    if before > 0 && now >= before && now - before < 600_000 {return None}
    let existed = crate::data_path("pending-failure.json").map(|p|p.exists()).unwrap_or(false);
    let saved = enqueue(body);
    if saved && !existed {
        times.retain(|_, v| v.as_u64().map(|at| now.saturating_sub(at) < 600_000).unwrap_or(false));
        times.insert(key, json!(now));
        crate::write_private(&path, &serde_json::to_string(&times).unwrap_or_default());
    }
    Some(saved)
}

pub fn connection_failure(stage: &str, protocol: &str, attempt: &str, cause: &str) {
    fn identifier(s: &str) -> String {
        if !s.is_empty() && s.len() <= 64 && s.bytes().all(|c|c.is_ascii_alphanumeric() || b"_.:-".contains(&c)) {s.into()}
        else {"unknown".into()}
    }
    let stage = if ["config","dns","tcp","tls","handshake","tunnel","traffic","disconnect"].contains(&stage) {stage} else {"unknown"}.to_string();
    let protocol = identifier(protocol); let cause = identifier(cause);
    let attempt: String = attempt.chars().take(32).collect();
    std::thread::spawn(move || {
        let body = json!({"text":"Сбой подключения VPN","n_img":0,"diag":{
            "platform":std::env::consts::OS,"version":env!("CARGO_PKG_VERSION"),"automatic":true,
            "failure_stage":stage,"error_code":cause,"protocol":protocol,"attempt_id":attempt}});
        if enqueue_automatic(&format!("vpn:{protocol}:{stage}"), body) == Some(true) {
            tauri::async_runtime::block_on(flush());
        }
    });
}
pub async fn flush() -> bool {
    use std::sync::atomic::Ordering;
    if SENDING.swap(true,Ordering::SeqCst) {return false}
    struct Done;
    impl Drop for Done {fn drop(&mut self){SENDING.store(false,Ordering::SeqCst);}}
    let _done=Done;
    let Some(path)=crate::data_path("pending-failure.json") else {return false};
    let Ok(raw)=std::fs::read_to_string(&path) else {return false};
    let Ok(entry)=serde_json::from_str::<Value>(&raw) else {return false};
    // Reports saved before login retain their anonymous identity.
    let token=if entry["owner"]==owner("") {String::new()} else {crate::load_token()};
    if entry["owner"].as_str()!=Some(owner(&token).as_str()) {return false}
    let body=&entry["body"];
    // The primary website follows its current DNS entry. Pinning the former
    // Hetzner address bypassed the recovered public ingress and broke reports.
    // Keep an independent pinned backup for DNS failures, with TLS verification.
    for (base,backup) in [(crate::BASE,None),(crate::BASE_ALT,Some(("n2.insellers.su","212.34.151.212")))] {
        let mut builder=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(5)).timeout(std::time::Duration::from_secs(12));
        if let Some((host,ip))=backup {
            let Ok(addr)=format!("{ip}:443").parse() else {continue};
            builder=builder.resolve(host,addr);
        }
        let Ok(client)=builder.build() else {continue};
        let mut request=client.post(format!("{base}/api/app/failure")).json(body);
        if !token.is_empty(){request=request.header("X-App-Token",&token);}
        let Ok(response)=request.send().await else {continue};
        if !response.status().is_success(){continue}
        let Ok(ack)=response.json::<Value>().await else {continue};
        if ack["ok"]==true && ack["queued"]==true && ack["id"].as_u64().unwrap_or(0)>0 && ack["request_id"]==body["request_id"] {
            let Ok(_guard)=LOCK.lock() else {return false};
            if std::fs::read_to_string(&path).ok().as_deref()==Some(raw.as_str()) {return std::fs::remove_file(path).is_ok()}
        }
    }
    false
}
pub fn start() {
    std::thread::spawn(|| {
        let mut delay=15;
        loop {
            let sent=tauri::async_runtime::block_on(flush());
            delay=if sent {15} else {(delay*2).min(300)};
            std::thread::sleep(std::time::Duration::from_secs(delay));
        }
    });
}
