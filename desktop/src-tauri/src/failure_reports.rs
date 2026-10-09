//! Startup complaint delivery survives process restarts. No credentials in the outbox.
use std::sync::Mutex;
use serde_json::{Value,json};
static LOCK: Mutex<()> = Mutex::new(());
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
pub async fn flush() -> bool {
    use std::sync::atomic::Ordering;
    if SENDING.swap(true,Ordering::SeqCst) {return false}
    struct Done;
    impl Drop for Done {fn drop(&mut self){SENDING.store(false,Ordering::SeqCst);}}
    let _done=Done;
    let Some(path)=crate::data_path("pending-failure.json") else {return false};
    let Ok(raw)=std::fs::read_to_string(&path) else {return false};
    let Ok(entry)=serde_json::from_str::<Value>(&raw) else {return false};
    let token=crate::load_token();
    if entry["owner"].as_str()!=Some(owner(&token).as_str()) {return false}
    let body=&entry["body"];
    // These IPs are also physical-route exceptions in tun::bypass_ips; no system proxy.
    for (base,host,ip) in [(crate::BASE,"vpn.insellers.su","46.224.14.67"),(crate::BASE_ALT,"n2.insellers.su","212.34.151.212")] {
        let Ok(addr)=format!("{ip}:443").parse() else {continue};
        let Ok(client)=reqwest::Client::builder().no_proxy().redirect(reqwest::redirect::Policy::none())
            .resolve(host,addr).connect_timeout(std::time::Duration::from_secs(5)).timeout(std::time::Duration::from_secs(12)).build() else {continue};
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
