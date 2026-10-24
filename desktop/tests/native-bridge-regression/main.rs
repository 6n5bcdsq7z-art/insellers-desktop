use std::sync::Mutex;
const HOST:&str="vpn.insellers.su";
fn prefs()->serde_json::Value{serde_json::json!({})}
fn install_id()->String{"fixture".into()}
fn host_model()->String{"fixture".into()}
fn guest_until()->u64{0}
mod naive { pub fn available()->bool{true} pub fn available_protocol(k:&str)->bool{matches!(k,"tuic"|"mieru"|"anytls")} }
include!(concat!(env!("OUT_DIR"), "/gate.rs"));
include!(concat!(env!("OUT_DIR"), "/bridge.rs"));
include!(concat!(env!("OUT_DIR"), "/status.rs"));
fn main(){
 let nonce=new_bridge_nonce().unwrap();let next=new_bridge_nonce().unwrap();assert_eq!(nonce.len(),64);assert_ne!(nonce,next);
 let good=format!("https://{HOST}/__native/vpn_disconnect?n={nonce}&a=%7B%7D");
 let accepts=|s:&str|native_request_nonce_ok(&url::Url::parse(s).unwrap(),&nonce);
 assert!(accepts(&good));
 for bad in [format!("https://{HOST}/__native/vpn_disconnect"),good.replace(&nonce,"wrong"),good.replace(&nonce,&next),format!("{good}&n={nonce}"),format!("{good}&n=wrong"),good.replace("https:","http:"),good.replace(HOST,"ads.example"),good.replace(HOST,"vpn.insellers.su.evil.example"),good.replace(HOST,"vpn.insellers.su:444"),good.replace("/__native/","/other/")] {assert!(!accepts(&bad));}
 assert!(!native_request_nonce_ok(&url::Url::parse(&good).unwrap(),""));
 assert!(accepts(&good.replace("vpn_disconnect","page_alive")));
 std::fs::write(std::env::args().nth(1).expect("output fixture path"),init_script("fixture.token.value","1.0.fixture",&nonce)).unwrap();
 let mut scripts=vec![replay_status_script()];
 scripts.push(publish_status("connecting","","","selected_tuic",true).unwrap());
 scripts.push(publish_status("connected","","","naive",true).unwrap());
 assert_eq!(scripts.last().unwrap(), &replay_status_script());
 scripts.push(publish_status("degraded","failed","","tuic",true).unwrap());
 assert!(publish_status("connected","","","tuic",false).is_none());
 assert_eq!(scripts.last().unwrap(), &replay_status_script());
 scripts.push(publish_status("connected","","","tuic",true).unwrap());
 scripts.push(publish_status("disconnected","","","tuic",false).unwrap());
 scripts.push(publish_status("connected","","","tuic\";window.pwned=1;//",true).unwrap());
 let out=std::env::args().nth(1).unwrap()+".status.json";std::fs::write(out,serde_json::to_string(&scripts).unwrap()).unwrap();
 println!("14 actual-source nonce checks and verified runtime snapshot transitions PASS");
}
