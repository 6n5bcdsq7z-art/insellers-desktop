const HOST:&str="vpn.insellers.su";
fn prefs()->serde_json::Value{serde_json::json!({})}
fn install_id()->String{"fixture".into()}
fn host_model()->String{"fixture".into()}
fn guest_until()->u64{0}
include!(concat!(env!("OUT_DIR"), "/gate.rs"));
include!(concat!(env!("OUT_DIR"), "/bridge.rs"));
fn main(){
 let nonce=new_bridge_nonce().unwrap();let next=new_bridge_nonce().unwrap();assert_eq!(nonce.len(),64);assert_ne!(nonce,next);
 let good=format!("https://{HOST}/__native/vpn_disconnect?n={nonce}&a=%7B%7D");
 let accepts=|s:&str|native_request_nonce_ok(&url::Url::parse(s).unwrap(),&nonce);
 assert!(accepts(&good));
 for bad in [format!("https://{HOST}/__native/vpn_disconnect"),good.replace(&nonce,"wrong"),good.replace(&nonce,&next),format!("{good}&n={nonce}"),format!("{good}&n=wrong"),good.replace("https:","http:"),good.replace(HOST,"ads.example"),good.replace(HOST,"vpn.insellers.su.evil.example"),good.replace(HOST,"vpn.insellers.su:444"),good.replace("/__native/","/other/")] {assert!(!accepts(&bad));}
 assert!(!native_request_nonce_ok(&url::Url::parse(&good).unwrap(),""));
 assert!(accepts(&good.replace("vpn_disconnect","page_alive")));
 std::fs::write(std::env::args().nth(1).expect("output fixture path"),init_script("fixture.token.value","1.0.fixture",&nonce)).unwrap();
 println!("14 actual-source native nonce checks PASS");
}
