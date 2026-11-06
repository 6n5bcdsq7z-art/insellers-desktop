"""Test the real private journal and protocol labels without an app or VPN."""
from pathlib import Path
import subprocess,tempfile
root=Path(__file__).resolve().parents[2]
s=(root/'src-tauri/src/vpn.rs').read_text()
def function(name):
 a=s.index('fn '+name+'(');end=s.index('{',a)+1;depth=1
 while depth:
  depth+=(s[end]=='{')-(s[end]=='}');end+=1
 return s[a:end]
with tempfile.TemporaryDirectory(prefix='vpn-journal-tests-') as temp:
 p=Path(temp);(p/'src').mkdir()
 (p/'Cargo.toml').write_text('[package]\nname="vpn-journal-tests"\nversion="0.1.0"\nedition="2021"\n[dependencies]\nserde_json="1"\n')
 src='use serde_json::{Value,json};\n#[path='+__import__('json').dumps(str(root/'src-tauri/src/connection_journal.rs'))+']\nmod connection_journal;\n'
 src+='\n'.join(function(x) for x in ['is_hy','is_proxy','net_of','path_tag','path_desc','record_engine_error'])
 src+='''
use std::sync::Mutex;
struct Child(u32);impl Child{fn pid(&self)->u32{self.0}}
struct VpnState{child:Mutex<Option<Child>>,router:Mutex<Option<Child>>}
struct AppHandle(VpnState);impl AppHandle{fn state<T>(&self)->&VpnState{&self.0}}
static EVENTS:Mutex<Vec<Value>>=Mutex::new(Vec::new());
fn remote_log(_: &str,data:Value){EVENTS.lock().unwrap().push(data);}
#[test]fn engine_events_ignore_replaced_process_and_bound_duplicates(){
 EVENTS.lock().unwrap().clear();
 let app=AppHandle(VpnState{child:Mutex::new(Some(Child(7))),router:Mutex::new(Some(Child(8)))});
 let mut seen=std::collections::BTreeSet::new();
 record_engine_error(&app,6,false,b"i/o timeout SECRET",&mut seen);
 assert!(EVENTS.lock().unwrap().is_empty());
 record_engine_error(&app,7,false,b"i/o timeout SECRET",&mut seen);
 record_engine_error(&app,7,false,b"i/o timeout SECRET",&mut seen);
 record_engine_error(&app,7,true,b"TLS handshake failed SECRET",&mut seen);
 assert_eq!(EVENTS.lock().unwrap().len(),1);
 record_engine_error(&app,8,true,b"TLS handshake failed SECRET",&mut seen);
 let events=EVENTS.lock().unwrap();assert_eq!(events.len(),2);
 assert_eq!(events[0]["component"],"engine");assert_eq!(events[1]["component"],"router");
 assert!(!serde_json::to_string(&*events).unwrap().contains("SECRET"));
}
#[test]fn actual_protocol_labels_are_not_all_reality(){
 for (protocol,network,security,want) in [("trojan","tcp","tls","trojan"),("vmess","ws","tls","vmess"),("vless","tcp","reality","reality"),("vless","xhttp","reality","xhttp"),("vless","tcp","tls","vless")] {
 let c=json!({"outbounds":[{"tag":"proxy","protocol":protocol,"settings":{"servers":[{"address":"192.0.2.1"}]},"streamSettings":{"network":network,"security":security}}]});
 assert_eq!(path_desc(&c),format!("{want}@192.0.2.1"));
 }
}
'''
 (p/'src/lib.rs').write_text(src)
 subprocess.run(['cargo','test','--quiet','--manifest-path',str(p/'Cargo.toml')],check=True)
