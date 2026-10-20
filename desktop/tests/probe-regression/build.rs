use std::{env,fs,path::PathBuf};
fn main() {
 let src=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../src-tauri/src/probe.rs");
 println!("cargo:rerun-if-changed={}",src.display());
 let s=fs::read_to_string(src).unwrap();let out=PathBuf::from(env::var("OUT_DIR").unwrap());
 let a=s.find("async fn get_via(").unwrap();let b=a+s[a..].find("\npub async fn run_variants").unwrap();
 fs::write(out.join("helper.rs"),format!("use std::time::{{Instant,Duration}};\n{}",&s[a..b])).unwrap();
 let a=s.find("pub async fn run_variants").unwrap();let a=a+s[a..].find("    for v in vs {").unwrap();let b=a+s[a..].find("    let _ = child.kill();").unwrap();
 fs::write(out.join("variants.rs"),format!("use serde_json::{{Value,json}};\nasync fn test_variants(vs:Vec<Value>,lat:&str,big:&str,want:usize)->Vec<Value>{{let mut out=Vec::new();\n{}\nout}}",&s[a..b])).unwrap();
 let vpn=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../src-tauri/src/vpn.rs");
 println!("cargo:rerun-if-changed={}",vpn.display());
 let v=fs::read_to_string(vpn).unwrap();
 let section=|start:&str,end:&str| {let a=v.find(start).unwrap();let b=a+v[a..].find(end).unwrap();v[a..b].to_owned()};
 let selection=section("fn is_hy(","/// Видео")+&section("fn fresh_last(","/// Ссылка на подписку")
     +&section("fn manual_choice(","/// Описание пути");
 fs::write(out.join("selection.rs"),format!("use serde_json::{{Value,json}};\n{}",selection)).unwrap();

 println!("cargo:rerun-if-env-changed=INSELLERS_VPN_CANCEL_SOURCE");
 let cancellation_src=env::var("INSELLERS_VPN_CANCEL_SOURCE").ok().map(|p|fs::read_to_string(p).unwrap()).unwrap_or(v);
 let section=|start:&str,end:&str| {let a=cancellation_src.find(start).unwrap();let b=a+cancellation_src[a..].find(end).unwrap();cancellation_src[a..b].to_owned()};
 let stop=section("pub fn stop(","/// Kept for the bridge");
 let status=section("                    let st = tauri::async_runtime::spawn_blocking(crate::tun::status)","\n                }");
 let finish_start=if cancellation_src.contains("    let transition = CONNECTION_TRANSITION.lock()") {"    let transition = CONNECTION_TRANSITION.lock()"}else{"    if !tun_on {"};
 let finish=section(finish_start,"\n    // 5) Monitor our own tunnel");
 let final_a=cancellation_src.rfind("\n    });\n").unwrap()+"\n    });\n".len();
 let final_b=cancellation_src.rfind("\n}").unwrap();
 let final_return=&cancellation_src[final_a..final_b];
 let actual=format!("{stop}\nasync fn finish_start(app:AppHandle,my_gen:u32,await_status:bool,tun_on:bool)->Result<(),String>{{let why=String::from(\"fixture failure\");let until=0;\nif await_status {{\n{status}\n}}\n{finish}\ntest_platform::after_transition();\n{final_return}\n}}");
 let actual=actual.replace("tauri::async_runtime::spawn_blocking", "tokio::task::spawn_blocking")
     .replace("crate::tun::", "test_platform::tun::")
     .replace("crate::telemetry::", "test_platform::telemetry::")
     .replace("crate::remote_log", "test_platform::remote_log")
     .replace("crate::now_ms", "test_platform::now_ms")
     .replace("std::thread::sleep", "test_platform::sleep");
 fs::write(out.join("cancellation.rs"),actual).unwrap();

}
