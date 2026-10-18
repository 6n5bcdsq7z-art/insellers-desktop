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

}
