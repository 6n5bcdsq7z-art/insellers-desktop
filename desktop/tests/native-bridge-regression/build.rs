use std::{env,fs,path::PathBuf};
fn main() {
 let src=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../src-tauri/src/main.rs");
 println!("cargo:rerun-if-changed={}",src.display());
 let s=fs::read_to_string(src).unwrap();let out=PathBuf::from(env::var("OUT_DIR").unwrap());
 let a=s.find("fn native_request_nonce_ok(").unwrap();let b=a+s[a..].find("\nfn build_main(").unwrap();
 fs::write(out.join("gate.rs"),&s[a..b]).unwrap();
 let a=s.find("fn init_script(").unwrap();let b=a+s[a..].find("\n// 29.09 (владелец): Windows").unwrap();
 fs::write(out.join("bridge.rs"),&s[a..b]).unwrap();
 let guard=s.find("if !native_request_nonce_ok(u, &bridge_nonce) { return false; }").unwrap();
 let dispatch=s[guard..].find("native_cmd(h, &cmd, arg)").unwrap();assert!(dispatch>0);
}
