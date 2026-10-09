use std::{env,fs,path::PathBuf};
fn main(){let src=PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap()).join("../../src-tauri/src/vpn.rs");println!("cargo:rerun-if-changed={}",src.display());let s=fs::read_to_string(src).unwrap();let a=s.find("static GEO_UPDATING:").unwrap();let b=a+s[a..].find("/// Убираем правила").unwrap();fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("geo.rs"),&s[a..b]).unwrap();
let m=s.find("fn is_hy(").unwrap();let n=m+s[m..].find("/// Видео").unwrap();fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("choice.rs"),&s[m..n]).unwrap();
let x=s.find("fn subscription_mirror(").unwrap();let y=x+s[x..].find("/// Кандидаты для подключения:").unwrap();
fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("subscription.rs"),&s[x..y]).unwrap();
let a=s.find("    let (subscription, requested_choice) =").unwrap();let b=a+s[a..].find("    let (url, until)").unwrap();
fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("bootstrap.rs"),format!("async fn bootstrap(client:reqwest::Client,token:String)->(Result<String,String>,String){{{} (subscription,requested_choice)}}",&s[a..b])).unwrap();let a=s.find("async fn link_ok_within(").unwrap();let b=a+s[a..].find("/// Есть ли интернет").unwrap();
let c=s.find("async fn freeze_confirmed()").unwrap();let d=c+s[c..].find("async fn freeze_watch(").unwrap();
fs::write(PathBuf::from(env::var("OUT_DIR").unwrap()).join("connection.rs"),format!("{}\n{}",&s[a..b],&s[c..d])).unwrap();
}
