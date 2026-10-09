#![allow(dead_code)]
extern crate self as tauri;
pub mod async_runtime {pub fn block_on<F: std::future::Future>(_: F)->F::Output {panic!("background networking disabled in offline regression")}}
use std::sync::Mutex;
static LOG_QUEUE:Mutex<Vec<serde_json::Value>>=Mutex::new(Vec::new());
static ROOT:Mutex<Option<std::path::PathBuf>>=Mutex::new(None);
static TOKEN:Mutex<String>=Mutex::new(String::new());
const BASE:&str="https://vpn.insellers.su";
const BASE_ALT:&str="https://n2.insellers.su";
fn data_path(name:&str)->Option<std::path::PathBuf>{ROOT.lock().unwrap().as_ref().map(|p|p.join(name))}
fn load_token()->String{TOKEN.lock().unwrap().clone()}
fn new_bridge_nonce()->Result<String,()>{Ok("a".repeat(64))}
fn now_ms()->u64{123000}
#[path="../../src-tauri/src/private_file.rs"] mod private_file;
fn write_private(p:&std::path::Path,s:&str)->bool{private_file::write_private(p,s)}
#[path="../../src-tauri/src/failure_reports.rs"] mod failure_reports;
#[test] fn durable_deduplication_and_account_binding(){
 let dir=tempfile::tempdir().unwrap();*ROOT.lock().unwrap()=Some(dir.path().into());*TOKEN.lock().unwrap()="fixture-token".into();
 let body=serde_json::json!({"text":"startup failed","diag":{}});
 assert!(failure_reports::enqueue(body.clone()));
 let path=data_path("pending-failure.json").unwrap();let original=std::fs::read_to_string(&path).unwrap();
 assert!(!original.contains("fixture-token"));assert!(original.contains("occurred_at"));
 assert!(failure_reports::enqueue(serde_json::json!({"text":"second tap","diag":{}})));
 assert_eq!(original,std::fs::read_to_string(&path).unwrap());
 *TOKEN.lock().unwrap()="different-account".into();assert!(!failure_reports::enqueue(body.clone()));
 assert_eq!(original,std::fs::read_to_string(&path).unwrap());
 std::fs::write(&path,"broken").unwrap();assert!(!failure_reports::enqueue(body));
}
