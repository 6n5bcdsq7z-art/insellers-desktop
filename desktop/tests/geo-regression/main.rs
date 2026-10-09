#![allow(dead_code)]
use std::{path::PathBuf,time::Duration};
extern crate self as tauri;
pub mod async_runtime {pub use tokio::{spawn,task::spawn_blocking};}
struct AppHandle;
const BASE:&str="http://127.0.0.1:9";
fn http()->Result<reqwest::Client,reqwest::Error>{reqwest::Client::builder().no_proxy().timeout(Duration::from_millis(50)).build()}
#[path="../../src-tauri/src/private_file.rs"] mod private_file;
include!(concat!(env!("OUT_DIR"),"/geo.rs"));
static STARTED:std::sync::atomic::AtomicUsize=std::sync::atomic::AtomicUsize::new(0);
async fn barrier(){ STARTED.fetch_add(1,std::sync::atomic::Ordering::SeqCst);while STARTED.load(std::sync::atomic::Ordering::SeqCst)<2{tokio::task::yield_now().await;} }
async fn sub_url(_: &reqwest::Client,_:&str)->Result<String,String>{barrier().await;Ok("fixture".into())}
async fn transport_choice(_: &reqwest::Client,_:&str)->String{barrier().await;"manual".into()}
include!(concat!(env!("OUT_DIR"),"/bootstrap.rs"));
const HTTP_PORT:u16=9;
static PROBES:std::sync::Mutex<std::collections::VecDeque<(bool,u64,u64,String)>>=std::sync::Mutex::new(std::collections::VecDeque::new());
async fn probe_real_t(_:&str,_:u64)->(bool,u64,u64,String){PROBES.lock().unwrap().pop_front().expect("unexpected extra probe")}
include!(concat!(env!("OUT_DIR"),"/connection.rs"));
#[tokio::main]async fn main(){
 for (first,second,expected) in [("ok","timeout",false),("timeout","ok",false),("timeout","timeout",true),("http 502","timeout",false),("core","timeout",false)] {
 *PROBES.lock().unwrap()=[first,second].into_iter().map(|r|(r=="ok",0,0,r.into())).collect();assert_eq!(freeze_confirmed().await,expected);
 }
 let deadline_start=std::time::Instant::now();assert!(!link_ok_within(1).await);assert!(deadline_start.elapsed()<Duration::from_millis(1300),"deadline overshot");
 let result=tokio::time::timeout(Duration::from_secs(2),bootstrap(http().unwrap(),"fixture-token".into())).await.unwrap();assert_eq!(result,(Ok("fixture".into()),"manual".into()));
 let dir=tempfile::tempdir().unwrap();let path=dir.path().to_path_buf();
 for n in ["geoip.dat","geosite.dat"] {std::fs::write(path.join(n),vec![7;2048]).unwrap();std::fs::File::open(path.join(n)).unwrap().set_modified(std::time::UNIX_EPOCH).unwrap();}
 let t=std::time::Instant::now();assert!(ensure_geo(&AppHandle,&path).await);assert!(t.elapsed()<Duration::from_millis(100));
 tokio::time::sleep(Duration::from_millis(150)).await;assert!(!GEO_UPDATING.load(std::sync::atomic::Ordering::SeqCst));
 for n in ["geoip.dat","geosite.dat"] {assert_eq!(std::fs::read(path.join(n)).unwrap(),vec![7;2048]);}
 std::fs::remove_file(path.join("geosite.dat")).unwrap();assert!(!ensure_geo(&AppHandle,&path).await);
 assert!(private_file::write_private_bytes(&path.join("geosite.dat"),&vec![8;3000]));assert!(ensure_geo(&AppHandle,&path).await);
 println!("PASS actual Desktop geo: stale cache immediate, failed refresh preserves files, missing file honest, atomic binary replacement");
}
