use std::sync::{Mutex,Arc,atomic::{AtomicBool,AtomicUsize,Ordering}};
type AppHandle=();
macro_rules! json { ($($t:tt)*) => { () }; }
fn remote_log(_: &str, _: ()) {}
static STARTING:AtomicBool=AtomicBool::new(false);
static MODE:AtomicUsize=AtomicUsize::new(0);
static GENERATION:AtomicUsize=AtomicUsize::new(0);
static EVENTS:Mutex<Vec<&'static str>>=Mutex::new(Vec::new());
struct StartGuard;
impl Drop for StartGuard{fn drop(&mut self){STARTING.store(false,Ordering::SeqCst);}}
mod vpn_handover {
 pub type Stopped=std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>;
 pub struct Mac;
 pub fn restore(_: &mut Mac, _: &[&str])->Result<(),String>{
  assert!(super::STARTING.load(super::Ordering::SeqCst),"rollback must keep duplicate-start lock");
  super::EVENTS.lock().unwrap().push("restore");
  if super::MODE.load(super::Ordering::SeqCst)==4 {Err("restore failed".into())}else{Ok(())}
 }
}
mod tauri {pub mod async_runtime{pub async fn spawn_blocking<F:FnOnce()->R,R>(f:F)->Result<R,()>{Ok(f())}}}
fn stop(_: &AppHandle){EVENTS.lock().unwrap().push("stop_ours");}
fn stop_transport(app: &AppHandle){GENERATION.fetch_add(1,Ordering::SeqCst);stop(app);}
fn cur_gen(_: &AppHandle)->usize{GENERATION.load(Ordering::SeqCst)}
fn notify(_: &AppHandle,_: &str,_: &str){}
async fn tokio_sleep(_:u64){}
async fn start_once(_:AppHandle, handover:Option<vpn_handover::Stopped>)->Result<(),String>{
 let mode=MODE.load(Ordering::SeqCst);
 if mode==3{return Err("BOOTSTRAP:fixture".into());}
 GENERATION.fetch_add(1,Ordering::SeqCst); // production start_once performs own cleanup
 if let Some(s)=handover{s.lock().unwrap().push("old VPN");EVENTS.lock().unwrap().push("handover");}
 match mode{0=>Ok(()),2=>Err("CANCELLED".into()),_=>Err("fixture connection failed".into())}
}
// ACTUAL_WRAPPER
fn run(mode:usize,user:bool)->(Result<(),String>,Vec<&'static str>){
 MODE.store(mode,Ordering::SeqCst);GENERATION.store(0,Ordering::SeqCst);STARTING.store(false,Ordering::SeqCst);EVENTS.lock().unwrap().clear();
 struct Wake;impl std::task::Wake for Wake{fn wake(self:Arc<Self>){}}
 let w=std::task::Waker::from(Arc::new(Wake));let mut cx=std::task::Context::from_waker(&w);
 let mut f=Box::pin(start_with_handover((),user));
 let result=loop{match std::future::Future::poll(f.as_mut(),&mut cx){std::task::Poll::Ready(r)=>break r,_=>std::thread::yield_now()}};
 assert!(!STARTING.load(Ordering::SeqCst));
 let events=EVENTS.lock().unwrap().clone();(result,events)
}
#[test]fn failure_stops_ours_before_restoring_previous(){let(r,e)=run(1,true);assert!(r.is_err());assert_eq!(e,vec!["handover","stop_ours","restore"]);}
#[test]fn success_keeps_previous_vpn_off(){let(r,e)=run(0,true);assert!(r.is_ok());assert_eq!(e,vec!["handover"]);}
#[test]fn background_retry_never_takes_over(){let(r,e)=run(1,false);assert!(r.is_err());assert!(e.is_empty());}
#[test]fn cancellation_never_resurrects_a_connection(){let(r,e)=run(2,true);assert_eq!(r,Err("CANCELLED".into()));assert_eq!(e,vec!["handover"]);}
#[test]fn configuration_failure_preserves_existing_vpn(){let(r,e)=run(3,true);assert!(r.unwrap_err().starts_with("BOOTSTRAP:"));assert!(e.is_empty());}
#[test]fn failed_restore_is_reported_honestly(){let(r,_)=run(4,true);assert!(r.unwrap_err().contains("restore failed"));}
