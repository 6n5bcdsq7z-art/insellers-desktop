use std::{future::Future, pin::Pin, task::{Context, Poll, Wake, Waker}};
fn poll<F:Future>(mut future:Pin<&mut F>)->Poll<F::Output> {
    struct N; impl Wake for N {fn wake(self:std::sync::Arc<Self>){}}
    let w=Waker::from(std::sync::Arc::new(N)); future.as_mut().poll(&mut Context::from_waker(&w))
}
fn ready<F:Future>(future:F)->F::Output {
    let mut f=std::pin::pin!(future);
    for _ in 0..100 {if let Poll::Ready(x)=poll(f.as_mut()){return x;}}
    panic!("operation never completed")
}
macro_rules! json {($($t:tt)*)=>{()};}
mod retry {
 use super::*;
 use std::{sync::{Arc,Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}},time::Duration};
 #[derive(Clone)] struct AppHandle {wanted:Arc<AtomicBool>,calls:Arc<AtomicUsize>,events:Arc<Mutex<Vec<String>>>}
 static MODE:Mutex<&str>=Mutex::new("");
 fn wanted(a:&AppHandle)->bool {a.wanted.load(Ordering::SeqCst)}
 fn run_inline(f:impl FnOnce()){f()}
 fn now_ms()->u64{0}
 fn remote_log(_: &str,_:()){}
 fn notify(a:&AppHandle,s:&str,_:&str){a.events.lock().unwrap().push(s.into());}
 fn test_sleep(_:Duration){if ["stop_while_waiting","new_manual_connect"].contains(&*MODE.lock().unwrap()){cancel_reconnect();}}
 async fn start(a:AppHandle)->Result<(),String>{
   let n=a.calls.fetch_add(1,Ordering::SeqCst); let mode=*MODE.lock().unwrap();
   if n==0 {
     a.wanted.store(false,Ordering::SeqCst); // start_once's internal stop_transport
     if mode=="cancel_during_start" {cancel_reconnect();}
     return Err(match mode {"busy"=>"BUSY","cancelled"=>"CANCELLED",_=>"Выбранный протокол не передаёт данные"}.into());
   }
   a.wanted.store(true,Ordering::SeqCst);Ok(())
 }
 async fn tunnel_check()->(bool,u64,String){(*MODE.lock().unwrap()!="probe_failed",1,String::new())}
 mod tauri {pub mod async_runtime {pub fn block_on<F:std::future::Future>(f:F)->F::Output{super::super::super::ready(f)}}}
 // ACTUAL_RETRY
 fn fixture(mode:&'static str)->AppHandle{*MODE.lock().unwrap()=mode;AppHandle{wanted:Arc::new(AtomicBool::new(true)),calls:Arc::new(AtomicUsize::new(0)),events:Arc::new(Mutex::new(vec![]))}}
 #[test] fn transient_failure_after_teardown_retries_and_connects(){
   let a=fixture("recover");reconnect_retry(&a,0,"health");
   assert_eq!(a.calls.load(Ordering::SeqCst),2,"cleanup must not cancel retry intent");
   assert_eq!(a.events.lock().unwrap().last().unwrap(),"connected");
 }
 #[test] fn explicit_stop_or_new_manual_connect_cancels_wait(){
   for mode in ["stop_while_waiting","new_manual_connect"]{let a=fixture(mode);reconnect_retry(&a,0,"health");assert_eq!(a.calls.load(Ordering::SeqCst),1);}
 }
 #[test] fn stop_during_failed_start_does_not_publish_stale_wait(){
   let a=fixture("cancel_during_start");reconnect_retry(&a,0,"health");assert!(a.events.lock().unwrap().is_empty());
 }
 #[test] fn no_recovery_when_already_stopped(){let a=fixture("");a.wanted.store(false,Ordering::SeqCst);reconnect_retry(&a,0,"health");assert_eq!(a.calls.load(Ordering::SeqCst),0);}
 #[test] fn busy_or_cancelled_start_not_retried(){for mode in ["busy","cancelled"]{let a=fixture(mode);reconnect_retry(&a,0,"health");assert_eq!(a.calls.load(Ordering::SeqCst),1);assert!(a.events.lock().unwrap().is_empty());}}
 #[test] fn failed_post_start_probe_never_claims_connected(){let a=fixture("probe_failed");reconnect_retry(&a,0,"health");let e=a.events.lock().unwrap();assert!(!e.iter().any(|x|x=="connected"));assert_eq!(e.last().unwrap(),"error");}
}
mod request {
 use super::*;
 use std::sync::{Mutex,atomic::{AtomicBool,AtomicUsize,Ordering}};
 #[derive(Clone)] struct AppHandle;
 struct Window;
 impl AppHandle {fn get_webview_window(&self,_:&str)->Option<Window>{Some(Window)}}
 impl Window {fn eval(&self,_:&str)->Result<(),()>{REPLAYS.fetch_add(1,Ordering::SeqCst);Ok(())}}
 static REPLAYS:AtomicUsize=AtomicUsize::new(0);
 static STARTS:AtomicUsize=AtomicUsize::new(0);
 static STOPPED:AtomicUsize=AtomicUsize::new(0);
 static RELEASE:AtomicBool=AtomicBool::new(false);
 static EVENTS:Mutex<Vec<String>>=Mutex::new(vec![]);
 fn vpn_running(_: &AppHandle)->bool{false}
 fn remote_log(_: &str,_:()){}
 struct Sleep(bool);impl Future for Sleep {type Output=();fn poll(mut self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<()>{if self.0{Poll::Ready(())}else{self.0=true;Poll::Pending}}}
 async fn tokio_sleep(_:u64){Sleep(false).await}
 mod telemetry {pub async fn captive()->bool{false}pub fn attempt(_: &str){}pub fn result(_: &str,_:&str,_:&str){}pub fn set_stop_reason(_: &str){}}
 mod vpn {
  use super::*;
  pub fn cancel_reconnect(){}
  pub fn replay_status_script()->String{String::new()}
  pub fn take_connect_msg()->String{String::new()}
  pub fn notify(_: &AppHandle,s:&str,_:&str){EVENTS.lock().unwrap().push(s.into());}
  pub fn notify_code(a:&AppHandle,s:&str,m:&str,_:&str){notify(a,s,m)}
  pub fn set_wanted(_: &AppHandle,_:bool){}
  pub fn stop(_: &AppHandle){STOPPED.fetch_add(1,Ordering::SeqCst);}
  struct Start {first:bool,stopped:usize}
  impl Future for Start {type Output=Result<(),String>;fn poll(self:Pin<&mut Self>,_:&mut Context<'_>)->Poll<Self::Output>{
    if self.first&&!RELEASE.load(Ordering::SeqCst){return Poll::Pending;}
    Poll::Ready(if STOPPED.load(Ordering::SeqCst)!=self.stopped{Err("CANCELLED".into())}else{Ok(())})
  }}
  pub async fn start(_:AppHandle)->Result<(),String>{let first=STARTS.fetch_add(1,Ordering::SeqCst)==0;Start{first,stopped:STOPPED.load(Ordering::SeqCst)}.await}
  pub async fn start_user(a:AppHandle)->Result<(),String>{start(a).await}
 }
 // ACTUAL_REQUEST
 fn reset(){CONNECT_REQUEST.store(false,Ordering::SeqCst);STARTS.store(0,Ordering::SeqCst);STOPPED.store(0,Ordering::SeqCst);RELEASE.store(false,Ordering::SeqCst);REPLAYS.store(0,Ordering::SeqCst);EVENTS.lock().unwrap().clear();}
 #[test] fn duplicate_click_replays_state_without_duplicate_start(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());
   assert_eq!(ready(vpn_connect_mode(AppHandle,true)),Err("BUSY".into()));assert_eq!(STARTS.load(Ordering::SeqCst),1);assert_eq!(REPLAYS.load(Ordering::SeqCst),1);
   RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(first),Ok(()));
 }
 #[test] fn connect_after_cancel_waits_for_previous_request_then_starts(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   let mut next=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(next.as_mut()).is_pending(),"new Connect must not be dropped as BUSY");
   RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(first),Err("CANCELLED".into()));assert_eq!(ready(next),Ok(()));assert_eq!(STARTS.load(Ordering::SeqCst),2);
 }
 #[test] fn stop_cancels_a_queued_connect(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   let mut next=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(next.as_mut()).is_pending());vpn_disconnect(AppHandle);
   assert_eq!(ready(next),Err("CANCELLED".into()));RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(first),Err("CANCELLED".into()));assert_eq!(STARTS.load(Ordering::SeqCst),1);
 }
 #[test] fn queued_duplicate_clicks_launch_only_once(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   let mut next=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(next.as_mut()).is_pending());let mut duplicate=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(duplicate.as_mut()).is_pending());
   RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(first),Err("CANCELLED".into()));
   // Hold the next request in startup so the second click sees the same attempt.
   STARTS.store(0,Ordering::SeqCst);RELEASE.store(false,Ordering::SeqCst);assert!(poll(next.as_mut()).is_pending());assert_eq!(ready(duplicate),Err("BUSY".into()));
   RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(next),Ok(()));assert_eq!(STARTS.load(Ordering::SeqCst),1);
 }
 #[test] fn queued_duplicate_does_not_restart_a_fast_completed_connection(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   let mut next=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(next.as_mut()).is_pending());let mut duplicate=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(duplicate.as_mut()).is_pending());
   RELEASE.store(true,Ordering::SeqCst);assert_eq!(ready(first),Err("CANCELLED".into()));assert_eq!(ready(next),Ok(()));assert_eq!(ready(duplicate),Err("BUSY".into()));assert_eq!(STARTS.load(Ordering::SeqCst),2);
 }
 #[test] fn stop_on_last_wait_tick_does_not_publish_a_stale_timeout(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   let mut next=std::pin::pin!(vpn_connect_mode(AppHandle,true));for _ in 0..40 {assert!(poll(next.as_mut()).is_pending());}
   vpn_disconnect(AppHandle);assert_eq!(ready(next),Err("CANCELLED".into()));assert_eq!(EVENTS.lock().unwrap().last().unwrap(),"disconnected");
 }
 #[test] fn old_request_that_never_finishes_has_visible_bounded_error(){
   reset();let mut first=std::pin::pin!(vpn_connect_mode(AppHandle,true));assert!(poll(first.as_mut()).is_pending());vpn_disconnect(AppHandle);
   assert_eq!(ready(vpn_connect_mode(AppHandle,true)),Err("BUSY_TIMEOUT".into()));assert_eq!(EVENTS.lock().unwrap().last().unwrap(),"error");assert_eq!(STARTS.load(Ordering::SeqCst),1);
 }
}
