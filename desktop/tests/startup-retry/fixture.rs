use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

macro_rules! json { ($($value:tt)*) => { () } }
static STARTING: AtomicBool = AtomicBool::new(false);
static ACTIVE: Mutex<Option<AppHandle>> = Mutex::new(None);
struct StartGuard;
impl Drop for StartGuard { fn drop(&mut self) { STARTING.store(false, Ordering::SeqCst); } }
#[derive(Clone)]
struct AppHandle(Arc<State>);
struct State {
    generation: AtomicU32, calls: AtomicUsize, stops: AtomicUsize,
    results: Mutex<VecDeque<Result<(), String>>>, cancel_at: &'static str,
    displaced: bool, restores: AtomicUsize,
}
fn wanted(_: &AppHandle) -> bool { true }
fn cur_gen(app: &AppHandle) -> u32 { app.0.generation.load(Ordering::SeqCst) }
fn cancel(app: &AppHandle) { app.0.generation.fetch_add(1, Ordering::SeqCst); }
fn stop_transport(app: &AppHandle) { stop(app); }
fn stop(app: &AppHandle) {
    cancel(app); app.0.stops.fetch_add(1, Ordering::SeqCst);
    if app.0.cancel_at == "cleanup" { cancel(app); }
}
fn notify(_: &AppHandle, _: &str, _: &str) {}
fn remote_log(_: &str, _: ()) {}
async fn tokio_sleep(_: u64) {
    let app = ACTIVE.lock().unwrap().clone().unwrap();
    if app.0.cancel_at == "wait" { cancel(&app); }
}
mod vpn_handover {
    use super::*;
    pub struct Mac;
    pub type Stopped = Arc<Mutex<Vec<String>>>;
    pub fn restore(_: &mut Mac, _: &Vec<String>) -> Result<(), String> {
        ACTIVE.lock().unwrap().as_ref().unwrap().0.restores.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
mod tauri { pub mod async_runtime {
    pub async fn spawn_blocking<F: FnOnce() -> R, R>(f: F) -> Result<R, String> { Ok(f()) }
} }
async fn start_once(app: AppHandle, handover: Option<vpn_handover::Stopped>, expected: u32) -> Result<(), String> {
    if cur_gen(&app) != expected { return Err("CANCELLED".into()); }
    app.0.calls.fetch_add(1, Ordering::SeqCst);
    // Production start_once performs one own cleanup before attempting TUN.
    cancel(&app);
    if app.0.displaced { handover.unwrap().lock().unwrap().push("previous VPN".into()); }
    if app.0.cancel_at == "attempt" { cancel(&app); }
    app.0.results.lock().unwrap().pop_front().expect("unexpected extra connection attempt")
}
include!("actual.rs");
struct Noop;
impl Wake for Noop { fn wake(self: Arc<Self>) {} }
fn run<F: Future>(f: F) -> F::Output {
    let w = Waker::from(Arc::new(Noop)); let mut cx = Context::from_waker(&w);
    let mut f = Box::pin(f);
    loop { if let Poll::Ready(v) = f.as_mut().poll(&mut cx) { return v; } }
}
fn app(results: &[&str], cancel_at: &'static str, displaced: bool) -> AppHandle {
    STARTING.store(false, Ordering::SeqCst);
    let app = AppHandle(Arc::new(State {
        generation: AtomicU32::new(40), calls: AtomicUsize::new(0), stops: AtomicUsize::new(0),
        results: Mutex::new(results.iter().map(|s| if *s == "ok" { Ok(()) } else { Err(s.to_string()) }).collect()),
        cancel_at, displaced, restores: AtomicUsize::new(0),
    }));
    *ACTIVE.lock().unwrap() = Some(app.clone()); app
}
#[test] fn transient_tun_failure_recovers_without_another_click() {
    let a = app(&["TUN_FAILED:no traffic", "ok"], "", false);
    assert_eq!(run(start_with_handover(a.clone(), false)), Ok(()));
    assert_eq!(a.0.calls.load(Ordering::SeqCst), 2);
    assert_eq!(a.0.stops.load(Ordering::SeqCst), 1);
    assert!(!STARTING.load(Ordering::SeqCst));
}
#[test] fn retry_is_bounded_and_preserves_failed_result() {
    let a = app(&["TUN_FAILED:first", "TUN_FAILED:second"], "", false);
    assert_eq!(run(start_with_handover(a.clone(), true)), Err("TUN_FAILED:second".into()));
    assert_eq!(a.0.calls.load(Ordering::SeqCst), 2);
}
#[test] fn successful_connection_is_not_restarted() {
    let a = app(&["ok"], "", false);
    assert_eq!(run(start_with_handover(a.clone(), false)), Ok(()));
    assert_eq!(a.0.calls.load(Ordering::SeqCst), 1);
}
#[test] fn hard_errors_are_never_retried() {
    for error in ["CANCELLED", "BUSY", "BOOTSTRAP:expired", "OTHER_VPN:connected", "engine missing", "xTUN_FAILED:wrong prefix"] {
        let a = app(&[error], "", false);
        assert_eq!(run(start_with_handover(a.clone(), false)), Err(error.into()));
        assert_eq!(a.0.calls.load(Ordering::SeqCst), 1);
        assert_eq!(a.0.stops.load(Ordering::SeqCst), 0);
    }
}
#[test] fn cancellation_never_resurrects_connection() {
    for phase in ["attempt", "cleanup", "wait"] {
        let a = app(&["TUN_FAILED:no traffic"], phase, false);
        assert_eq!(run(start_with_handover(a.clone(), false)), Err("CANCELLED".into()), "phase: {phase}");
        assert_eq!(a.0.calls.load(Ordering::SeqCst), 1);
        assert!(!STARTING.load(Ordering::SeqCst));
    }
}
#[test] fn displaced_foreign_vpn_is_restored_without_retry() {
    let a = app(&["TUN_FAILED:no traffic"], "", true);
    assert!(run(start_with_handover(a.clone(), true)).unwrap_err().contains("восстановлено"));
    assert_eq!(a.0.calls.load(Ordering::SeqCst), 1);
    assert_eq!(a.0.restores.load(Ordering::SeqCst), 1);
}
#[test] fn concurrent_start_remains_busy() {
    let a = app(&[], "", false); STARTING.store(true, Ordering::SeqCst);
    assert_eq!(run(start_with_handover(a.clone(), false)), Err("BUSY".into()));
    assert_eq!(a.0.calls.load(Ordering::SeqCst), 0);
    assert!(STARTING.load(Ordering::SeqCst));
}

#[test]
fn queued_recovery_does_not_adopt_a_new_cancel_generation() {
    let a=app(&["ok"],"",false);
    let expected=cur_gen(&a);cancel(&a);
    assert_eq!(run(start_with_expected(a.clone(),false,Some(expected))),Err("CANCELLED".into()));
    assert_eq!(a.0.calls.load(Ordering::SeqCst),0);
    assert!(!STARTING.load(Ordering::SeqCst));
}
