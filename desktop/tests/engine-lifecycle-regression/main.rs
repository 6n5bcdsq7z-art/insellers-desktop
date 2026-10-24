use std::sync::{Arc, Mutex, atomic::{AtomicBool, AtomicU32, Ordering}};
use std::time::Duration;

static JOBS: Mutex<Vec<Box<dyn FnOnce() + Send>>> = Mutex::new(Vec::new());
static EVENTS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static KS: AtomicBool = AtomicBool::new(false);
static RECONNECT: AtomicBool = AtomicBool::new(true);
static TUN: AtomicBool = AtomicBool::new(true);
static PROXY: AtomicBool = AtomicBool::new(true);
static STARTS: AtomicU32 = AtomicU32::new(0);
static PANICS: AtomicU32 = AtomicU32::new(0);
struct Child { id: u32, killed: Arc<AtomicBool> }
impl Child {
    fn pid(&self) -> u32 { self.id }
    fn kill(self) -> Result<(), ()> { self.killed.store(true, Ordering::SeqCst); Ok(()) }
}
struct VpnState {
    child: Mutex<Option<Child>>, router: Mutex<Option<Child>>,
    wanted: AtomicBool, generation: AtomicU32, retries: AtomicU32,
}
#[derive(Clone)] struct AppHandle(Arc<VpnState>);
impl AppHandle { fn state<T>(&self) -> &VpnState { &self.0 } }
fn wanted(a: &AppHandle) -> bool { a.0.wanted.load(Ordering::SeqCst) }
fn cur_gen(a: &AppHandle) -> u32 { a.0.generation.load(Ordering::SeqCst) }
fn pref(key: &str) -> bool { if key == "killswitch" { KS.load(Ordering::SeqCst) } else { RECONNECT.load(Ordering::SeqCst) } }
fn set_proxy(on: bool) { PROXY.store(on, Ordering::SeqCst); }
fn notify(_: &AppHandle, state: &str, _: &str) { EVENTS.lock().unwrap().push(state.into()); }
fn queue<F: FnOnce() + Send + 'static>(job: F) { JOBS.lock().unwrap().push(Box::new(job)); }
fn noop_sleep(_: Duration) {}
fn identity<T>(value: T) -> T { value }
fn start(_: AppHandle) -> Result<(), String> { STARTS.fetch_add(1, Ordering::SeqCst); Ok(()) }
mod telemetry {
    pub fn core_panic(_: &str, _: Option<i32>) { super::PANICS.fetch_add(1, super::Ordering::SeqCst); }
    pub fn set_stop_reason(_: &str) {}
}
mod tun { pub fn down() { super::TUN.store(false, super::Ordering::SeqCst); } }
struct Terminated { code: Option<i32> }
macro_rules! json { ($($t:tt)*) => { () }; }
fn remote_log(_: &str, _: ()) {}
// ACTUAL_EXIT_HANDLER

fn fixture() -> (AppHandle, Arc<AtomicBool>, Arc<AtomicBool>) {
    JOBS.lock().unwrap().clear(); EVENTS.lock().unwrap().clear();
    KS.store(false, Ordering::SeqCst); RECONNECT.store(true, Ordering::SeqCst);
    TUN.store(true, Ordering::SeqCst); PROXY.store(true, Ordering::SeqCst);
    STARTS.store(0, Ordering::SeqCst); PANICS.store(0, Ordering::SeqCst);
    let main = Arc::new(AtomicBool::new(false)); let router = Arc::new(AtomicBool::new(false));
    let a = AppHandle(Arc::new(VpnState {
        child: Mutex::new(Some(Child { id: 10, killed: main.clone() })),
        router: Mutex::new(Some(Child { id: 20, killed: router.clone() })),
        wanted: AtomicBool::new(true), generation: AtomicU32::new(1), retries: AtomicU32::new(0),
    }));
    (a, main, router)
}
fn drain() { let jobs = std::mem::take(&mut *JOBS.lock().unwrap()); for job in jobs { job(); } }

#[test] fn router_crash_stops_both_and_recovers_once() {
    let (a, main, router) = fixture(); engine_terminated(&a, 20, true, Some(1));
    assert!(main.load(Ordering::SeqCst) && router.load(Ordering::SeqCst));
    assert!(!TUN.load(Ordering::SeqCst) && !PROXY.load(Ordering::SeqCst));
    assert_eq!(&*EVENTS.lock().unwrap(), &["connecting"]);
    assert_eq!(JOBS.lock().unwrap().len(), 1); drain();
    assert_eq!(STARTS.load(Ordering::SeqCst), 1);
    assert_eq!(EVENTS.lock().unwrap().last().unwrap(), "connected");
}
#[test] fn core_crash_also_stops_router() {
    let (a, main, router) = fixture(); engine_terminated(&a, 10, false, Some(1));
    assert!(main.load(Ordering::SeqCst) && router.load(Ordering::SeqCst));
    assert_eq!(JOBS.lock().unwrap().len(), 1);
}
#[test] fn peer_callback_and_duplicate_event_do_not_restart_twice() {
    let (a, _, _) = fixture(); engine_terminated(&a, 20, true, None);
    engine_terminated(&a, 10, false, None); engine_terminated(&a, 20, true, None);
    assert_eq!(PANICS.load(Ordering::SeqCst), 1); assert_eq!(JOBS.lock().unwrap().len(), 1);
}
#[test] fn stale_process_event_leaves_current_connection_untouched() {
    let (a, main, router) = fixture(); engine_terminated(&a, 19, true, None);
    assert!(!main.load(Ordering::SeqCst) && !router.load(Ordering::SeqCst));
    assert!(TUN.load(Ordering::SeqCst) && PROXY.load(Ordering::SeqCst));
    assert!(JOBS.lock().unwrap().is_empty() && EVENTS.lock().unwrap().is_empty());
}
#[test] fn startup_or_stopped_connection_does_not_reconnect() {
    let (a, _, _) = fixture(); a.0.wanted.store(false, Ordering::SeqCst);
    engine_terminated(&a, 20, true, None);
    assert!(JOBS.lock().unwrap().is_empty() && EVENTS.lock().unwrap().is_empty());
}
#[test] fn user_stop_cancels_delayed_reconnect() {
    let (a, _, _) = fixture(); engine_terminated(&a, 20, true, None);
    a.0.wanted.store(false, Ordering::SeqCst); a.0.generation.fetch_add(1, Ordering::SeqCst);
    drain(); assert_eq!(STARTS.load(Ordering::SeqCst), 0);
}
#[test] fn newer_manual_connection_cancels_old_reconnect_even_when_wanted() {
    let (a, _, _) = fixture(); engine_terminated(&a, 20, true, None);
    a.0.generation.fetch_add(1, Ordering::SeqCst);
    drain(); assert_eq!(STARTS.load(Ordering::SeqCst), 0);
}
#[test] fn kill_switch_keeps_network_paused() {
    let (a, _, _) = fixture(); KS.store(true, Ordering::SeqCst);
    engine_terminated(&a, 20, true, None);
    assert!(TUN.load(Ordering::SeqCst) && PROXY.load(Ordering::SeqCst));
}
#[test] fn reconnect_disabled_reports_actual_disconnection() {
    let (a, _, _) = fixture(); RECONNECT.store(false, Ordering::SeqCst);
    engine_terminated(&a, 20, true, None);
    assert_eq!(&*EVENTS.lock().unwrap(), &["disconnected"]); assert!(JOBS.lock().unwrap().is_empty());
}
#[test] fn kill_switch_without_reconnect_reports_error_and_retains_pause() {
    let (a, _, _) = fixture(); KS.store(true, Ordering::SeqCst); RECONNECT.store(false, Ordering::SeqCst);
    engine_terminated(&a, 20, true, None);
    assert_eq!(&*EVENTS.lock().unwrap(), &["error"]); assert!(TUN.load(Ordering::SeqCst));
    assert!(JOBS.lock().unwrap().is_empty());
}
#[test] fn concurrent_process_failures_claim_connection_once() {
    let (a, _, _) = fixture(); let b = a.clone();
    let first = std::thread::spawn(move || engine_terminated(&b, 20, true, None));
    engine_terminated(&a, 10, false, None); first.join().unwrap();
    assert_eq!(PANICS.load(Ordering::SeqCst), 1); assert_eq!(JOBS.lock().unwrap().len(), 1);
}
