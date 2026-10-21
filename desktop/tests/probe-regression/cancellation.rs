//! Compile the actual startup finalization and stop() against controllable OS
//! calls. Cancellation happens on a different thread while each call is blocked.
use serde_json::json;
use std::sync::{Arc, Condvar, Mutex};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::time::Duration;

static CONNECTION_TRANSITION: Mutex<()> = Mutex::new(());
static UP_AT: AtomicU64 = AtomicU64::new(0);
static PROXY: AtomicBool = AtomicBool::new(false);
static TUN: AtomicBool = AtomicBool::new(true);
static CORE: AtomicBool = AtomicBool::new(true);
#[derive(Clone, Copy, PartialEq, Debug)]
enum Phase { None, Status, SetProxy, ProxyCheck, RetrySleep, Wanted, TimerBefore, TimerAfter, FinalReturn, OwnStop }
struct Gate { phase: Phase, entered: bool, release: bool }
static GATE: (Mutex<Gate>, Condvar) = (Mutex::new(Gate { phase: Phase::None, entered: false, release: false }), Condvar::new());

fn pause(phase: Phase) {
    let (lock, cv) = &GATE;
    let mut g = lock.lock().unwrap();
    if g.phase != phase { return; }
    g.entered = true; cv.notify_all();
    while !g.release { g = cv.wait(g).unwrap(); }
}
fn selected() -> Phase { GATE.0.lock().unwrap().phase }
#[derive(Clone)] struct AppHandle(Arc<VpnState>);
struct VpnState { guest_gen: AtomicU32, wanted: AtomicBool, child: Mutex<Option<Child>> }
impl AppHandle { fn try_state<T>(&self) -> Option<&VpnState> { Some(&self.0) } }
struct Child;
impl Child { fn kill(self) -> Result<(), ()> { CORE.store(false, Ordering::SeqCst); Ok(()) } }
fn data_dir(_: &AppHandle) -> Result<std::path::PathBuf, String> { Err("no filesystem in lifecycle fixture".into()) }
fn cur_gen(app: &AppHandle) -> u32 { app.0.guest_gen.load(Ordering::SeqCst) }
fn bump_gen(app: &AppHandle) -> u32 { app.0.guest_gen.fetch_add(1, Ordering::SeqCst) + 1 }
fn set_wanted(app: &AppHandle, value: bool) {
    if value { pause(Phase::Wanted); }
    app.0.wanted.store(value, Ordering::SeqCst);
}
fn wanted(app: &AppHandle) -> bool { app.0.wanted.load(Ordering::SeqCst) }
fn set_proxy(value: bool) {
    if value { pause(Phase::SetProxy); }
    PROXY.store(value, Ordering::SeqCst);
}
fn proxy_is_ours() -> bool {
    pause(Phase::ProxyCheck);
    selected() != Phase::RetrySleep && PROXY.load(Ordering::SeqCst)
}
fn proxy_left_on() -> bool { PROXY.load(Ordering::SeqCst) }
fn kill_child(app: &AppHandle) { app.0.child.lock().unwrap().take(); CORE.store(false, Ordering::SeqCst); }
fn kill_own_xray(_: Option<u32>) { CORE.store(false, Ordering::SeqCst); }
fn arm_guest_timer(app: &AppHandle, _: u64) {
    pause(Phase::TimerBefore); bump_gen(app); pause(Phase::TimerAfter);
}
mod test_platform {
    use super::*;
    pub fn sleep(_: Duration) { pause(Phase::RetrySleep); }
    pub fn now_ms() -> u64 { 42 }
    pub fn after_transition() { pause(Phase::FinalReturn); }
    pub fn remote_log(_: &str, _: serde_json::Value) {}
    pub mod telemetry { pub fn disconnect() {} }
    pub mod tun {
        use super::*;
        pub fn status() -> serde_json::Value { pause(Phase::Status); json!({"fixture":true}) }
        pub fn down() { pause(Phase::OwnStop); TUN.store(false, Ordering::SeqCst); }
    }
}
include!(concat!(env!("OUT_DIR"), "/cancellation.rs"));

pub fn run() {
    // Startup's own cleanup holds the transition lock. A concurrent explicit
    // stop must not be adopted as this startup's generation when cleanup ends.
    *GATE.0.lock().unwrap() = Gate { phase: Phase::OwnStop, entered: false, release: false };
    let app = AppHandle(Arc::new(VpnState { guest_gen: AtomicU32::new(1), wanted: AtomicBool::new(true), child: Mutex::new(Some(Child)) }));
    let worker_app = app.clone();
    let worker = std::thread::spawn(move || begin_start(worker_app, 1));
    let (lock, cv) = &GATE;
    let g = lock.lock().unwrap();
    let (g, timeout) = cv.wait_timeout_while(g, Duration::from_secs(3), |g| !g.entered).unwrap();
    assert!(!timeout.timed_out(), "own stop did not enter blocked teardown"); drop(g);
    assert_eq!(cur_gen(&app), 2, "startup's own stop advances exactly once");
    let stop_app = app.clone();
    let stopper = std::thread::spawn(move || stop(&stop_app));
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while cur_gen(&app) == 2 && std::time::Instant::now() < deadline { std::thread::yield_now(); }
    assert_eq!(cur_gen(&app), 3, "user stop must cancel during blocked own cleanup");
    { let mut g = lock.lock().unwrap(); g.release = true; cv.notify_all(); }
    let result = worker.join().unwrap(); stopper.join().unwrap();
    assert_eq!(result, Err("CANCELLED".into()), "startup adopted a concurrent user stop as its own generation");
    assert!(!wanted(&app) && !CORE.load(Ordering::SeqCst) && !TUN.load(Ordering::SeqCst) && !PROXY.load(Ordering::SeqCst));
    *GATE.0.lock().unwrap() = Gate { phase: Phase::None, entered: false, release: true };
    let app = AppHandle(Arc::new(VpnState { guest_gen: AtomicU32::new(1), wanted: AtomicBool::new(true), child: Mutex::new(Some(Child)) }));
    assert_eq!(begin_start(app, 1), Ok(2), "ordinary own cleanup keeps startup enabled");
    println!("PASS actual Desktop own-stop boundary: concurrent stop cancels; ordinary cleanup advances once");
    for phase in [Phase::Status, Phase::SetProxy, Phase::ProxyCheck, Phase::RetrySleep, Phase::Wanted, Phase::TimerBefore, Phase::TimerAfter, Phase::FinalReturn] {
        *GATE.0.lock().unwrap() = Gate { phase, entered: false, release: false };
        PROXY.store(false, Ordering::SeqCst); TUN.store(true, Ordering::SeqCst); CORE.store(true, Ordering::SeqCst);
        let app = AppHandle(Arc::new(VpnState { guest_gen: AtomicU32::new(1), wanted: AtomicBool::new(false), child: Mutex::new(Some(Child)) }));
        let worker_app = app.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
                .block_on(finish_start(worker_app, 1, phase == Phase::Status, false))
        });
        let (lock, cv) = &GATE;
        let g = lock.lock().unwrap();
        let (g, timeout) = cv.wait_timeout_while(g, Duration::from_secs(3), |g| !g.entered).unwrap();
        assert!(!timeout.timed_out(), "startup never entered {phase:?}"); drop(g);
        let before_stop = cur_gen(&app);
        let stop_app = app.clone();
        let stopper = std::thread::spawn(move || stop(&stop_app));
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        while cur_gen(&app) == before_stop && std::time::Instant::now() < deadline { std::thread::yield_now(); }
        assert_ne!(cur_gen(&app), before_stop, "stop must cancel immediately even while OS transition is blocked");
        { let mut g = lock.lock().unwrap(); g.release = true; cv.notify_all(); }
        let result = worker.join().unwrap(); stopper.join().unwrap();
        assert_eq!(result, Err("CANCELLED".into()), "cancellation at {phase:?}: proxy={} wanted={} core={} tun={}",
            PROXY.load(Ordering::SeqCst), app.0.wanted.load(Ordering::SeqCst), CORE.load(Ordering::SeqCst), TUN.load(Ordering::SeqCst));
        assert!(!PROXY.load(Ordering::SeqCst), "stale startup restored proxy at {phase:?}");
        assert!(!app.0.wanted.load(Ordering::SeqCst), "stale startup restored wanted at {phase:?}");
        assert!(!CORE.load(Ordering::SeqCst) && !TUN.load(Ordering::SeqCst));
        println!("PASS actual Desktop cancellation during {phase:?}: no proxy/TUN/core/wanted resurrection");
    }
    *GATE.0.lock().unwrap() = Gate { phase: Phase::None, entered: false, release: true };
    for (await_status, tun_on) in [(true, false), (false, false), (false, true)] {
        PROXY.store(false, Ordering::SeqCst); TUN.store(tun_on || await_status, Ordering::SeqCst); CORE.store(true, Ordering::SeqCst);
        let app = AppHandle(Arc::new(VpnState { guest_gen: AtomicU32::new(1), wanted: AtomicBool::new(false), child: Mutex::new(Some(Child)) }));
        let worker_app = app.clone();
        let result = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
                .block_on(finish_start(worker_app, 1, await_status, tun_on))
        }).join().unwrap();
        assert_eq!(result, Ok(()));
        assert!(app.0.wanted.load(Ordering::SeqCst) && CORE.load(Ordering::SeqCst));
        assert_eq!(PROXY.load(Ordering::SeqCst), !tun_on);
        assert_eq!(TUN.load(Ordering::SeqCst), tun_on);
    }
    println!("PASS actual Desktop finalization without cancellation: TUN, proxy-only, failed-TUN fallback");
}
