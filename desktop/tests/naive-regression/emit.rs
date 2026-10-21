use std::path::Path;
fn main() {
    let args: Vec<_> = std::env::args().collect();
    let profile: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[1]).unwrap()).unwrap();
    let port: u16 = args[3].parse().unwrap();
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let engine = insellers_naive_regression::engine(&profile, port, now).unwrap();
    let router = insellers_naive_regression::router(&profile, now).unwrap();
    std::fs::write(Path::new(&args[2]).join("engine.json"),engine.to_string()).unwrap();
    std::fs::write(Path::new(&args[2]).join("router.json"),router.to_string()).unwrap();
}
