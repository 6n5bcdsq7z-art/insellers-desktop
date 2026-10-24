#!/usr/bin/env python3
"""Compile the actual session reader with inert Keychain and private temp files."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2] / 'src-tauri/src/main.rs')
p.add_argument('--rustc', default='rustc')
a = p.parse_args()
source = a.source.read_text(encoding="utf-8")
start = source.index('pub fn load_token() -> String {')
depth = 1
end = source.index('{', start) + 1
while depth:
    depth += (source[end] == '{') - (source[end] == '}')
    end += 1
actual = source[start:end]
fixture = r'''
use std::sync::{OnceLock, atomic::{AtomicBool, AtomicUsize, Ordering}};
static ROOT: OnceLock<std::path::PathBuf> = OnceLock::new();
static CALLS: AtomicUsize = AtomicUsize::new(0);
static PRESENT: AtomicBool = AtomicBool::new(true);
fn data_path(name: &str) -> Option<std::path::PathBuf> { Some(ROOT.get().unwrap().join(name)) }
fn keychain_token() -> Option<String> {
    CALLS.fetch_add(1, Ordering::SeqCst);
    PRESENT.load(Ordering::SeqCst).then(|| "fixture-keychain-session".to_string())
}
struct Entry;
impl Entry { fn get_password(&self) -> Result<String, ()> { keychain_token().ok_or(()) } }
fn keyring_entry() -> Option<Entry> { Some(Entry) }
fn main() {
    let path = std::env::temp_dir().join(format!("insellers-session-fixture-{}", std::process::id()));
    std::fs::create_dir(&path).unwrap(); ROOT.set(path.clone()).unwrap();
    let file = path.join("session.token");
    std::fs::write(&file, "  fixture-file-session\n").unwrap();
    if cfg!(target_os = "macos") {
        assert_eq!(load_token(), "fixture-file-session", "existing session must open without Keychain");
        assert_eq!(CALLS.load(Ordering::SeqCst), 0, "Keychain may block, so it must not be called");
    } else {
        assert_eq!(load_token(), "fixture-keychain-session");
        assert_eq!(CALLS.swap(0, Ordering::SeqCst), 1);
    }
    std::fs::write(&file, " \n").unwrap();
    assert_eq!(load_token(), "fixture-keychain-session");
    assert_eq!(CALLS.swap(0, Ordering::SeqCst), 1);
    std::fs::remove_file(&file).unwrap();
    assert_eq!(load_token(), "fixture-keychain-session");
    assert_eq!(CALLS.swap(0, Ordering::SeqCst), 1);
    PRESENT.store(false, Ordering::SeqCst);
    assert_eq!(load_token(), "");
    std::fs::remove_dir(&path).unwrap();
    println!("actual session reader: private file first, empty/missing file, unavailable Keychain PASS");
}
'''
with tempfile.TemporaryDirectory(prefix='insellers-session-compile-') as directory:
    root = Path(directory)
    src = root / 'fixture.rs'; src.write_text(actual + '\n' + fixture, encoding='utf-8')
    exe = root / ('session-fixture.exe' if os.name == 'nt' else 'session-fixture')
    subprocess.run([a.rustc, '--edition=2021', '-Awarnings', str(src), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)
