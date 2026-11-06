"""Compile the actual startup wrapper with inert OS adapters; no VPN changes."""
import argparse,subprocess,tempfile,sys
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--rustc',default='rustc');a=p.parse_args()
root=Path(__file__).resolve().parents[2];source=root/'src-tauri/src/vpn.rs'
with tempfile.TemporaryDirectory(prefix='vpn-handover-regression-') as td:
 out=Path(td)
 subprocess.run([a.rustc,'--edition=2021','--test',str(root/'src-tauri/src/vpn_handover.rs'),'-o',str(out/'module')],check=True)
 subprocess.run([str(out/'module')],check=True)
 if sys.platform!='darwin':sys.exit(0)
 s=source.read_text();start=s.index('async fn start_with_handover(');end=s.index('\nasync fn start_once(',start)
 actual=s[start:end]
 fixture=Path(__file__).with_name('wrapper.rs').read_text().replace('// ACTUAL_WRAPPER',actual)
 (out/'test.rs').write_text(fixture)
 subprocess.run([a.rustc,'--edition=2021','--test','-Awarnings',str(out/'test.rs'),'-o',str(out/'wrapper')],check=True)
 subprocess.run([str(out/'wrapper'),'--test-threads=1'],check=True)

# Compile the actual macOS acceptance guard: a failed requested TUN cannot become connected.
if sys.platform=='darwin':
 import re
 guard=re.search(r'    #\[cfg\(target_os = "macos"\)\]\n    if !crate::pref\("tun_off"\).*?\n    }',source.read_text(),re.S).group(0)
 fixture='use std::sync::atomic::{AtomicBool,Ordering};\nstatic OFF:AtomicBool=AtomicBool::new(false);\nfn pref(_: &str)->bool{OFF.load(Ordering::SeqCst)}\nfn accept(tun_on:bool)->Result<(),String>{GUARD\nOk(())}\n#[test]fn rejected_tun_is_not_connected(){OFF.store(false,Ordering::SeqCst);assert!(accept(false).unwrap_err().starts_with("TUN_FAILED:"));assert!(accept(true).is_ok());OFF.store(true,Ordering::SeqCst);assert!(accept(false).is_ok());}\n'.replace('GUARD',guard)
 with tempfile.TemporaryDirectory(prefix='vpn-tun-acceptance-') as td:
  p=Path(td);(p/'test.rs').write_text(fixture)
  subprocess.run([a.rustc,'--edition=2021','--test',str(p/'test.rs'),'-o',str(p/'test')],check=True)
  subprocess.run([str(p/'test')],check=True)
