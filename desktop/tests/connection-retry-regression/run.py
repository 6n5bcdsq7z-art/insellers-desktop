"""Run extracted production retry/request logic with inert network/OS adapters."""
import argparse, pathlib, subprocess, tempfile
p=argparse.ArgumentParser()
p.add_argument('--rustc',default='rustc')
p.add_argument('--vpn-source',type=pathlib.Path)
p.add_argument('--main-source',type=pathlib.Path)
a=p.parse_args(); here=pathlib.Path(__file__).resolve().parent
vpn=(a.vpn_source or here.parents[1]/'src-tauri/src/vpn.rs').read_text()
main=(a.main_source or here.parents[1]/'src-tauri/src/main.rs').read_text()
start='static RECONNECT_EPOCH:' if 'static RECONNECT_EPOCH:' in vpn else 'fn reconnect_retry('
retry=vpn[vpn.index(start):vpn.index('/// Пробуждение системы',vpn.index(start))]
if start.startswith('fn '):
    retry='fn cancel_reconnect() {}\n'+retry
retry=retry.replace('std::thread::spawn','run_inline').replace('std::thread::sleep','test_sleep').replace('crate::remote_log','remote_log').replace('crate::now_ms','now_ms')
request=main[main.index('static CONNECT_REQUEST:'):main.index('#[tauri::command]\nfn logout',main.index('static CONNECT_REQUEST:'))]
request=request.replace('#[tauri::command]','').replace('serde_json::json!','json!')
assert 'cancel_connect_request();' in request or a.main_source, 'Stop must invalidate queued Connect'
source=(here/'main.rs').read_text().replace('// ACTUAL_RETRY',retry).replace('// ACTUAL_REQUEST',request)
with tempfile.TemporaryDirectory(prefix='insellers-retry-regression-') as tmp:
    root=pathlib.Path(tmp); (root/'test.rs').write_text(source)
    subprocess.run([a.rustc,'--edition=2021','--test','-Awarnings',str(root/'test.rs'),'-o',str(root/'test')],check=True,timeout=60)
    subprocess.run([str(root/'test'),'--test-threads=1'],check=True,timeout=30)
