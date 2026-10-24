"""Compile actual process-exit handling with inert OS operations; never run a VPN."""
import argparse
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('--rustc', default='rustc')
p.add_argument('--source', type=Path, default=Path(__file__).resolve().parents[2] / 'src-tauri/src/vpn.rs')
p.add_argument('--case')
a = p.parse_args()
text = a.source.read_text()
if 'fn engine_terminated(' in text:
    actual = text[text.index('fn engine_terminated('):text.index('\nfn launch(', text.index('fn engine_terminated('))]
    assert 'engine_terminated(&a, my_pid, false, tp.code)' in text
    assert 'engine_terminated(&a, pid, true, t.code)' in text
else:
    # Execute the old router callback itself to reproduce its silent exit.
    router = text[text.index('fn launch_router_value('):text.index('/// Открывается ли внешний сайт', text.index('fn launch_router_value('))]
    callback = router.split('if let CommandEvent::Terminated(t) = ev {', 1)[1].split('\n            }', 1)[0]
    actual = 'fn engine_terminated(_app: &AppHandle, pid: u32, _router_exit: bool, code: Option<i32>) { let t = Terminated {code}; loop {' + callback + '}}'
actual = actual.replace('std::thread::spawn', 'queue').replace('std::thread::sleep', 'noop_sleep').replace('tauri::async_runtime::block_on', 'identity')
template = Path(__file__).with_name('main.rs').read_text()
with tempfile.TemporaryDirectory(prefix='insellers-lifecycle-') as td:
    root = Path(td)
    source = root / 'test.rs'; binary = root / 'test'
    source.write_text(template.replace('// ACTUAL_EXIT_HANDLER', actual))
    subprocess.run([a.rustc, '--edition=2021', '--test', '-Awarnings', str(source), '-o', str(binary)], check=True, timeout=60)
    args = [str(binary), '--test-threads=1']
    if a.case:
        args.append(a.case)
    subprocess.run(args, check=True, timeout=30)
