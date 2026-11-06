"""Compile the production startup wrapper against a controlled lifecycle.

No Tauri installation, credentials, network or system VPN changes are needed.
"""
import argparse, os, pathlib, subprocess, tempfile

root = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser()
parser.add_argument('--source', type=pathlib.Path, default=root/'src-tauri/src/vpn.rs')
args = parser.parse_args()
source = args.source.read_text()
start = source.index('async fn start_with_handover(')
end = source.index('\nasync fn start_once(', start)
actual = source[start:end].replace('#[cfg(target_os = "macos")]', '')
fixture = pathlib.Path(__file__).with_name('fixture.rs').read_text()
with tempfile.TemporaryDirectory(prefix='insellers-startup-test-') as temporary:
    path = pathlib.Path(temporary)
    (path/'actual.rs').write_text(actual)
    (path/'fixture.rs').write_text(fixture)
    subprocess.run([os.environ.get('RUSTC', 'rustc'), '--edition=2021', '--test',
                    '-A', 'warnings', str(path/'fixture.rs'), '-o', str(path/'check')], check=True)
    subprocess.run([str(path/'check'), '--test-threads=1'], check=True)
