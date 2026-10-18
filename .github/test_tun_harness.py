"""Offline checks of the CI harness; never starts a VPN or reads its test secret."""
import ast
import pathlib
import threading
import types
import unittest
from unittest import mock


# Load definitions only: the integration script deliberately executes its probes
# at top level. Importing it directly would touch the machine running this test.
source = pathlib.Path(__file__).with_name("tun_test.py")
tree = ast.parse(source.read_text())
tree.body = [node for node in tree.body
             if isinstance(node, (ast.Import, ast.ImportFrom, ast.FunctionDef))]
h = types.ModuleType("tun_harness")
exec(compile(tree, str(source), "exec"), h.__dict__)


class HarnessChecks(unittest.TestCase):
    def test_html_and_wrong_address_family_are_not_ip_evidence(self):
        self.assertFalse(h.valid_ip("<html>error</html>"))
        self.assertFalse(h.valid_ip(""))
        self.assertTrue(h.valid_ip("192.0.2.1", 4))
        self.assertFalse(h.valid_ip("192.0.2.1", 6))
        self.assertTrue(h.valid_ip("2001:db8::1", 6))

    def test_ci_proxy_environment_cannot_change_route(self):
        env = {"HTTPS_PROXY": "http://invalid", "http_proxy": "http://invalid",
               "ALL_PROXY": "http://invalid", "NO_PROXY": "*", "PATH": "/test"}
        with mock.patch.dict(h.os.environ, env, clear=True), \
             mock.patch.object(h.subprocess, "run", return_value=types.SimpleNamespace(
                 returncode=0, stdout="192.0.2.1\n")) as run:
            h.curl("https://example.invalid", ["--socks5-hostname", "127.0.0.1:38808"])
        self.assertEqual(run.call_args.kwargs["env"], {"PATH": "/test"})
        self.assertIn("--socks5-hostname", run.call_args.args[0])

    def test_proxy_preflight_rejects_errors_html_and_direct_exit(self):
        for response in [(28, ""), (0, "<html>blocked</html>"), (0, "192.0.2.1")]:
            with self.subTest(response=response), mock.patch.object(h, "curl", return_value=response):
                self.assertFalse(h.proxy_ready("192.0.2.1"))
        with mock.patch.object(h, "curl", return_value=(0, "198.51.100.1")):
            self.assertTrue(h.proxy_ready("192.0.2.1"))

    def test_heartbeat_continues_and_reports_failure(self):
        stop, errors, calls = threading.Event(), [], []

        def helper(req, t):
            calls.append(req)
            if len(calls) == 1:
                raise OSError("unavailable")
            stop.set()
            return {"ok": True, "running": True}

        with mock.patch.object(h, "helper", side_effect=helper):
            worker = threading.Thread(target=h.keepalive, args=(stop, errors, 0.001))
            worker.start()
            worker.join(timeout=2)
            stop.set()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(calls, [{"cmd": "ping"}, {"cmd": "ping"}])
        self.assertEqual(errors, ["helper ping failed"])

    def test_cleanup_stops_heartbeat_and_authenticates_down(self):
        stop, worker = threading.Event(), mock.Mock()
        with mock.patch.object(h, "helper") as helper:
            h.cleanup(stop, worker, "offline-test-token")
        self.assertTrue(stop.is_set())
        worker.join.assert_called_once_with(timeout=11)
        helper.assert_called_once_with({"cmd": "down", "token": "offline-test-token"}, t=5)


if __name__ == "__main__":
    unittest.main()
