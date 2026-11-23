import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


WORKFLOW = Path(__file__).with_name("workflows") / "promote.yml"


def promote_run_script():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    trigger = workflow.get("on", workflow.get(True))
    return workflow["jobs"]["promote"]["steps"][0]["run"]


def manifest_filter():
    lines = promote_run_script().splitlines()
    marker = 'python3 - "$VER" "$PLATFORM" <<\'PY\''
    start = lines.index(marker) + 1
    end = lines.index("PY", start)
    return "\n".join(lines[start:end]) + "\n"


class PromotePlatformFilter(unittest.TestCase):
    def run_filter(self, platforms, version="1.0.194", platform="windows-x86_64",
                   expected_version=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "latest.json"
            path.write_text(
                json.dumps({"version": version, "platforms": platforms}),
                encoding="utf-8",
            )
            result = subprocess.run(
                ["python3", "-", expected_version or version, platform],
                cwd=tmp,
                input=manifest_filter(),
                text=True,
                capture_output=True,
                check=False,
            )
            return result, json.loads(path.read_text(encoding="utf-8"))

    def test_selector_is_backward_compatible_and_offers_windows_only(self):
        workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        trigger = workflow.get("on", workflow.get(True))
        selector = trigger["workflow_dispatch"]["inputs"]["platform"]
        self.assertEqual(selector["default"], "all")
        self.assertIn("all", selector["options"])
        self.assertIn("windows-x86_64", selector["options"])

    def test_all_keeps_every_platform(self):
        platforms = {
            "windows-x86_64": {"url": "win"},
            "linux-x86_64": {"url": "linux"},
        }
        result, manifest = self.run_filter(platforms, platform="all")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(manifest["platforms"], platforms)

    def test_windows_keeps_only_the_confirmed_platform(self):
        platforms = {
            "windows-x86_64": {"url": "win"},
            "darwin-aarch64": {"url": "mac"},
            "linux-x86_64": {"url": "linux"},
        }
        result, manifest = self.run_filter(platforms)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(manifest["platforms"], {"windows-x86_64": {"url": "win"}})

    def test_missing_platform_and_wrong_version_fail_closed(self):
        result, manifest = self.run_filter({"linux-x86_64": {"url": "linux"}})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("windows-x86_64", result.stderr)
        self.assertEqual(set(manifest["platforms"]), {"linux-x86_64"})

        result, manifest = self.run_filter(
            {"windows-x86_64": {"url": "win"}},
            version="1.0.193",
            expected_version="1.0.194",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("1.0.194", result.stderr)
        self.assertEqual(manifest["version"], "1.0.193")


if __name__ == "__main__":
    unittest.main()
