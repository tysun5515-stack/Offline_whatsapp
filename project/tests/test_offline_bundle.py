import re
import unittest
from unittest.mock import patch
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUNDLE_ROOT = ROOT.parent
PINNED = re.compile(r"^([A-Za-z0-9_.-]+)==([^\s\\]+)", re.MULTILINE)
DIRECT = re.compile(r"^([A-Za-z0-9_.-]+)(?:==|>=|<=|<|>)", re.MULTILINE)


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def package_names(path: Path, pattern: re.Pattern) -> set[str]:
    return {normalize(match.group(1)) for match in pattern.finditer(path.read_text(encoding="utf-8"))}


class OfflineBundleTests(unittest.TestCase):
    def test_primary_lock_contains_every_direct_dependency(self):
        direct = package_names(ROOT / "requirements.txt", DIRECT)
        locked = package_names(ROOT / "requirements.lock.txt", PINNED)
        self.assertTrue(direct)
        self.assertTrue(direct <= locked, direct - locked)

    def test_harness_lock_contains_every_direct_dependency(self):
        direct = package_names(ROOT / "whatsapp_ai_harness" / "requirements.txt", DIRECT)
        locked = package_names(ROOT / "whatsapp_ai_harness" / "requirements.lock.txt", PINNED)
        self.assertTrue(direct)
        self.assertTrue(direct <= locked, direct - locked)

    def test_locks_are_fully_pinned_and_hashed(self):
        for relative in ("requirements.lock.txt", "whatsapp_ai_harness/requirements.lock.txt"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            with self.subTest(lock=relative):
                self.assertNotRegex(text, r"(?m)^[A-Za-z0-9_.-]+\s*(?:>=|<=|~=|!=|>)")
                self.assertNotIn(" @ ", text)
                entries = list(PINNED.finditer(text))
                self.assertTrue(entries)
                for index, entry in enumerate(entries):
                    end = entries[index + 1].start() if index + 1 < len(entries) else len(text)
                    self.assertIn("--hash=sha256:", text[entry.start():end], entry.group(1))

    def test_offline_installer_never_uses_an_index(self):
        text = (ROOT / "install_offline.ps1").read_text(encoding="utf-8")
        self.assertIn("--no-index", text)
        self.assertIn("--require-hashes", text)
        self.assertIn("pip check", text)
        self.assertNotIn("pip install --upgrade", text)
        self.assertIn('Join-Path $bundleRoot "wheels"', text)

    def test_bundle_contains_external_runtime_installers_and_geo_assets(self):
        for path in (
            BUNDLE_ROOT / "python-3.12.0-amd64.exe",
            BUNDLE_ROOT / "Wireshark-x64.exe",
            ROOT / "GeoLite2-City.mmdb",
            ROOT / "GeoLite2-ASN.mmdb",
        ):
            with self.subTest(path=path.name):
                self.assertTrue(path.is_file())
                self.assertGreater(path.stat().st_size, 0)

    def test_wheelhouse_covers_every_locked_package(self):
        locked = set()
        for relative in ("requirements.lock.txt", "whatsapp_ai_harness/requirements.lock.txt"):
            locked |= package_names(ROOT / relative, PINNED)
        wheels = {
            normalize(path.name.split("-", 1)[0])
            for path in (BUNDLE_ROOT / "wheels").glob("*.whl")
        }
        self.assertTrue(locked <= wheels, locked - wheels)

    def test_offline_mode_skips_reverse_dns(self):
        from src import geolocation

        with patch.dict("os.environ", {"WA_OFFLINE": "1"}), patch.object(
            geolocation.socket, "gethostbyaddr", side_effect=AssertionError("network lookup attempted")
        ):
            self.assertIsNone(geolocation.reverse_dns("8.8.8.8"))

    def test_bundle_builder_downloads_and_rechecks_wheelhouse(self):
        text = (ROOT / "scripts" / "build_submission.ps1").read_text(encoding="utf-8")
        self.assertIn("pip download", text)
        self.assertIn("--only-binary=:all:", text)
        self.assertIn("--no-index", text)
        self.assertIn("OFFLINE_BUNDLE_MANIFEST.sha256", text)
        self.assertIn('"project\\requirements.lock.txt"', text)


if __name__ == "__main__":
    unittest.main()
