import re
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TEXT_SUFFIXES = {".py", ".html", ".js", ".css", ".md", ".txt", ".cmd", ".ps1"}


class RepositoryHygieneTests(unittest.TestCase):
    def test_static_template_references_exist(self):
        pattern = re.compile(r"filename=['\"]([^'\"]+)['\"]")
        for template in (ROOT / "src" / "webapp" / "templates").glob("*.html"):
            for relative in pattern.findall(template.read_text(encoding="utf-8")):
                with self.subTest(template=template.name, asset=relative):
                    self.assertTrue((ROOT / "src" / "webapp" / "static" / relative).is_file())

    def test_direct_requirements_have_runtime_callers(self):
        callers = {
            "Flask": "src/webapp/app.py",
            "Werkzeug": "src/webapp/app.py",
            "Jinja2": "src/webapp/report_generator.py",
            "cryptography": "src/quic_decrypt.py",
            "geoip2": "src/geolocation.py",
        }
        requirements = {
            line.split("==", 1)[0]
            for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        }
        self.assertEqual(requirements, set(callers))
        for dependency, relative in callers.items():
            with self.subTest(dependency=dependency):
                text = (ROOT / relative).read_text(encoding="utf-8").lower()
                self.assertIn(dependency.lower(), text)

    def test_source_has_no_known_mojibake_markers(self):
        markers = (
            "\u00e2\u20ac",
            "\u00e2\u201d",
            "\u00c3",
            "\u00ef\u00b8",
            "\u00f0\u0178",
        )
        for path in ROOT.rglob("*"):
            if (
                not path.is_file()
                or path.suffix.lower() not in TEXT_SUFFIXES
                or ".venv" in path.parts
                or "node_modules" in path.parts
                or "vendor" in path.parts
            ):
                continue
            text = path.read_text(encoding="utf-8")
            for marker in markers:
                with self.subTest(path=str(path.relative_to(ROOT)), marker=marker):
                    self.assertNotIn(marker, text)

    def test_runtime_jobs_are_not_tracked(self):
        result = subprocess.run(
            ["git", "ls-files", "jobs"], cwd=ROOT, text=True,
            capture_output=True,
        )
        if result.returncode != 0:
            self.skipTest("Git metadata is not present in this source archive")
        self.assertEqual(result.stdout.strip(), "")


if __name__ == "__main__":
    unittest.main()
