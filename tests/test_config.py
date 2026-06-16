from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repo_publication_gate.config import GateConfig, load_config


class ConfigTests(unittest.TestCase):
    def test_defaults_when_config_missing(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config = load_config(Path(temp))
            self.assertEqual(config.fail_on, "high")
            self.assertGreater(config.max_file_size_bytes, 0)

    def test_loads_toml(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".repo-publication-gate.toml").write_text(
                """
[gate]
fail_on = "medium"
max_file_size_bytes = 1234
content_scan_max_bytes = 4321
ignore_paths = ["vendor/**"]
allow_paths = [".env.demo"]
""".strip()
                + "\n",
                encoding="utf-8",
            )
            config = load_config(root)
            self.assertEqual(config.fail_on, "medium")
            self.assertEqual(config.max_file_size_bytes, 1234)
            self.assertEqual(config.ignore_paths, ["vendor/**"])
            self.assertEqual(config.allow_paths, [".env.demo"])

    def test_invalid_severity_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".repo-publication-gate.toml").write_text(
                "[gate]\nfail_on = \"extreme\"\n", encoding="utf-8"
            )
            with self.assertRaises(ValueError):
                load_config(root)


if __name__ == "__main__":
    unittest.main()
