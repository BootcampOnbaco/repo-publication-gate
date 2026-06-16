from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repo_publication_gate.config import GateConfig
from repo_publication_gate.scanner import scan_repository


def make_clean_repo(root: Path) -> None:
    for name in ["LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"]:
        (root / name).write_text("safe\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        "\n".join(
            [
                ".env",
                "*.pem",
                "*.key",
                "*.sqlite",
                "*.db",
                ".venv/",
                "node_modules/",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    (root / "app.py").write_text("print('safe')\n", encoding="utf-8")


class ScannerTests(unittest.TestCase):
    def test_clean_repository_passes(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            result = scan_repository(root, GateConfig())
            self.assertEqual(result.verdict, "PASS")
            self.assertEqual(result.findings, [])

    def test_env_file_blocks_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / ".env").write_text("SAFE_PLACEHOLDER=replace-me\n", encoding="utf-8")
            result = scan_repository(root, GateConfig(ignore_paths=[]))
            self.assertTrue(any(item.rule_id == "RPG001" for item in result.findings))
            self.assertEqual(result.verdict, "BLOCKED")

    def test_env_example_is_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / ".env.example").write_text("TOKEN=replace-me\n", encoding="utf-8")
            result = scan_repository(root, GateConfig(ignore_paths=[]))
            self.assertFalse(any(item.rule_id == "RPG001" for item in result.findings))

    def test_private_key_marker_is_critical(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            marker = "-----BEGIN " + "PRIVATE KEY-----\nsynthetic-placeholder\n"
            (root / "sample.txt").write_text(marker, encoding="utf-8")
            result = scan_repository(root, GateConfig())
            matches = [item for item in result.findings if item.rule_id == "RPG004"]
            self.assertEqual(matches[0].severity, "critical")

    def test_database_file_is_high(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / "runtime.sqlite").write_bytes(b"synthetic")
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG003" for item in result.findings))

    def test_large_file_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / "large.bin").write_bytes(b"x" * 101)
            config = GateConfig(max_file_size_bytes=100)
            result = scan_repository(root, config)
            self.assertTrue(any(item.rule_id == "RPG006" for item in result.findings))

    def test_local_windows_path_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            content = "path = " + "C:\\Users\\example\\private\\file.txt\n"
            (root / "config.txt").write_text(content, encoding="utf-8")
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG005" for item in result.findings))

    def test_local_unix_path_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / "config.txt").write_text(
                "path=" + "/" + "home/example/private/file.txt\n", encoding="utf-8"
            )
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG005" for item in result.findings))

    def test_missing_governance_warns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".gitignore").write_text(
                ".env\n*.pem\n*.key\n*.sqlite\n*.db\n.venv/\nnode_modules/\n",
                encoding="utf-8",
            )
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG009" for item in result.findings))
            self.assertEqual(result.verdict, "WARNING")

    def test_missing_gitignore_warns(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            for name in ["LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"]:
                (root / name).write_text("safe\n", encoding="utf-8")
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG010" for item in result.findings))

    def test_nested_cache_directory_is_ignored_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            cache = root / "src" / "package" / "__pycache__"
            cache.mkdir(parents=True)
            (cache / "module.pyc").write_bytes(b"synthetic")
            result = scan_repository(root, GateConfig())
            self.assertFalse(any(item.path.endswith("__pycache__") for item in result.findings))

    def test_generated_directory_is_reported_when_not_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            generated = root / "node_modules"
            generated.mkdir()
            (generated / "x.js").write_text("safe\n", encoding="utf-8")
            result = scan_repository(root, GateConfig(ignore_paths=[]))
            self.assertTrue(any(item.rule_id == "RPG007" for item in result.findings))

    def test_secret_assignment_is_reported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            value = "password" + " = " + "'synthetic-long-value'\n"
            (root / "settings.py").write_text(value, encoding="utf-8")
            result = scan_repository(root, GateConfig())
            self.assertTrue(any(item.rule_id == "RPG004" for item in result.findings))


if __name__ == "__main__":
    unittest.main()
