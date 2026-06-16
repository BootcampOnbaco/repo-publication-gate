from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from repo_publication_gate.cli import main


def make_clean_repo(root: Path) -> None:
    for name in ["LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md"]:
        (root / name).write_text("safe\n", encoding="utf-8")
    (root / ".gitignore").write_text(
        ".env\n*.pem\n*.key\n*.sqlite\n*.db\n.venv/\nnode_modules/\n",
        encoding="utf-8",
    )


class CliTests(unittest.TestCase):
    def test_clean_repo_exit_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root)])
            self.assertEqual(code, 0)
            self.assertIn("PASS", output.getvalue())

    def test_high_finding_exit_one(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            make_clean_repo(root)
            (root / "data.db").write_bytes(b"synthetic")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), "--fail-on", "high"])
            self.assertEqual(code, 1)
            self.assertIn("BLOCKED", output.getvalue())

    def test_init_creates_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main([str(root), "--init"])
            self.assertEqual(code, 0)
            self.assertTrue((root / ".repo-publication-gate.toml").exists())

    def test_list_rules(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["--list-rules"])
        self.assertEqual(code, 0)
        self.assertIn("RPG001", output.getvalue())


if __name__ == "__main__":
    unittest.main()
