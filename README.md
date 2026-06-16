# repo-publication-gate

Local-first CLI that audits a repository before it becomes public or before a
release is published.

It detects common publication risks such as secrets, private keys, `.env`
files, local database files, generated directories, oversized artifacts,
absolute workstation paths, nested Git repositories, and missing governance
files. It produces a deterministic `PASS`, `WARNING`, or `BLOCKED` report in
Markdown or JSON.

## Why this project exists

Repositories are often made public from working directories that contain
runtime leftovers, backups, local databases, credentials, private paths, or
missing security documentation. Manual review is inconsistent and difficult
to reproduce.

`repo-publication-gate` turns that review into a repeatable pre-publication
control suitable for maintainers, release workflows, and CI.

## Maintainer

- Primary maintainer: [@BootcampOnbaco](https://github.com/BootcampOnbaco)
- Repository: `https://github.com/BootcampOnbaco/repo-publication-gate`

## Current status

`v0.1.0` — functional initial release.

The scanner is intentionally conservative. Findings are evidence for human
review, not proof that a repository is safe.

## Features

- Local-only scanning; no repository content is uploaded.
- Secret and private-key pattern detection.
- Detection of `.env`, database, backup, certificate, and key files.
- Oversized-file detection.
- Generated/runtime directory detection.
- Nested `.git` detection.
- Absolute local workstation path detection.
- Governance checks for `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and
  `CODE_OF_CONDUCT.md`.
- `.gitignore` coverage checks.
- Configurable ignore rules and thresholds.
- Markdown and JSON reports.
- Stable exit codes for CI.
- Standard-library-only runtime.

## Installation

Requires Python 3.11 or newer.

### From the repository

```bash
python -m pip install -e .
```

### Development installation

```bash
python -m pip install -e ".[dev]"
```

## Quick start

Scan the current directory:

```bash
repo-gate .
```

Write a Markdown report:

```bash
repo-gate . --format markdown --output publication-gate-report.md
```

Write JSON for automation:

```bash
repo-gate . --format json --output publication-gate-report.json
```

Fail CI on medium-or-higher findings:

```bash
repo-gate . --fail-on medium
```

Create a starter configuration:

```bash
repo-gate --init
```

List implemented rules:

```bash
repo-gate --list-rules
```

## Verdicts

| Verdict | Meaning |
|---|---|
| `PASS` | No findings were detected. |
| `WARNING` | Reviewable low/medium findings exist. |
| `BLOCKED` | At least one high/critical publication risk exists. |

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | No finding met the configured failure threshold. |
| `1` | At least one finding met the failure threshold. |
| `2` | Operational/configuration error. |

## Configuration

Create `.repo-publication-gate.toml`:

```toml
[gate]
fail_on = "high"
max_file_size_bytes = 5242880
content_scan_max_bytes = 1048576
ignore_paths = [
  ".git/**",
  "**/.git/**",
  ".venv/**",
  "**/.venv/**",
  "node_modules/**",
  "**/node_modules/**",
]
allow_paths = [
  ".env.example",
]
```

Command-line options override configuration values where applicable.

## GitHub Actions

```yaml
- name: Repository publication gate
  run: |
    python -m pip install .
    repo-gate . --fail-on high --format markdown --output publication-gate-report.md
```

The included CI workflow runs unit tests and scans this repository.

## Security limitations

This tool reduces publication risk but cannot prove the absence of secrets,
personal data, vulnerable dependencies, or legal/licensing problems. Binary
files are checked by filename and size but are not deeply inspected.

Read [SECURITY.md](SECURITY.md) and
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).

## License

MIT.
