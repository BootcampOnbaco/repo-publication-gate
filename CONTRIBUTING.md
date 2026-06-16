# Contributing

Contributions are welcome.

## Good first contributions

- Add a narrowly scoped publication-risk rule.
- Add regression tests for false positives.
- Improve Windows, macOS, or Linux path handling.
- Improve report clarity.
- Add safe fixtures that contain no real secrets.
- Improve GitHub Actions integration.

## Development

```bash
python -m venv .venv
```

Windows:

```powershell
.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
```

## Pull-request requirements

- Keep changes scoped.
- Add or update tests.
- Do not include real secrets, credentials, private repositories, customer
  data, production logs, or personal documents.
- Document behavior changes.
- Explain expected false-positive and false-negative impact.
- Preserve deterministic output.

## Rule design

Each rule must define:

1. A stable rule ID.
2. Severity.
3. Evidence.
4. Why the finding matters before publication.
5. A practical remediation.
6. Tests for detection and non-detection.
