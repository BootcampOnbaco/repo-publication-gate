# v0.1.0 release checklist

## Before release

- [ ] Repository is public.
- [ ] Primary maintainer is correct.
- [ ] CI passes on Python 3.11 and 3.12.
- [ ] `repo-gate . --fail-on high` passes.
- [ ] README installation and examples are correct.
- [ ] No private files or real secrets are present.
- [ ] Security policy is visible.
- [ ] Private vulnerability reporting is enabled.

## Release

Tag: `v0.1.0`

Title:

```text
repo-publication-gate v0.1.0
```

Release notes:

```text
Initial public release of repo-publication-gate, a local-first CLI that checks
repositories for common publication risks including secrets, environment
files, private keys, databases, backups, generated directories, oversized
artifacts, local paths, nested Git metadata, and missing governance files.

The tool produces Markdown or JSON reports and stable exit codes for CI.
```

## Initial public issues

1. Add SARIF output for GitHub code scanning.
2. Add reviewed-findings baseline support.
3. Add optional Git-history scanning.
