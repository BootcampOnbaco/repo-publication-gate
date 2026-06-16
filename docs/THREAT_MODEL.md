# Threat model

## Protected assets

- Credentials and API tokens.
- Private keys and certificates.
- Personal or customer data.
- Local databases and backups.
- Internal file paths and infrastructure details.
- Repository integrity and maintainer trust.

## Primary failure scenario

A maintainer publishes a repository or release containing material that was
safe only inside a local or private working environment.

## Threats addressed

- Accidental commit of `.env` files.
- Embedded credential strings.
- Private keys.
- Local SQLite/database files.
- Backups and dumps.
- Generated or runtime directories.
- Oversized artifacts.
- Nested repositories.
- Absolute workstation paths.
- Missing security/governance documents.
- Insufficient `.gitignore` coverage.

## Threats not fully addressed

- Secrets hidden in binary formats.
- Obfuscated credentials.
- Historical secrets already present in Git history.
- Legal ownership, licensing, export-control, or privacy compliance.
- Vulnerable dependencies.
- Malicious code behavior.
- Information inferred across multiple harmless-looking files.

## Trust boundaries

The target repository is untrusted input. The scanner must not execute target
files, import target modules, follow external network links, or upload content.

## Design principles

- Local-first.
- Read-only by default.
- Deterministic results.
- No target-code execution.
- Explicit evidence.
- Human review remains mandatory.
