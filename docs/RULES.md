# Rules

| Rule ID | Default severity | Description |
|---|---|---|
| `RPG001` | high | Environment file likely contains secrets. |
| `RPG002` | high | Private key/certificate or credential container. |
| `RPG003` | high | Local database, dump, or backup artifact. |
| `RPG004` | high | Secret-like content pattern. |
| `RPG005` | medium | Absolute local workstation path. |
| `RPG006` | medium | Oversized file. |
| `RPG007` | medium | Generated/runtime directory present. |
| `RPG008` | high | Nested Git repository/worktree metadata. |
| `RPG009` | low | Recommended governance document missing. |
| `RPG010` | medium | `.gitignore` lacks recommended protection. |
| `RPG011` | medium | Symlink present and requires manual review. |

Severity reflects default publication risk, not certainty.
