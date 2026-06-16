# Publish to GitHub

## Repository settings

- Owner: `BootcampOnbaco`
- Name: `repo-publication-gate`
- Visibility: `Public`
- Description: `Local-first security and governance gate for repositories before publication.`

## Web upload

Create an empty public repository without adding a README, `.gitignore`, or
license. Upload the contents of this directory, not the ZIP itself.

Commit message:

```text
Initial public release: repo-publication-gate v0.1.0
```

## Git CLI

```bash
git init
git add .
git commit -m "Initial public release: repo-publication-gate v0.1.0"
git branch -M main
git remote add origin https://github.com/BootcampOnbaco/repo-publication-gate.git
git push -u origin main
```

## After publication

1. Confirm the repository is public.
2. Confirm CI passes.
3. Create release `v0.1.0`.
4. Open the roadmap issues listed in `RELEASE_CHECKLIST.md`.
5. Enable private vulnerability reporting in repository security settings.
6. Add repository topics:
   - `security`
   - `oss`
   - `repository`
   - `secrets`
   - `release`
   - `python`
   - `cli`
