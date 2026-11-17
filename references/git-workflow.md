# Git Workflow

## Branches

- Branch from `main`. Use a typed prefix that matches the change: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `test/<topic>`, `chore/<topic>`.
- `release/<version>` branches carry the release PR that bumps `.version`, `pyproject.toml`, and `CHANGELOG.md`. Don't create them as part of a feature change.
- Dependabot opens `dependabot/pip/*` and `dependabot/github_actions/*` branches daily. For pip it ignores semver-major bumps (`.github/dependabot.yml`).

## Commits

- Conventional commit subject: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:` (dependency floors), `chore:`, `revert:`. One line, lowercase after the prefix, no trailing period, and say what changed (e.g. `fix: relay the status Auth0 returned for passkey errors`).
- One logical change per commit. Docs, tests, and code for the same change can land as separate commits in one PR.
- The repo has no commitlint or pre-commit config, so nothing checks the format automatically.

## Pull requests

Follow `.github/PULL_REQUEST_TEMPLATE.md`:

- **Changes:** what and why, including endpoints and classes or methods added, changed, or deprecated, plus a usage summary for public API changes.
- **References:** supporting links (ticket, community post).
- **Testing:** how reviewers test it, plus the unit coverage, integration coverage, and latest-platform checkboxes.
- **Checklist:** contribution guidelines, code of conduct, all tests pass.

The `claude-code-review.yml` workflow is triggered by PR comments and reviews.
