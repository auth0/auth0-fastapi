# Git Workflow

## Branches

- Branch from `main`. Use a typed prefix that matches the change: `feat/<topic>`, `docs/<topic>`, `chore/<topic>`. Some branches use a Jira key instead (`SDK-8920-cte`).
- `release/<version>` branches (e.g. `release/1.0.0b12`) carry the release PR that bumps `.version`, `pyproject.toml`, and `CHANGELOG.md`. Don't create them as part of a feature change.
- Dependabot opens `dependabot/pip/*` and `dependabot/github_actions/*` branches daily. For pip it ignores semver-major bumps (`.github/dependabot.yml`).

## Commits

- Conventional commit subject: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `build:` (dependency floors), `chore:`, `revert:`. One line, lowercase after the prefix, no trailing period, and say what changed (e.g. `fix: relay the status Auth0 returned for passkey errors`).
- One logical change per commit. Docs, tests, and code for the same change can land as separate commits in one PR.
- The repo has no commitlint or pre-commit config. Reviewers enforce the format.

## Pull requests

Follow `.github/PULL_REQUEST_TEMPLATE.md`:

- **Changes:** what and why, including endpoints and classes or methods added, changed, or deprecated, plus a usage summary for public API changes.
- **References:** supporting links (ticket, community post).
- **Testing:** how reviewers test it, plus the unit coverage, integration coverage, and latest-platform checkboxes.
- **Checklist:** contribution guidelines, code of conduct, all tests pass.

CODEOWNERS assigns every path to `@auth0/project-dx-sdks-engineer-codeowner`. A Claude review workflow (`claude-code-review.yml`) responds to PR comments and reviews.
