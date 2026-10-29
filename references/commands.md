# Commands

Run everything through Poetry. CI pins Poetry 2.2.1 and creates the virtualenv in-project (`.github/workflows/tests.yml`).

```bash
# Install runtime and dev dependencies
poetry install

# Lint (the exact CI step)
poetry run ruff check .

# Auto-fix lint findings in the files you changed
poetry run ruff check --fix <path>

# Run all unit tests (pyproject.toml addopts add coverage and an htmlcov/ report)
poetry run pytest

# Run tests the way CI does
poetry run pytest --cov=auth0_fastapi --cov-report=xml --cov-report=term-missing

# Run one test file, one class, or one test
poetry run pytest src/auth0_fastapi/test/test_routes.py
poetry run pytest src/auth0_fastapi/test/test_auth_client.py::TestPasskey
poetry run pytest -k "passkey"

# Build the sdist and wheel into dist/
poetry build
```

## Not available

- **Formatter:** CI does not run `ruff format`, and running it reformats files the task didn't touch. Format by hand to match the surrounding code.
- **Type checker:** no mypy or pyright configuration exists.
- **Clean target:** none. Generated output (`dist/`, `htmlcov/`, `.coverage`, `.pytest_cache/`) is not tracked in git.

## CI-only jobs

- `sca_scan.yml` installs `requirements.txt` into a venv and runs the Snyk scan from `auth0/devsecops-tooling`.
- `codeql.yml` runs CodeQL analysis.
- `publish.yml` is a manual `workflow_dispatch` release that reads the version from `.version`, runs the RL scanner, creates the GitHub release, and publishes to PyPI. Agents don't run it.
