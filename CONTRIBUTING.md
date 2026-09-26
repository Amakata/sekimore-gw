# Contributing to sekimore-gw

Thank you for your interest in contributing to sekimore-gw. This document describes how to set up a development environment and how to submit changes.

## Development setup

### Prerequisites

- Python 3.11 or later
- [uv](https://github.com/astral-sh/uv) package manager
- Docker 20.10 or later
- Docker Compose 2.0 or later
- Git

### Initial setup

1. Fork the repository and clone your fork:

```bash
git clone https://github.com/YOUR_USERNAME/sekimore-gw.git
cd sekimore-gw
```

2. Install the dependencies:

```bash
uv sync
```

3. Verify the setup:

```bash
uv run pytest -m "not e2e"
uv run ruff check src/
```

`mise run ci` runs the Rust and Python lints and tests in parallel.

## Development workflow

### 1. Create a branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make changes

- Follow the coding standards of the project.
- Add tests for new functionality.
- Update the documentation as needed.

### 3. Run the tests and linters

Before you commit, make sure that all checks pass:

```bash
# Run tests
uv run pytest tests/unit/ -v

# Run linter
uv run ruff check src/
uv run ruff format src/

# Type check
uv run mypy src/

# Check coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

### 4. Commit changes

Use the Conventional Commits format:

```bash
git commit -m "feat: add new domain filtering feature"
git commit -m "fix: resolve DNS resolution issue"
git commit -m "docs: update README with new examples"
git commit -m "test: add unit tests for firewall module"
```

Commit types:

- `feat`: a new feature
- `fix`: a bug fix
- `docs`: documentation changes
- `test`: new or modified tests
- `refactor`: code refactoring
- `chore`: maintenance tasks
- `ci`: CI/CD changes

### 5. Push and create a pull request

```bash
git push origin feature/your-feature-name
```

Then create a pull request on GitHub.

## Code standards

### Python style

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints in function signatures.
- Keep lines at 100 characters or fewer. This limit is configured in pyproject.toml.
- Use `ruff` for linting and formatting.

### Code organization

The following tree shows the main modules. It is not a complete listing of `src/`.

```
src/
├── __init__.py
├── config.py           # Configuration management
├── dns_server.py       # DNS server implementation
├── firewall.py         # Firewall management
├── orchestrator.py     # Main orchestrator
├── logger.py           # Logging utilities
└── web_ui/
    └── app.py          # Web UI application
```

### Testing

- Use `pytest` with `pytest-describe` for BDD-style tests.
- Aim for more than 80% code coverage.
- Write unit tests for new functions and classes.
- Add integration tests for complex workflows.

Example test structure:

```python
def describe_my_feature():
    """Tests for my new feature."""

    def it_does_something():
        """Test that it does something."""
        result = my_function()
        assert result is True
```

### Documentation

- Add docstrings to all public functions and classes.
- Use Google-style docstrings.
- Update README.md for user-facing changes.
- Update the Japanese translation (`*.ja.md`) next to each document that you change. See [docs/localization.md](docs/localization.md#documentation).
- Update the inline comments that explain complex logic.

Example docstring:

```python
def my_function(arg1: str, arg2: int) -> bool:
    """Short description.

    Longer description if needed.

    Args:
        arg1: Description of arg1
        arg2: Description of arg2

    Returns:
        Description of return value

    Raises:
        ValueError: When arg2 is negative
    """
```

## Testing guidelines

### Running the tests

```bash
# Unit tests
uv run pytest tests/unit/ -v

# Integration tests (includes timeout tests for infinite loop detection)
uv run pytest tests/integration/ -v

# All tests except E2E (for CI and the dev container)
uv run pytest -m "not e2e" -v

# E2E tests (require docker compose; run on the host machine only)
uv run pytest tests/e2e/ -v

# With coverage
uv run pytest --cov=src --cov-report=html -m "not e2e"
```

### Unit tests

Place unit tests in `tests/unit/`:

```bash
tests/unit/
├── test_config.py
├── test_dns_server.py
└── test_firewall.py
```

Run the unit tests:

```bash
uv run pytest tests/unit/ -v
```

### The base image (`base/`)

The dev-container base image and the files it distributes live in `base/` and are released
from the same tag as the gateway (#235). Their tests are shell scripts, run directly:

```bash
base/tests/test_sample_sgw.sh      # share/sgw/ and the sample agree
base/tests/test_upgrade.sh         # upgrade.sh against a fake GHCR and a fake raw.githubusercontent.com
base/tests/test_post_start.sh
base/tests/test_sgw_tty.sh
base/tests/test_wrapper_refresh.sh
base/tests/test_image.sh           # builds the image; needs docker
python3 base/scripts/check-upgrading.py
```

After changing anything under `base/share/sgw/` or `share/gateway.mise.*.toml`, run
`base/scripts/sync-sample-sgw.sh` so the sample follows. `tests/unit/test_base_versions.py`
holds every version written under `base/` to `pyproject.toml`'s.

### Integration tests

Place integration tests in `tests/integration/`:

```bash
tests/integration/
└── test_orchestrator.py
```

### Functional tests

Place functional tests in `tests/functional/`:

```bash
tests/functional/
└── test_end_to_end.py
```

### E2E tests

The E2E tests (`tests/e2e/`) verify actual port binding and Docker integration. They cover the
following:

- The DNS server binding to port 53
- Subnet auto-detection through the Docker API
- Actual DNS query responses

The E2E tests must run on a host machine with `docker compose`, not in CI or in a dev container.
Stop any existing containers first, and then run `uv run pytest tests/e2e/ -v`. The E2E tests
carry the `e2e` marker, so `-m "not e2e"` deselects them.

## Docker development

### Build the image

```bash
docker build -t sekimore-gw:dev .
```

### Pull from GitHub Container Registry

```bash
docker pull ghcr.io/Amakata/sekimore-gw:latest
```

### Preview images

Pull requests and pushes to `main` build an image for verification. **These images are not
releases.**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # the image for that pull request
docker pull ghcr.io/Amakata/sekimore-gw:main    # the tip of main
```

Preview images are built for `linux/arm64` only. The next push overwrites the tag, so no
long-running deployment should reference it. Version tags (`:0.2.14`) and `:latest` are created
only from a `v*.*.*` Git tag.

Preview images separate deploying a change for testing from publishing a version. Without them,
testing a change on a real machine would require a release.

### Test with Docker Compose

```bash
# Start services
docker compose up -d

# View logs
docker compose logs -f sekimore-gw

# Stop services
docker compose down
```

## Pull request guidelines

### Before you submit

- [ ] All tests pass.
- [ ] The code is formatted with `ruff format`.
- [ ] `ruff check` reports no errors.
- [ ] The documentation is updated.
- [ ] The commit messages follow the Conventional Commits format.
- [ ] The branch is up to date with `main`.

### Pull request description

Include the following sections:

1. **What**: a brief description of the changes
2. **Why**: the motivation and context
3. **How**: technical details, if the change is complex
4. **Testing**: how you tested the changes
5. **Screenshots**: for UI changes

Example:

```markdown
## What
Add support for IPv6 address filtering

## Why
Users requested IPv6 support for allow/block lists

## How
- Extended IPManager to handle IPv6 CIDR notation
- Added ipset family detection
- Updated configuration validation

## Testing
- Added unit tests for IPv6 parsing
- Tested with IPv6-enabled Docker network
- Verified backward compatibility with IPv4

## Related Issues
Fixes #123
```

## Code review process

1. Automated checks (CI/CD) run on every pull request.
2. At least one maintainer must review the pull request.
3. Address review comments promptly.
4. After the pull request is approved, a maintainer merges it.

## Release process

1. Update the version in `pyproject.toml` and in `relay/Cargo.toml`.
2. Update the changelogs: `CHANGELOG.md`, `CHANGELOG.ja.md`, `relay/CHANGELOG.md` and `relay/CHANGELOG.ja.md`.
3. Create the git tag: `git tag v0.0.2`.
4. Push the tag: `git push origin v0.0.2`.
5. GitHub Actions builds and publishes the Docker image.

## Getting help

- Open an issue to report a bug or request a feature.
- Discuss changes in pull request comments.
- Check the existing issues and pull requests first.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.

Thank you for contributing to sekimore-gw.
