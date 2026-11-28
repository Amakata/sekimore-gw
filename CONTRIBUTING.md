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
└── logger.py           # Logging utilities
```

The Web UI is `relay/src/webui/`, served by `sekimore-relay serve` (0.3.0-alpha.4).

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

### The host tool `sgw` (`relay/src/host/`)

The operator's binary on the host (#234) is a second binary of the relay crate, behind the
`host` feature so the image build never compiles it:

```bash
cd relay
cargo build --features host --bin sgw
cargo test --features host host          # the unit tests
cargo test --features host --test sgw    # end to end, against a fake docker on PATH
```

CI runs clippy and the tests with `--features test-hooks,host`. Its help and messages are the
`sgw.*` keys of `relay/locales/{en,ja}.json`.

### The equivalence harness (`relay/tests/equivalence/`)

0.3.0 moves the gateway from Python to Rust without changing what it does (#496). The harness
asks both implementations the same questions and compares the answers: how every config in
`relay/tests/fixtures/corpus/` is read (#498), what the Web UI answers (#493), and what the log
followers record, what `maint` answers and how the orchestrator reads the reload window's state
file that `maint` writes (#505; the cases are `relay/tests/fixtures/gateway/`).

```bash
cd relay
cargo test --test equivalence                              # the recorded answers, and live Python when uv is on PATH
SEKIMORE_E2E_REQUIRED=1 cargo test --test equivalence      # live Python required, as in CI
SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_config   # re-record relay/tests/fixtures/oracle/config.json
```

Re-record after changing the corpus or the Python side, and read the diff of the record: it is
Python's behaviour. A case that is known to differ carries a `# ledger: …` line in its header and
is listed in the 0.3.0 plan's difference ledger.

**The Web UI's record is fixed.** The Python UI was removed in the change that brought the Rust
one (0.3.0-alpha.4), so `relay/tests/fixtures/oracle/webui.json` is the only oracle of the `webui`
comparison and nothing re-records it from the current tree. It was recorded at commit `37335fc`,
the last with `src/web_ui/` in it. To record it again — after adding a case to
`relay/tests/fixtures/webui/cases.json`, say — record from that commit and bring the record back:

```bash
git worktree add ../webui-oracle 37335fc
cp relay/tests/fixtures/webui/cases.json ../webui-oracle/relay/tests/fixtures/webui/
(cd ../webui-oracle && uv sync --frozen && cd relay && \
  SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_web_ui_answers_as_python_did)
cp ../webui-oracle/relay/tests/fixtures/oracle/webui.json relay/tests/fixtures/oracle/
git worktree remove ../webui-oracle
```

A case whose files or requests that commit's harness cannot express needs a Rust test instead.

**The followers' and `maint`'s records are fixed** the same way: the Python log followers and
`src/maint.py` were removed in 0.3.0-alpha.5 (`python -m src.maint` now runs `sekimore-relay
maint`). They were recorded at commit `2f22f15`, the last with them in it:

```bash
git worktree add ../periphery-oracle 2f22f15
cp relay/tests/fixtures/gateway/*.json ../periphery-oracle/relay/tests/fixtures/gateway/
(cd ../periphery-oracle && uv sync --frozen && cd relay && \
  SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence the_followers_record_what_python_recorded && \
  SEKIMORE_ORACLE_RECORD=1 cargo test --test equivalence maint_answers_as_python_did)
cp ../periphery-oracle/relay/tests/fixtures/oracle/{followers,maint}.json relay/tests/fixtures/oracle/
git worktree remove ../periphery-oracle
```

`reload_state` is still compared with live Python, and re-recorded from the current tree
(`… the_orchestrator_reads_the_window_maint_writes`), until the orchestrator moves.

### The base image (`base/`)

The dev-container base image and the files it distributes live in `base/` and are released
from the same tag as the gateway (#235). Their tests are shell scripts, run directly:

```bash
base/tests/test_sgw_post_start.sh  # the dev container's start: setup, docker-init, post-create
base/tests/test_image.sh           # builds the image; needs docker
SGW_DEBIAN=trixie base/tests/test_image.sh   # the Debian 13 image (#507); CI runs both
```

That `UPGRADING.md` has been reviewed up to the gateway `base/Dockerfile` takes is a check in
`tools/` (`cargo test --test upgrading`, below).

The project template `sgw init` writes is `relay/templates/devcontainer/`, embedded in the
`sgw` binary; `relay/src/host/templates.rs` holds the two to each other, and
`docs/template.md` describes it. `tests/unit/test_base_versions.py`
holds every version written under `base/` to `pyproject.toml`'s.

### The sidecar template (`examples/sidecar-template/`)

The command sidecar a third party copies is Go, standard library only (#499). Its Go version is
written in `go.mod`, its `Dockerfile`, `mise.toml` and `relay.yml`, and
`the_go_version_agrees_across_the_files` holds them together:

```bash
cd examples/sidecar-template
gofmt -l . && go vet ./... && go test ./...
docker build -t sekimore-notes .
```

`relay/tests/command_sidecar.rs` builds it with `go build` and runs it through the gateway; `GO`
names a toolchain other than `go`. Without one the test is skipped, or fails under
`SEKIMORE_E2E_REQUIRED` (CI and `mise run ci`).

### The repository's tools and checks (`tools/`)

`tools/` is a crate of its own (#506): nothing in it ships in the image or in `sgw`. It holds two
tools and the checks that are about the repository rather than the gateway, run by
`mise run ci:tools` and the `Tools` workflow on every pull request:

```bash
cd tools
cargo test                              # every check below
cargo test --test changelog_style       # CHANGELOG.md / CHANGELOG.ja.md keep their shape
cargo test --test paths_ledger          # docs/paths.yml against the code (docs/paths.md)
cargo test --test supply_chain_pins     # actions, images, apt packages, the Debian snapshot's age, Dependabot
cargo test --test upgrading             # UPGRADING's reviewed-up-to marker
cargo test --test agent_setup_sh        # agent-setup.sh, with fake curl / ssh-keyscan
cargo run --bin paths -- edges          # ask the path ledger (docs/paths.md)
```

`lang-plan` is what `lang-images.yml` runs to decide which language images to build. It reads
`lang/` relative to where it runs, so run it from the repository root:
`cargo run --manifest-path tools/Cargo.toml --bin lang-plan -- pr --base <file> --changed <file>`.

`lang-plan` and `paths` replaced `lang/plan.py` and `scripts/paths.py` and print the same bytes:
`tests/plan_golden.rs` and `tests/paths_golden.rs` replay runs recorded from the Python versions.

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

Pull requests and pushes to `main` and `next` build an image for verification. **These images are not
releases.**

```bash
docker pull ghcr.io/Amakata/sekimore-gw:pr-61   # the image for that pull request
docker pull ghcr.io/Amakata/sekimore-gw:main    # the tip of main
docker pull ghcr.io/Amakata/sekimore-gw:next    # the tip of next (the 0.3 line)
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
2. Update the changelog: `CHANGELOG.md` and `CHANGELOG.ja.md`.
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
