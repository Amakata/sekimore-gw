# Contributing to sekimore-gw

Thank you for your interest in contributing to sekimore-gw! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.11+
- [uv](https://github.com/astral-sh/uv) package manager
- Docker 20.10+
- Docker Compose 2.0+
- Git

### Initial Setup

1. Fork and clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/sekimore-gw.git
cd sekimore-gw
```

2. Install dependencies:

```bash
uv sync
```

3. Verify the setup:

```bash
uv run pytest
uv run ruff check src/
```

## Development Workflow

### 1. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/your-bug-fix
```

### 2. Make Changes

- Write code following the project's coding standards
- Add tests for new functionality
- Update documentation as needed

### 3. Run Tests and Linters

Before committing, ensure all checks pass:

```bash
# Run tests
uv run pytest tests/unit/ -v

# Run linter
uv run ruff check src/
uv run ruff format src/

# Type check
uv run mypy src/

# Check coverage
uv run pytest --cov=src --cov-report=html
```

### 4. Commit Changes

Follow conventional commit format:

```bash
git commit -m "feat: add new domain filtering feature"
git commit -m "fix: resolve DNS resolution issue"
git commit -m "docs: update README with new examples"
git commit -m "test: add unit tests for firewall module"
```

Commit types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or modifications
- `refactor`: Code refactoring
- `chore`: Maintenance tasks
- `ci`: CI/CD changes

### 5. Push and Create Pull Request

```bash
git push origin feature/your-feature-name
```

Then create a Pull Request on GitHub.

## Code Standards

### Python Style

- Follow [PEP 8](https://peps.python.org/pep-0008/)
- Use type hints for function signatures
- Maximum line length: 100 characters (configured in pyproject.toml)
- Use `ruff` for linting and formatting

### Code Organization

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

- Use `pytest` with `pytest-describe` for BDD-style tests
- Aim for >80% code coverage
- Write unit tests for new functions/classes
- Add integration tests for complex workflows

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

- Add docstrings to all public functions and classes
- Use Google-style docstrings
- Update README.md for user-facing changes
- Update inline comments for complex logic

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

## Testing Guidelines

### Unit Tests

Place unit tests in `tests/unit/`:

```bash
tests/unit/
├── test_config.py
├── test_dns_server.py
└── test_firewall.py
```

Run unit tests:

```bash
uv run pytest tests/unit/ -v
```

### Integration Tests

Place integration tests in `tests/integration/`:

```bash
tests/integration/
└── test_orchestrator.py
```

### Functional Tests

Place functional tests in `tests/functional/`:

```bash
tests/functional/
└── test_end_to_end.py
```

## Docker Development

### Building the Image

```bash
docker build -t sekimore-gw:dev .
```

### Testing with Docker Compose

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f sekimore-gw

# Stop services
docker-compose down
```

## Pull Request Guidelines

### Before Submitting

- [ ] All tests pass
- [ ] Code is formatted with `ruff format`
- [ ] No linting errors (`ruff check`)
- [ ] Documentation is updated
- [ ] Commit messages follow conventional format
- [ ] Branch is up-to-date with master

### PR Description

Include:

1. **What**: Brief description of changes
2. **Why**: Motivation and context
3. **How**: Technical details if complex
4. **Testing**: How you tested the changes
5. **Screenshots**: For UI changes

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

## Code Review Process

1. Automated checks run on all PRs (CI/CD)
2. At least one maintainer review required
3. Address review comments promptly
4. Once approved, maintainers will merge

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG (if exists)
3. Create git tag: `git tag v0.0.2`
4. Push tag: `git push origin v0.0.2`
5. GitHub Actions will build and publish Docker image

## Getting Help

- Open an issue for bugs or feature requests
- Discuss in pull request comments
- Check existing issues and PRs first

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

Thank you for contributing to sekimore-gw!
