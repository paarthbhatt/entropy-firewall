# Contributing to Antigravity

First off, thanks for taking the time to contribute! 🎉

## Code of Conduct

This project adheres to the [Contributor Covenant](https://www.contributor-covenant.org/) code of conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

- Ensure the bug was not already reported by searching on GitHub under [Issues](https://github.com/your-username/entropy/issues).
- If you're unable to find an open issue addressing the problem, open a new one. Be sure to include a **title and clear description**, as well as as much relevant information as possible, and a **code sample** or an **executable test case** demonstrating the expected behavior that is not occurring.

### Suggesting Enhancements

- Open a new issue with a clear title and detailed description.
- Explain why this enhancement would be useful to most Entropy users.

### Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes (`pytest`).
5. Make sure your code lints (`ruff check .` or `flake8`).

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/entropy.git
cd entropy

# Create virtual env
python -m venv .venv
source .venv/bin/activate

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest
```

## Style Guide

- We use `ruff` for linting and formatting.
- Type hints are required for all new functions (`mypy` strict mode).
- Write docstrings for all public modules, classes, and functions (Google style).

## License

By contributing, you agree that your contributions will be licensed under its MIT License.
