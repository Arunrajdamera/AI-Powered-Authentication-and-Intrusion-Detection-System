# Contributing

Thank you for your interest in improving this project.

## Development Setup

1. Fork or clone the repository.
2. Create a virtual environment.
3. Install dependencies:

```bash
pip install -r requirements.txt
```

4. Copy `.env.example` to `.env` and configure local values.
5. Initialize the database:

```bash
python scripts/seed_admin.py
```

6. Run tests:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Contribution Guidelines

- Keep security-sensitive values out of Git.
- Do not commit `.env`, database files, logs, caches, or virtual environments.
- Add or update tests for behavior changes.
- Keep routes, services, models, and ML code modular.
- Use clear commit messages.
- Document any new setup or usage steps in `README.md`.

## Pull Request Checklist

- Tests pass locally.
- No secrets are committed.
- Documentation is updated where needed.
- Generated runtime files are not included.
- Changes are focused and easy to review.
