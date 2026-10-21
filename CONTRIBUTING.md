# Contributing to NetScope

Guidelines for reporting bugs, submitting documentation improvements, and contributing code to NetScope.

---

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/NeaCol/netscope.git
   cd netscope
   ```

2. **Create and activate a virtual environment:**
   ```bash
   python -m venv venv
   # On Linux/macOS:
   source venv/bin/activate
   # On Windows:
   venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   pip install pytest pytest-asyncio
   pip install -e .
   ```

---

## Running Tests

Before submitting any code changes, ensure all tests pass:

```bash
pytest tests/ -v
```

---

## Code Guidelines

- **Type Annotations**: Provide explicit type hints for function signatures.
- **Error Handling**: Gracefully handle missing network interfaces, permission restrictions, or unresolvable DNS queries.
- **Zero-Telemetry**: The dashboard and CLI must operate with zero external analytics or trackers.
- **Conventional Commits**: Format commit messages according to [Conventional Commits](https://www.conventionalcommits.org/):
  - `feat: ...`
  - `fix: ...`
  - `docs: ...`
  - `ci: ...`
  - `test: ...`
