# AGENTS.md

## Dev Environment

- Use `uv` with Python 3.11. Local setup and CI both use `uv sync`; CI specifically runs `uv sync --frozen`.
- Mirror CI verification order when checking changes: `uv run ruff format --check .`, `uv run ruff check .`, `uv run pyright`, `uv run pytest`.
- Ruff targets `src`, `tests`, and `bin`; Pyright is `strict` and also checks `src`, `tests`, and `bin`.

## Entry Points

- Main package code lives in `src/solosec/`.
- CLI entrypoint is `solosec.cli:main`; `python -m solosec` goes through `src/solosec/__main__.py`.
- Helper CLIs also exist: `solosec-config` resolves `.solosec.yaml`, and `solosec-aggregate` aggregates JSON reports from `.security_reports/`.
- `bin/solosec.sh` and `bin/solosec.ps1` are source-checkout wrappers; when `uv` is available they run `uv run --directory <repo> solosec`.

## Runtime Behavior

- `solosec` writes tool outputs to `.security_reports/` and the combined report to `security_audit.json` at the scanned project root.
- Running the CLI can append `.security_reports/` to the target repo's `.gitignore` if that entry is missing.
- Aggregation fails the process on `HIGH` or `CRITICAL` findings only.
- Trivy and Gitleaks are external executables expected on `PATH`; Semgrep is a Python dependency from this repo's environment; ZAP runs via `docker`.

## Config And Test Gotchas

- `.solosec.yaml` is parsed by a small custom parser in `src/solosec/config.py`, not a full YAML library. Keep configs simple: top-level scalars, `exclude_dirs`, and `tools` only.
- CLI `--url` overrides config `target_url`/`url`; if `tools.zap` is false, the resolved URL is cleared entirely.
- For focused verification, run individual tests with pytest node paths, e.g. `uv run pytest tests/test_config.py -q` or `uv run pytest tests/test_cli.py -q`.
- Aggregation tests use static fixtures in `tests/fixtures/`; CLI tests monkeypatch tool runners instead of invoking real scanners.

## CI / Action

- `.github/workflows/ci.yml` has two jobs: `quality` first, then `scan`.
- The composite action in `action.yml` builds this repo's `Dockerfile`, runs the container against `${GITHUB_WORKSPACE}`, and mounts `/var/run/docker.sock` so optional ZAP scans can launch.
