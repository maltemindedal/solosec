# SoloSec documentation

Every document in this directory, grouped by purpose. Start with
[Getting started](getting-started.md) if you have never run SoloSec.

## Tutorial — learning

For newcomers working through a first success end to end.

| Document | Covers |
| --- | --- |
| [Getting started](getting-started.md) | Install SoloSec and scan your first project. Assumes no prior knowledge. |

## How-to guides — tasks

Goal-oriented recipes. Each assumes you already have SoloSec working.

| Document | Covers |
| --- | --- |
| [Configuring scans](guides/configuring-scans.md) | Write a `.solosec.yaml`: exclude directories, disable tools, set a DAST target. |
| [Running with Docker](guides/running-with-docker.md) | Run the containerised scanner without installing the tools locally, including the DAST setup. |
| [Using SoloSec in CI](guides/ci-github-actions.md) | Wire the scan into GitHub Actions, in this repo or another one. |
| [Troubleshooting](guides/troubleshooting.md) | Diagnose skipped tools, permission errors, and unexpected exit codes. |

## Reference — lookup

Exhaustive and factual. For readers who already know what they want.

| Document | Covers |
| --- | --- |
| [CLI](reference/cli.md) | Every command, flag, and exit code across `solosec`, `solosec-config`, and `solosec-aggregate`. |
| [Configuration](reference/configuration.md) | Every `.solosec.yaml` key and environment variable, with types, defaults, and precedence. |
| [Report format](reference/report-format.md) | The `security_audit.json` schema and how each tool's severities are normalised. |

## Explanation — understanding

Background and rationale.

| Document | Covers |
| --- | --- |
| [Architecture overview](architecture/overview.md) | How the pieces fit together, the data flow through a scan, and the trade-offs behind non-obvious choices. |

## Contributing

| Document | Covers |
| --- | --- |
| [Contributing](contributing.md) | Development environment, the quality gate, and what CI enforces. |
