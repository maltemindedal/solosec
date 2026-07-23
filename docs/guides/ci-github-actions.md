# Using Gavel in CI

Gavel exits non-zero when it finds Critical or High issues, which is all most
CI systems need to turn a build red. This guide covers the bundled GitHub
Actions workflow and the reusable action.

## How the gate works

GitHub Actions decides pass or fail from the process exit code:

| Exit code | Result |
| --- | --- |
| `0` | Job passes |
| non-zero | Job fails |

Gavel exits `1` when any Critical or High finding is present. Medium and below
are reported but do not fail the job. See
[Exit codes](../reference/cli.md#exit-codes).

One caveat worth designing around: **a scanner that fails to run does not fail
the build.** Its error is printed as a warning and the scan continues. Treat a
green build as "no High or Critical findings *in the reports that were
produced*", and check the log or `tools_run` in the report if you need
certainty that every scanner ran.

## The workflow in this repository

`.github/workflows/ci.yml` runs on pushes to `main`, on pull requests, and on
manual dispatch. It has two jobs:

- **`quality`** — formatting, linting, type checking, and tests. See
  [Contributing](../contributing.md).
- **`scan`** — runs Gavel on this repository via the local action. Requires
  `quality` to pass first.

To run a DAST scan, trigger the workflow manually from the Actions tab and
supply the `url` input. On pushes and pull requests that input is empty, so ZAP
is skipped.

Both jobs declare `permissions: contents: read`, restricting the `GITHUB_TOKEN`
to the minimum the scan needs.

## Using Gavel from another repository

This repository ships a composite action at `action.yml`. Add a step:

```yaml
- name: Gavel scan
  uses: maltemindedal/gavel@main
  with:
    upload-artifact: true
    artifact-name: gavel-report
```

> **This repository has no tags or releases.** Pinning to `@v1` will fail
> because that ref does not exist. Until a release is published, reference
> `@main` or a specific commit SHA. Pinning to a SHA is the safer choice — a
> branch ref can change under you, and this action executes a Docker build.

To enable DAST, add a `url`:

```yaml
- name: Gavel scan
  uses: maltemindedal/gavel@main
  with:
    url: http://host.docker.internal:3000
    upload-artifact: true
```

Start the target application in an earlier step; the action does not start it
for you.

### Action inputs

| Input | Default | Effect |
| --- | --- | --- |
| `url` | none | DAST target. Omit to skip ZAP. |
| `upload-artifact` | `"true"` | Whether to upload the reports as a build artifact. |
| `artifact-name` | `"gavel-report"` | Name of the uploaded artifact. |

The action has no outputs. Consume the result via the step's exit status, or by
downloading the artifact.

### What the action does

1. Builds the bundled `Dockerfile` as `gavel:action`.
2. Runs it against `GITHUB_WORKSPACE`, mounted at `/src`, as the runner's own
   user ID, with the Docker socket mounted for the optional ZAP scan.
3. Uploads `security_audit.json` and `.security_reports/**` as an artifact —
   with `if: always()`, so reports survive a failing scan.

Because step 1 builds the image on every run, expect roughly a minute of build
time before scanning starts.

The uploaded artifact contains raw scanner output. Gitleaks findings are
redacted before they reach `security_audit.json`, but `.security_reports/` holds
each tool's unmodified report — treat the artifact as sensitive and keep it
private.

## Other CI systems

Nothing in Gavel is GitHub-specific. Any runner that can build a container and
read an exit code will work:

```bash
docker build -t gavel:ci .
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/src" gavel:ci
```

The non-zero exit fails the job. For DAST, add the socket mount and
`GAVEL_HOST_WORKSPACE` as described in
[Running with Docker](running-with-docker.md#report-paths-across-containers).
