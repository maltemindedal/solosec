# Running with Docker

The included `Dockerfile` bundles SoloSec with Trivy, Semgrep, and Gitleaks, so
you can scan a project without installing any of them.

No image is published to a registry — you build it locally.

## Build the image

From a clone of this repository:

```bash
docker build -t solosec:local .
```

The build pulls Trivy and Gitleaks from their upstream release channels. To pin
versions instead of taking the latest:

```bash
docker build -t solosec:local \
  --build-arg TRIVY_VERSION=0.58.1 \
  --build-arg GITLEAKS_VERSION=8.21.2 .
```

> **TODO(verify):** the two version numbers above are illustrative. The build
> accepts `TRIVY_VERSION` and `GITLEAKS_VERSION` arguments and defaults both to
> empty (latest), but this repository does not pin specific versions anywhere,
> so there is no known-good pair to document.

## Scan a project

Mount the project at `/src`:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" solosec:local
```

The report is written to `security_audit.json` in the mounted directory, owned
by your user.

Flags work exactly as they do natively — everything after the image name is
passed through:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" solosec:local --help
```

## Why the `--user` flag is required

The image runs as an unprivileged user (`solosec`, UID 10001). Without
`--user`, the container writes as UID 10001, which will not have permission to
create files in a bind-mounted directory owned by you. The scan fails partway
through with:

```
PermissionError: [Errno 13] Permission denied: '/src/.security_reports/semgrep.json'
```

Passing `--user "$(id -u):$(id -g)"` runs the container as you, so the report
lands with the right ownership.

On Docker Desktop for macOS and Windows the bind mount ignores UNIX ownership,
so the flag is unnecessary there — but it is harmless, so the commands above use
it unconditionally.

Because the container may run as any UID, the image keeps its scanner caches and
settings under `/var/tmp/solosec` rather than a fixed home directory, and sets
`safe.directory` system-wide so Gitleaks can read a repository owned by a
different user.

## Add a DAST scan

ZAP runs in its own container, so the SoloSec container needs to talk to the
Docker daemon. That means mounting the socket — and, because the container is
unprivileged, granting the socket's group:

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --group-add "$(getent group docker | cut -d: -f3)" \
    -v "$(pwd):/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    solosec:local --url "http://host.docker.internal:3000"
```

Without `--group-add`, the socket is unreadable and ZAP fails with
`permission denied while trying to connect to the Docker daemon socket`.

If your host's docker group is not named `docker`, read the group ID off the
socket instead:

```bash
--group-add "$(stat -c '%g' /var/run/docker.sock)"
```

### Reaching the target application

SoloSec rewrites `localhost` and `127.0.0.1` to `host.docker.internal`
automatically, so `--url http://localhost:3000` usually works from inside a
container.

On Linux, `host.docker.internal` is not resolvable by default. Either target a
service running in Docker by its container or network address, or add:

```bash
--add-host=host.docker.internal:host-gateway
```

### Report paths across containers

ZAP is started by the SoloSec container but runs as a *sibling* under the host's
Docker daemon, so the path SoloSec passes as a volume must be a **host** path,
not a container path. Set one of `SOLOSEC_HOST_REPORT_DIR`,
`SOLOSEC_HOST_WORKSPACE`, or `GITHUB_WORKSPACE` to supply it:

```bash
docker run --rm \
    --user "$(id -u):$(id -g)" \
    --group-add "$(stat -c '%g' /var/run/docker.sock)" \
    -e SOLOSEC_HOST_WORKSPACE="$(pwd)" \
    -v "$(pwd):/src" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    solosec:local --url "http://host.docker.internal:3000"
```

The GitHub Action sets `GITHUB_WORKSPACE` for you. See
[Configuration](../reference/configuration.md#environment-variables) for
precedence.

## Security note on the socket mount

Mounting `/var/run/docker.sock` grants the container effective root on the host,
because anything that can talk to the daemon can start a privileged container.
Only mount it when you need the DAST scan, and only for images you trust. The
static scanners need no socket at all — the first command in this guide is the
one to prefer.
