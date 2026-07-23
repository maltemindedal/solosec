# Gavel - Docker image (containerized runner)
# Build:
#   docker build -t gavel:local .
# Run (the image is unprivileged, so --user is required on Linux for the report
# to be writable back into the bind-mounted project):
#   docker run --rm --user "$(id -u):$(id -g)" -v "$(pwd):/src" gavel:local
# With DAST, which additionally needs the docker socket and its group:
#   docker run --rm --user "$(id -u):$(id -g)" \
#     --group-add "$(getent group docker | cut -d: -f3)" \
#     -v "$(pwd):/src" -v /var/run/docker.sock:/var/run/docker.sock \
#     gavel:local -u "http://host.docker.internal:3000"

FROM python:3.11-slim-bookworm

# Optional build args for reproducible builds
ARG TRIVY_VERSION=
ARG GITLEAKS_VERSION=

ENV PYTHONUNBUFFERED=1 \
    PYTHONUTF8=1 \
  UV_LINK_MODE=copy \
  UV_COMPILE_BYTECODE=1 \
  UV_PYTHON_DOWNLOADS=never

# Base utilities + docker CLI (for optional ZAP runs)
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      bash \
      ca-certificates \
      curl \
      git \
      gzip \
      tar \
      docker.io \
 && rm -rf /var/lib/apt/lists/*

# Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
  | sh -s -- -b /usr/local/bin ${TRIVY_VERSION}

# uv + Gavel runtime dependencies
RUN curl -LsSf https://astral.sh/uv/install.sh | sh \
 && ln -sf /root/.local/bin/uv /usr/local/bin/uv

# Gitleaks
RUN set -eu; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch="linux_x64" ;; \
      arm64) gl_arch="linux_arm64" ;; \
      *) echo "Unsupported architecture for gitleaks: $arch" >&2; exit 1 ;; \
    esac; \
    if [ -z "${GITLEAKS_VERSION}" ]; then \
      GITLEAKS_VERSION="$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | head -n 1 | sed -E 's/.*"v?([^\"]+)\".*/\1/')"; \
    fi; \
    url="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_${gl_arch}.tar.gz"; \
    curl -sSL "$url" -o /tmp/gitleaks.tgz; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    rm -f /tmp/gitleaks.tgz; \
    chmod +x /usr/local/bin/gitleaks

# Copy Gavel scripts into the image
WORKDIR /opt/gavel
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src/ ./src/
COPY bin/ ./bin/

RUN uv sync --frozen --no-dev \
 && chmod +x ./bin/gavel ./bin/gavel.sh \
 && ln -sf /opt/gavel/.venv/bin/gavel /usr/local/bin/gavel

ENV PATH="/opt/gavel/.venv/bin:${PATH}"

# Run as a non-root user. Callers are also expected to override the uid to match
# the owner of the bind-mounted project (see action.yml), so every path the tools
# write to at runtime must be usable by an arbitrary uid -- hence the sticky
# world-writable state directory rather than a real home under /home.
RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin gavel \
 && mkdir -p /var/tmp/gavel \
 && chmod 1777 /var/tmp/gavel

ENV HOME=/var/tmp/gavel \
    XDG_CACHE_HOME=/var/tmp/gavel/cache \
    XDG_CONFIG_HOME=/var/tmp/gavel/config \
    XDG_DATA_HOME=/var/tmp/gavel/data \
    TRIVY_CACHE_DIR=/var/tmp/gavel/cache/trivy \
    SEMGREP_SETTINGS_FILE=/var/tmp/gavel/config/semgrep/settings.yml

# /src is owned by the host user, so git (and therefore gitleaks) would otherwise
# refuse to operate on it under a different uid. Set system-wide rather than via
# GIT_CONFIG_* env vars so it survives any HOME the caller supplies.
RUN git config --system --add safe.directory '*'

USER gavel

# The scanned project is expected to be bind-mounted at /src
WORKDIR /src

ENTRYPOINT ["gavel"]
