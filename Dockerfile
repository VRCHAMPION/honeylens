# HoneyLens Python image: used by the migrate, pipeline, report and simulator services.
#
# Why multi-stage: the "build" stage has pip and build tools; the final stage
# only gets the installed package. Smaller image = fewer vulnerabilities.
# Base image is pinned to an exact version and is multi-arch (amd64 + arm64),
# so it runs on Intel/AMD laptops, Apple Silicon Macs and Oracle Ampere ARM VMs.

FROM python:3.12.13-slim-trixie AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir .

FROM python:3.12.13-slim-trixie
LABEL org.opencontainers.image.title="honeylens" \
      org.opencontainers.image.description="HoneyLens pipeline, report and simulator" \
      org.opencontainers.image.licenses="MIT"
ENV PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HL_MIGRATIONS_DIR=/app/db/migrations
# Apply Debian security updates available today (Trivy found fixable HIGH/CRITICAL
# CVEs in the base image), then remove the package lists to keep the image small.
# hadolint ignore=DL3008
RUN apt-get update \
 && apt-get -y upgrade --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
# Non-root user with a fixed UID so volume permissions are predictable.
RUN groupadd --system --gid 10001 honeylens \
 && useradd --system --uid 10001 --gid honeylens --home-dir /app --shell /usr/sbin/nologin honeylens
COPY --from=build /opt/venv /opt/venv
COPY db/migrations /app/db/migrations
# Folders for named volumes. Docker copies this ownership into a NEW empty
# named volume, so the non-root user can write there.
RUN mkdir -p /synthetic /out \
 && chown 10001:10001 /synthetic /out
WORKDIR /app
USER 10001:10001
# Default command; Compose overrides it per service.
CMD ["honeylens-pipeline"]
