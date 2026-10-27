FROM python:3.12-slim-bookworm AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/home/runner

WORKDIR /opt/runner
COPY pyproject.toml README.md LICENSE ./
COPY vardrrunner ./vardrrunner
RUN pip install --no-cache-dir . \
    && useradd --uid 10001 --create-home runner \
    && mkdir -p /home/runner/.vardrmap \
    && chown runner:runner /home/runner/.vardrmap \
    && chmod 700 /home/runner/.vardrmap

USER 10001:10001
WORKDIR /home/runner
ENTRYPOINT ["vardrrunner"]
CMD ["--help"]

# Optional tool-enabled target; the default final target remains CLI-only.
# Supply the pinned Gate source as BuildKit's named `gate` context.
FROM golang:1.25 AS gate-build
WORKDIR /src
COPY --from=gate . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/vardrgate ./cmd/vardrgate

FROM base AS toolkit
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
RUN vardrrunner tools install --all \
    && chmod -R a+rX /opt/vardrtools \
    && rm -rf /home/runner/.config /home/runner/.cache /home/runner/.pdcp \
    && ln -s /home/runner/.vardrmap /home/runner/.config
# Some tools ignore XDG_CONFIG_HOME; both config paths must reach the state volume.
ENV XDG_CONFIG_HOME=/home/runner/.vardrmap \
    XDG_CACHE_HOME=/home/runner/.vardrmap/tool-cache
COPY --from=gate-build /out/vardrgate /usr/local/bin/vardrgate
USER 10001:10001

FROM base AS core
