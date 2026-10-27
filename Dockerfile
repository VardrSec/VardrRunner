FROM python:3.12-slim-trixie@sha256:12316debbfb86890f6b2d825820612741ba527ad5a44e3902759141d572bfe8f AS base

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
FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gate-build
WORKDIR /src
COPY --from=gate . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/vardrgate ./cmd/vardrgate

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS katana-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-katana-build \
    && go get github.com/projectdiscovery/katana/cmd/katana@v1.8.0 \
        github.com/jackc/pgx/v5@v5.9.2 golang.org/x/net@v0.60.0 github.com/klauspost/compress@v1.18.7 \
    && go build -trimpath -o /out/katana github.com/projectdiscovery/katana/cmd/katana \
    && go version -m /out/katana > /out/build-info.txt \
    && sha256sum /out/katana > /out/katana.sha256 \
    && cp go.mod go.sum /out/

FROM base AS toolkit
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
COPY --from=katana-build /out/ /tmp/katana-build/
COPY container/katana_install.py /tmp/katana_install.py
RUN python -c 'from vardrrunner import toolchain; [toolchain.install(n) for n in toolchain.manageable_tools() if n != "katana"]' \
    && python /tmp/katana_install.py \
    && rm -rf /tmp/katana-build /tmp/katana_install.py \
    && chmod -R a+rX /opt/vardrtools \
    && rm -rf /home/runner/.config /home/runner/.cache /home/runner/.pdcp \
    && ln -s /home/runner/.vardrmap /home/runner/.config
# Some tools ignore XDG_CONFIG_HOME; both config paths must reach the state volume.
ENV XDG_CONFIG_HOME=/home/runner/.vardrmap \
    XDG_CACHE_HOME=/home/runner/.vardrmap/tool-cache
COPY --from=gate-build /out/vardrgate /usr/local/bin/vardrgate
USER 10001:10001

FROM base AS core
