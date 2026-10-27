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
        github.com/jackc/pgx/v5@v5.9.2 golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.18.7 \
    github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/katana github.com/projectdiscovery/katana/cmd/katana \
    && go version -m /out/katana > /out/build-info.txt \
    && sha256sum /out/katana > /out/katana.sha256 \
    && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS dnsx-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-dnsx-build \
    && go get github.com/projectdiscovery/dnsx/cmd/dnsx@v1.3.1 \
        golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.18.7 \
    github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/dnsx github.com/projectdiscovery/dnsx/cmd/dnsx \
    && go version -m /out/dnsx > /out/build-info.txt \
    && sha256sum /out/dnsx > /out/dnsx.sha256 \
    && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS naabu-build
WORKDIR /src
ENV CGO_ENABLED=1 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN apt-get update && apt-get install -y --no-install-recommends libpcap-dev \
    && rm -rf /var/lib/apt/lists/*
RUN go mod init vardrrunner-naabu-build \
    && go get github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1 \
        golang.org/x/net@v0.62.0 golang.org/x/crypto@v0.58.0 github.com/klauspost/compress@v1.18.7 \
    github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/naabu github.com/projectdiscovery/naabu/v2/cmd/naabu \
    && go version -m /out/naabu > /out/build-info.txt \
    && sha256sum /out/naabu > /out/naabu.sha256 \
    && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gau-source
WORKDIR /src
ENV GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-gau-source \
    && go get github.com/lc/gau/v2/cmd/gau@v2.2.4 && go mod verify \
    && mkdir /out \
    && go mod download -json github.com/lc/gau/v2@v2.2.4 > /out/upstream-module.json \
    && cp -a "$(go list -m -f '{{.Dir}}' github.com/lc/gau/v2)" /out/source \
    && chmod -R u+w /out/source

FROM base AS gau-patch
USER root
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
COPY --from=gau-source /out/ /build/
COPY container/go_tool_install.py /build/go_tool_install.py
RUN python /build/go_tool_install.py --patch-gau

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS gau-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
COPY --from=gau-patch /build/source/ ./
COPY --from=gau-patch /build/provenance/ /out/
RUN go get golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.18.7 \
        github.com/sirupsen/logrus@v1.9.3 github.com/valyala/fasthttp@v1.34.0 \
    && go mod verify && go build -trimpath -o /out/gau ./cmd/gau \
    && go version -m /out/gau > /out/build-info.txt \
    && sha256sum /out/gau > /out/gau.sha256 \
    && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS httpx-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-httpx-build     && go get github.com/projectdiscovery/httpx/cmd/httpx@v1.12.0         golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.18.7     github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/httpx github.com/projectdiscovery/httpx/cmd/httpx     && go version -m /out/httpx > /out/build-info.txt     && sha256sum /out/httpx > /out/httpx.sha256     && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS subfinder-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-subfinder-build     && go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder@v2.17.0         golang.org/x/net@v0.62.0 github.com/klauspost/compress@v1.18.7     github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/subfinder github.com/projectdiscovery/subfinder/v2/cmd/subfinder     && go version -m /out/subfinder > /out/build-info.txt     && sha256sum /out/subfinder > /out/subfinder.sha256     && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS ffuf-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-ffuf-build     && go get github.com/ffuf/ffuf/v2@v2.3.0         golang.org/x/net@v0.62.0     && go build -trimpath -ldflags "-X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION=2.3.0 -X github.com/ffuf/ffuf/v2/pkg/ffuf.VERSION_APPENDIX=" -o /out/ffuf github.com/ffuf/ffuf/v2     && go version -m /out/ffuf > /out/build-info.txt     && sha256sum /out/ffuf > /out/ffuf.sha256     && cp go.mod go.sum /out/

FROM golang:1.27.3@sha256:9048d5e7751706200eb1719c7dae0436950d362f29a1da91fa05e5c63867c60f AS nuclei-build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org
RUN go mod init vardrrunner-nuclei-build     && go get github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.11.1         github.com/getkin/kin-openapi@v0.149.0 github.com/go-git/go-git/v5@v5.19.2         golang.org/x/crypto@v0.58.0 golang.org/x/mod@v0.41.0 golang.org/x/net@v0.62.0         golang.org/x/text@v0.43.0 google.golang.org/grpc@v1.83.2     github.com/yuin/goldmark@v1.7.17 \n    && go build -trimpath -o /out/nuclei github.com/projectdiscovery/nuclei/v3/cmd/nuclei     && go version -m /out/nuclei > /out/build-info.txt     && sha256sum /out/nuclei > /out/nuclei.sha256     && cp go.mod go.sum /out/

FROM base AS toolkit
USER root
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/*
ENV VARDRRUNNER_TOOLS_DIR=/opt/vardrtools
COPY --from=katana-build /out/ /tmp/katana-build/
COPY --from=dnsx-build /out/ /tmp/dnsx-build/
COPY --from=naabu-build /out/ /tmp/naabu-build/
COPY --from=httpx-build /out/ /tmp/httpx-build/
COPY --from=subfinder-build /out/ /tmp/subfinder-build/
COPY --from=ffuf-build /out/ /tmp/ffuf-build/
COPY --from=nuclei-build /out/ /tmp/nuclei-build/
COPY --from=gau-build /out/ /tmp/gau-build/
COPY container/go_tool_install.py /tmp/go_tool_install.py
RUN python -c 'from vardrrunner import toolchain; [toolchain.install(n) for n in toolchain.manageable_tools() if n not in ("katana", "dnsx", "naabu", "gau", "httpx", "subfinder", "ffuf", "nuclei")]' \
    && python /tmp/go_tool_install.py \
    && rm -rf /tmp/katana-build /tmp/dnsx-build /tmp/naabu-build /tmp/gau-build /tmp/httpx-build /tmp/subfinder-build /tmp/ffuf-build /tmp/nuclei-build /tmp/go_tool_install.py \
    && chmod -R a+rX /opt/vardrtools \
    && rm -rf /home/runner/.config /home/runner/.cache /home/runner/.pdcp \
    && ln -s /home/runner/.vardrmap /home/runner/.config
# Some tools ignore XDG_CONFIG_HOME; both config paths must reach the state volume.
ENV XDG_CONFIG_HOME=/home/runner/.vardrmap \
    XDG_CACHE_HOME=/home/runner/.vardrmap/tool-cache
COPY --from=gate-build /out/vardrgate /usr/local/bin/vardrgate
USER 10001:10001

FROM base AS core
