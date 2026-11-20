# netio.patchman sunucu imajı
# Derleme: docker build -t netio-patchman-server .
# Sürüm, depodaki VERSION dosyasından okunur; --build-arg VERSION=<sürüm> ile
# değiştirilebilir. İmaj, sunucunun yanında amd64 ve arm64 Linux ajan
# dosyalarını da içerir; ajanlar /downloads/agent/ adresinden indirilir.

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY VERSION ./
COPY cmd ./cmd
COPY internal ./internal
COPY deploy ./deploy
# Windows'ta klonlanan depolarda betikler CRLF satır sonuyla gelebilir; ajan
# kurulum betiği ve systemd birimi Linux'ta çalışacağı için LF'ye çevrilir.
RUN sed -i 's/\r$//' deploy/agent/*.sh deploy/agent/*.service
ARG VERSION=
ENV CGO_ENABLED=0
RUN VERSION="${VERSION:-$(tr -d ' \r\n' < VERSION)}" && \
    LDFLAGS="-s -w -X netio.patchman/internal/version.Version=${VERSION}" && \
    go build -trimpath -ldflags "$LDFLAGS" -o /out/netio-patchman-server ./cmd/netio-patchman-server && \
    mkdir -p /out/agent /out/data && \
    echo "${VERSION}" > /out/agent/version && \
    for arch in amd64 arm64; do \
      GOOS=linux GOARCH=$arch go build -trimpath -ldflags "$LDFLAGS" \
        -o /out/agent/netio-patchman-agent-linux-$arch ./cmd/netio-patchman-agent && \
      (cd /out/agent && sha256sum netio-patchman-agent-linux-$arch > netio-patchman-agent-linux-$arch.sha256); \
    done

FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="netio.patchman" \
      org.opencontainers.image.description="Merkezi Linux Güvenlik Açığı ve Güncelleme Yönetimi" \
      org.opencontainers.image.source="https://github.com/alptekinsunnetci/netio.patchman"
ENV TZ=Europe/Istanbul \
    LANG=C.UTF-8 \
    PATCHMAN_DATA_DIR=/data \
    PATCHMAN_AGENT_DIST_DIR=/usr/share/netio-patchman/agent
COPY --from=build /out/netio-patchman-server /usr/local/bin/netio-patchman-server
COPY --from=build /out/agent /usr/share/netio-patchman/agent
COPY --from=build --chown=65532:65532 /out/data /data
VOLUME ["/data"]
EXPOSE 8080
USER nonroot:nonroot
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/netio-patchman-server", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/netio-patchman-server"]
