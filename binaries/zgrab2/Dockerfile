# syntax=docker/dockerfile:1
# Build one third-party binary from pinned source, then ship ONLY the static
# binary in a scratch image. Consumers COPY --from this versioned image, e.g.:
#   FROM ghcr.io/seriesoftubez/zgrab2:v1.0.0@sha256:... AS zgrab2-bin
#   COPY --from=zgrab2-bin /zgrab2 /usr/local/bin/zgrab2
ARG GO_VERSION=1.25
FROM golang:${GO_VERSION}-bookworm AS build
ARG REPO
ARG VERSION
ARG PKG
ARG BIN
# Static build so the binary runs on a minimal base and ships in scratch.
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
WORKDIR /src
# Pinned-tag clone; module downloads are verified against the Go checksum DB.
RUN git clone --depth 1 --branch "${VERSION}" "${REPO}" . \
    && go build -ldflags='-s -w' -o "/out/${BIN}" "${PKG}"

FROM scratch AS final
ARG BIN
COPY --from=build /out/${BIN} /${BIN}
