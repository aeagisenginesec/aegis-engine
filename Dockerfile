# Aegis container image — the same build the release workflow stamps into
# the platform binaries, packaged for CI use:
#
#   docker run --rm -v "$PWD:/src" ghcr.io/aeagisenginesec/aegis-engine:v2.1.1 scan /src
#
# Multi-stage: full Go toolchain only in the build stage; the runtime
# image is Alpine with just the static binary + CA certificates.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG BUILD_DATE=unknown
ARG COMMIT=unknown
# Version comes from the version const in the source tree (the release
# workflow guarantees it matches the tag); only the var stamps are set here.
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X aegis/internal/version.BuildDate=${BUILD_DATE} -X aegis/internal/version.Commit=${COMMIT}" \
      -o /out/aegis ./cmd/aegis

FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
 && addgroup -S aegis && adduser -S aegis -G aegis
COPY --from=build /out/aegis /usr/local/bin/aegis
USER aegis
ENTRYPOINT ["aegis"]
CMD ["--help"]
