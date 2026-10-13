FROM golang:1.22.5-bookworm AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /bin/svc ./cmd/svc

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /bin/svc /svc

EXPOSE 8080

USER nonroot:nonroot

ENTRYPOINT ["/svc"]
