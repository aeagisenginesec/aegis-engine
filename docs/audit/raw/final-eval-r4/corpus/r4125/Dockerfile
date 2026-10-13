# R4 project r4125
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY . .
RUN CGO_ENABLED=0 go build -o /app/server .
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /app/server /app/server
USER nonroot
CMD ["/app/server"]
