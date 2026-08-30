# The GO server image, for the parity gate (kotsmile/keyway#29).
#
# Deliberately not the root Dockerfile: that one builds the Rust server and is
# #30's to delete. Build context is the repo root (go.mod lives there).
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY embed.go ./
COPY migrations ./migrations
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/keywayd ./cmd/keywayd

FROM alpine:3.21
RUN adduser -D -u 10001 keyway
USER keyway
COPY --from=build /out/keywayd /usr/local/bin/keywayd
ENTRYPOINT ["keywayd"]
