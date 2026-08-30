# The keyway backend.
#
# The migrations are embedded (embed.go), so the binary is the whole
# deployment artefact — no schema files to COPY alongside it and get wrong.

FROM golang:1.26 AS build
WORKDIR /src

# Dependencies first, so editing source does not re-download the world.
COPY go.mod go.sum ./
RUN go mod download

COPY embed.go ./
COPY migrations ./migrations
COPY cmd ./cmd
COPY config ./config
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -o /out/keywayd ./cmd/api

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 keyway

COPY --from=build /out/keywayd /usr/local/bin/keywayd

# Nothing here needs root, and a secrets console is the last place to keep it.
USER 10001
EXPOSE 8080 9090
ENTRYPOINT ["keywayd"]
CMD ["serve"]
