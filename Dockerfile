# The keyway backend.
#
# Queries are checked against the committed .sqlx cache, so the build needs no
# database — see SQLX_OFFLINE below.

FROM rust:1-slim AS build
WORKDIR /src

RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config libssl-dev \
 && rm -rf /var/lib/apt/lists/*

# Dependencies first, so editing source does not re-download the world.
COPY Cargo.toml Cargo.lock ./
COPY keyway/Cargo.toml keyway/
COPY keyway-cli/Cargo.toml keyway-cli/
RUN mkdir -p keyway/src keyway-cli/src \
 && echo 'fn main() {}' > keyway/src/main.rs \
 && echo '' > keyway/src/lib.rs \
 && echo 'fn main() {}' > keyway-cli/src/main.rs \
 && cargo build --release --bin keyway-server \
 && rm -rf keyway/src keyway-cli/src

COPY .sqlx .sqlx
COPY keyway keyway
COPY keyway-cli keyway-cli
ENV SQLX_OFFLINE=true
RUN touch keyway/src/main.rs && cargo build --release --bin keyway-server

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 keyway

COPY --from=build /src/target/release/keyway-server /usr/local/bin/keyway-server

# Nothing here needs root, and a secrets console is the last place to keep it.
USER 10001
EXPOSE 8080 9090
ENTRYPOINT ["keyway-server"]
CMD ["serve"]
