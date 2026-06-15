FROM rust:1-bookworm AS api-build
WORKDIR /app
RUN apt-get update \
  && apt-get install -y --no-install-recommends cmake nasm pkg-config libssl-dev \
  && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY apps ./apps
COPY crates ./crates
COPY infra ./infra
RUN cargo build --locked --release -p cairn-api

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
  && apt-get install -y --no-install-recommends ca-certificates libssl3 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=api-build /app/target/release/cairn-api /usr/local/bin/cairn-api
ENV CAIRN_API_BIND=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["/usr/local/bin/cairn-api", "healthcheck"]
CMD ["/usr/local/bin/cairn-api"]
