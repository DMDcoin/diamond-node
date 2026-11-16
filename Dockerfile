ARG RUST_VERSION=1.85.1
FROM rust:${RUST_VERSION}-slim-bookworm AS builder

RUN apt-get update && \
    apt-get install --no-install-recommends -y build-essential cmake && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY . ./

ARG FEATURES=diamond-node/final
RUN cargo build --locked --release --features "$FEATURES" \
    -p diamond-node -p dmd -p hbbft_config_generator

FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install --no-install-recommends -y ca-certificates curl libstdc++6 libgcc-s1 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/diamond-node /app/diamond-node
COPY --from=builder /app/target/release/dmd /app/dmd
COPY --from=builder /app/target/release/hbbft_config_generator /app/hbbft_config_generator
COPY LICENSE /app/LICENSE

RUN /app/diamond-node --version

WORKDIR /dmd

ENTRYPOINT ["/app/diamond-node"]
CMD ["--config", "/dmd/validator.toml", "--no-persistent-txqueue"]
