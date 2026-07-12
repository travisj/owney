# Build stage
FROM rust:latest as builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin mailserverd

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/mailserverd /usr/local/bin/

ENTRYPOINT ["mailserverd"]
