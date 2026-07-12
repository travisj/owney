# Build stage
FROM rust:latest as builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin owneyd

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/owneyd /usr/local/bin/

ENTRYPOINT ["owneyd"]
