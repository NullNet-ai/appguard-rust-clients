# Build stage
FROM rust:1.86-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*

# Copy the full workspace (needed for path dependencies)
COPY . .

# Build the actix sample in release mode
RUN cargo build --release -p actix_sample

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/actix_sample /usr/local/bin/actix_sample

# EXPOSE 3001

CMD ["actix_sample"]