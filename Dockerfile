FROM rust:alpine AS builder

ENV RUSTFLAGS="-C target-feature=-crt-static"

# Install build dependencies
RUN apk add --no-cache build-base musl-dev openssl-dev openssl

# Create a new empty shell project
WORKDIR /app

# Copy over the Cargo.toml files to the shell project
COPY Cargo.toml Cargo.lock ./

# Build and cache the dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo fetch
RUN cargo build --release --bin aigateway_lib_unb_ca
RUN rm src/main.rs

# Copy the actual code files and build the application
COPY src ./src/
# Update the file date
RUN touch src/main.rs
RUN cargo build --release --bin aigateway_lib_unb_ca


FROM ghcr.io/unb-libraries/base:3.x

RUN apk add --no-cache libgcc
ENV APP_STARTUP_CMD="/app/gateway start-server"
COPY --from=builder /app/target/release/aigateway_lib_unb_ca /app/gateway

LABEL ca.unb.lib.generator="gateway" \
  org.opencontainers.image.title="aigateway.lib.unb.ca" \
  org.opencontainers.image.description="aigateway.lib.unb.ca routes application inference requests to the appropriate endpoints within our infrastructures." \
  org.opencontainers.image.vendor="University of New Brunswick Libraries" \
  org.opencontainers.image.authors="libsupport@unb.ca" \
  org.opencontainers.image.source="https://github.com/unb-libraries/aigateway.lib.unb.ca" \
  org.opencontainers.image.version="$VERSION" \
  org.opencontainers.image.revision="$VCS_REF" \
  org.opencontainers.image.created="$BUILD_DATE"
