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
RUN cargo build --release
RUN rm src/main.rs

# Copy the actual code files and build the application
COPY src ./src/
# Update the file date
RUN touch src/main.rs
RUN cargo build --release


FROM ghcr.io/unb-libraries/base:3.x

RUN apk add --no-cache libgcc
ENV APP_STARTUP_CMD="/app/gateway start-server"
COPY --from=builder /app/target/release/aigateway_lib_unb_ca /app/gateway

LABEL ca.unb.lib.generator="gateway" \
  com.microscaling.docker.dockerfile="/Dockerfile" \
  com.microscaling.license="MIT" \
  org.label-schema.build-date=$BUILD_DATE \
  org.label-schema.description="aigateway.lib.unb.ca routes application inference requests to the appropriate endpoints within our infrastructures." \
  org.label-schema.name="aigateway.lib.unb.ca" \
  org.label-schema.schema-version="1.0" \
  org.label-schema.vcs-ref=$VCS_REF \
  org.label-schema.vcs-url="https://github.com/unb-libraries/aigateway.lib.unb.ca" \
  org.label-schema.vendor="University of New Brunswick Libraries" \
  org.label-schema.version=$VERSION \
  org.opencontainers.image.authors="libsupport@unb.ca" \
  org.opencontainers.image.source="https://github.com/unb-libraries/aigateway.lib.unb.ca"
