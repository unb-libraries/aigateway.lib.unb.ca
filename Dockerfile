FROM clux/muslrust:stable AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app


FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl --bin aigateway_lib_unb_ca


FROM ghcr.io/unb-libraries/base:3.x

ENV APP_STARTUP_CMD="/app/gateway start-server"
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/aigateway_lib_unb_ca /app/gateway

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
