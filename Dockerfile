FROM rust:alpine AS builder

ARG BUILD_DIR=/tmp

RUN set -x && \
  apk add --no-cache musl-dev openssl-dev

ENV RUSTFLAGS="-C target-feature=-crt-static"
COPY ./ ${BUILD_DIR}

RUN set -x && \
  cd ${BUILD_DIR} && \
  cargo build --release && \
  find ${BUILD_DIR}/target


FROM ghcr.io/unb-libraries/base:3.x

RUN apk add --no-cache libgcc
ENV APP_STARTUP_CMD="/app/gateway start-server"
COPY --from=builder /tmp/target/release/aigateway_lib_unb_ca /app/gateway

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
