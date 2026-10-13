# The Personal Agent Naming registrar. Build from the registrar's own folder
# (Cargo.toml at the root of the build context), with SPEC-NAMING.md beside it:
#
#   docker build -f deploy/Dockerfile -t pan-registrar .
FROM rust:1-bookworm AS build
WORKDIR /w
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY migrations ./migrations
COPY web ./web
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 pan
COPY --from=build /w/target/release/pan-registrar /usr/local/bin/pan-registrar
# The spec is a document, not code: shipped beside the binary, read at runtime
# and served at /spec.
COPY SPEC-NAMING.md /srv/SPEC-NAMING.md
WORKDIR /srv
USER pan
ENV RUST_LOG=info PORT=8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pan-registrar"]
