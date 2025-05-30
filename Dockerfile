FROM rust:1.81 AS build-env
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml /app
COPY Cargo.lock /app
RUN mkdir -p /app/crates/trippy/src
RUN mkdir -p /app/crates/trippy-tui/src
RUN mkdir -p /app/crates/trippy-core/src
RUN mkdir -p /app/crates/trippy-dns/src
RUN mkdir -p /app/crates/trippy-packet/src
RUN mkdir -p /app/crates/trippy-privilege/src
RUN mkdir -p /app/crates/trippy-sim/src
COPY crates/trippy/Cargo.toml /app/crates/trippy/Cargo.toml
COPY crates/trippy-tui/Cargo.toml /app/crates/trippy-tui/Cargo.toml
COPY crates/trippy-core/Cargo.toml /app/crates/trippy-core/Cargo.toml
COPY crates/trippy-dns/Cargo.toml /app/crates/trippy-dns/Cargo.toml
COPY crates/trippy-packet/Cargo.toml /app/crates/trippy-packet/Cargo.toml
COPY crates/trippy-privilege/Cargo.toml /app/crates/trippy-privilege/Cargo.toml
COPY crates/trippy-sim/Cargo.toml /app/crates/trippy-sim/Cargo.toml
COPY examples/ /app/examples/

# dummy build to cache dependencies
RUN echo "fn main() {}" > /app/crates/trippy/src/main.rs
RUN touch /app/crates/trippy-tui/src/lib.rs
RUN touch /app/crates/trippy-core/src/lib.rs
RUN touch /app/crates/trippy-dns/src/lib.rs
RUN touch /app/crates/trippy-packet/src/lib.rs
RUN touch /app/crates/trippy-privilege/src/lib.rs
RUN touch /app/crates/trippy-sim/src/lib.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl --package trippy

# copy the actual application code and build
COPY crates/trippy/src /app/crates/trippy/src
COPY crates/trippy-tui/src /app/crates/trippy-tui/src
COPY crates/trippy-core/src /app/crates/trippy-core/src
COPY crates/trippy-dns/src /app/crates/trippy-dns/src
COPY crates/trippy-packet/src /app/crates/trippy-packet/src
COPY crates/trippy-privilege/src /app/crates/trippy-privilege/src
COPY crates/trippy-tui/build.rs /app/crates/trippy-tui
COPY crates/trippy-tui/locales.toml /app/crates/trippy-tui
COPY trippy-config-sample.toml /app
COPY trippy-config-sample.toml /app/crates/trippy-tui
COPY README.md /app
COPY README.md /app/crates/trippy
RUN cargo clean --release --target=x86_64-unknown-linux-musl -p trippy-tui -p trippy-core -p trippy-dns -p trippy-packet -p trippy-privilege
RUN cargo build --release --target=x86_64-unknown-linux-musl

FROM alpine
RUN apk update && apk add ncurses
COPY --from=build-env /app/target/x86_64-unknown-linux-musl/release/trip /
ENTRYPOINT ["./trip"]
