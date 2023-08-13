FROM rust:1.72.0 as build-env
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml /app
COPY Cargo.lock /app
RUN mkdir -p /app/trippy/src
RUN mkdir -p /app/trippy-core/src
COPY trippy/Cargo.toml /app/trippy/Cargo.toml
COPY trippy-core/Cargo.toml /app/trippy-core/Cargo.toml
RUN echo "fn main() {}" > /app/trippy/src/main.rs
RUN touch /app/trippy-core/src/lib.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl
COPY trippy/src /app/trippy/src
COPY trippy-core/src /app/trippy-core/src
COPY README.md /app
COPY LICENSE /app
RUN cargo build --release --target=x86_64-unknown-linux-musl

FROM alpine
RUN apk update && apk add ncurses
COPY --from=build-env /app/target/x86_64-unknown-linux-musl/release/trip /
ENTRYPOINT [ "./trip" ]