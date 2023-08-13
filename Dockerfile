FROM rust:1.72.0 as build-env
RUN rustup target add x86_64-unknown-linux-musl
WORKDIR /app
COPY Cargo.toml /app
COPY Cargo.lock /app
RUN mkdir /app/src
RUN echo "fn main() {}" > /app/src/main.rs
RUN cargo build --release --target=x86_64-unknown-linux-musl
COPY src /app/src
COPY README.md /app
COPY LICENSE /app
RUN cargo build --release --target=x86_64-unknown-linux-musl

FROM alpine
RUN apk update && apk add ncurses
COPY --from=build-env /app/target/x86_64-unknown-linux-musl/release/trip /
ENTRYPOINT [ "./trip" ]