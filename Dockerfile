FROM rust:1.60.0 as build-env
WORKDIR /app
COPY Cargo.toml /app
COPY Cargo.lock /app
RUN mkdir /app/src
RUN echo "fn main() {}" > /app/src/main.rs
RUN cargo build --release

COPY src /app/src
COPY README.md /app
COPY LICENSE /app
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=build-env /app/target/release/trip /
ENTRYPOINT [ "./trip" ]