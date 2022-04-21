FROM rust:1.60.0 as build-env
WORKDIR /app
COPY Cargo.toml /app
COPY Cargo.lock /app
COPY src /app/src
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=build-env /app/target/release/trippy /
ENTRYPOINT [ "./trippy" ]