FROM alpine:3.19.0 as build-env

RUN apk add --no-cache \
    curl=8.5.0-r0 \
    build-base=0.5-r3 \
    --repository=https://dl-cdn.alpinelinux.org/alpine/v3.19/main

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain=1.70.0

COPY Cargo* /home

RUN mkdir /home/src && echo "fn main() {}" > /home/src/main.rs

RUN source "$HOME/.cargo/env" && cd /home && cargo +1.70.0 build --release

ADD ./ /home

RUN source "$HOME/.cargo/env" && cd /home && cargo +1.70.0 build --release

FROM scratch

COPY --from=build-env /home/target/release/trip /

COPY LICENSE /

ENTRYPOINT ["./trip"]
