FROM alpine@sha256:13b7e62e8df80264dbb747995705a986aa530415763a6c58f84a3ca8af9a5bcd as build-env

RUN apk add --no-cache \
    curl=8.5.0-r0 \
    build-base=0.5-r3 \
    --repository=https://dl-cdn.alpinelinux.org/alpine/v3.19/main

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

ADD ./ /app

RUN source "$HOME/.cargo/env" && cd /app && cargo build --release

FROM alpine@sha256:13b7e62e8df80264dbb747995705a986aa530415763a6c58f84a3ca8af9a5bcd

RUN apk add --no-cache ncurses=6.4_p20231125-r0 --repository=https://dl-cdn.alpinelinux.org/alpine/v3.19/main

COPY --from=build-env /app/target/release/trip /

ENTRYPOINT ["./trip"]
