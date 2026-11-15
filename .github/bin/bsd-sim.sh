#!/bin/sh
set -eu

case $(uname -s) in
    FreeBSD|NetBSD)
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
        export PATH="$HOME/.cargo/bin:$PATH"
        ;;
    OpenBSD)
        sudo -n pkg_add rust
        ;;
esac

cargo build --locked -p trippy-core --features sim-tests --test sim
sudo -n -E env "PATH=$PATH" cargo test --locked -p trippy-core --features sim-tests --test sim -- --nocapture
