## Crates

The following is a list of the crates defined by Trippy and their purposes:

### `trippy`

A binary crate for the Trippy application and a library crate. This is the crate you would use if you wish to install
and run Trippy as a standalone tool.

```shell
cargo install --locked trippy
```

It can also be used as library for crates that wish to use the Trippy tracing functionality.

> [!NOTE]
> The `trippy` crate has `tui` as a default feature and so you should disable default features when using it as a
> library.

```shell
cargo add trippy --no-default-features --features core,dns
```

### `trippy-core`

A library crate providing the core Trippy tracing functionality. This crate is used by the Trippy application and is
the crate you would use if you wish to provide the Trippy tracing functionality in your own application.

```shell
cargo add trippy-core
```

### `trippy-packet`

A library crate which provides packet wire formats and packet parsing functionality. This crate is used by the Trippy
application and is the crate you would use if you wish to provide packet parsing functionality in your own application.

```shell
cargo add trippy-packet
```

### `trippy-dns`

A library crate for performing forward and reverse lazy DNS resolution. This crate is designed to be used by the Trippy
application but may also be useful for other applications that need to perform forward and reverse lazy DNS resolution.

```shell
cargo add trippy-dns
```

### `trippy-privilege`

A library crate for discovering platform privileges. This crate is designed to be used by the Trippy application but
may also be useful for other applications.

```shell
cargo add trippy-privilege
```

### `trippy-tui`

A library crate for the Trippy terminal user interface.

```shell
cargo add trippy-tui
```
