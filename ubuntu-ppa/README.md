# Debian Release

## Prerequisites

- update the `cargo-1.xx` version in `ubuntu-ppa/Dockerfile` (note: both `cargo` and `cargo-1.xx` are needed)
- update the `cargo-1.xx` and `rust-1.xx` versions in `control`
- update the `cargo-1.xx` versions in `rules`
- update the `cargo-1.xx` versions in `release.sh`
- update the trippy `VERSION` in the `release.sh` script
- update the `UPSTREAM` in the `release.sh` script (removing any `+repack{N}` suffix)
- reset the `REVISION` to `1` in the `release.sh` script

## Build and release the debian package

Copy the pgp key to the repo _root_ directory:

```bash
cp /path/to/pgp.key .
```

Build the debian ppa builder Docker image from the `ubuntu-ppa` directory:

```bash
docker build . -t fujiapple/trippy-ppa-build:latest
```

Run the debian Docker image (from the _repo_ root directory):

```bash
docker run -it -v (pwd):/data fujiapple/trippy-ppa-build
```

Note that the upload is simulated, remove the `-ss` flag from dput to upload the package to the PPA.
