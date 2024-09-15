# Debian Release

## Prerequisites

The script will download the src tar ball from the github release page. Ensure the version number is updated in the
`release.sh` script.

## Build and release the debian package

Copy the pgp key to the repo _root_ directory:

```bash
cp /path/to/pgp.key .
```

Build the debian ppa builder Docker image from the `debian` directory:

```bash
docker build . -t fujiapple/trippy-ppa-build:latest
```

Run the debian Docker image (from the _repo_ root directory):

```bash
docker run -it -v (pwd):/data fujiapple/trippy-ppa-build
```

Note that the upload is simulated, remove the `-ss` flag from dput to upload the package to the PPA.