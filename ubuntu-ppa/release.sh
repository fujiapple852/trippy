#!/bin/bash

set -o errexit -o pipefail -o nounset

# The Trippy version to release
VERSION="0.14.0-dev"

# The upstream version to use in the PPA
#
# This should usually be the same as the VERSION, but if the upstream tarball has been repacked
# (e.g. to remove unnecessary files or to fix the tarball) then this should be set to the upstream version
# with a `+repack{N}` suffix, where `{N}` is the number of times the tarball has been repacked. i.e. `0.1.0+repack1`.
UPSTREAM="0.14.0-dev"

# The revision number for the PPA
#
# This is incremented each time a new upload is made to the PPA so will always be one greater than repack number.
REVISION=1

# The Ubuntu series to build for
SERIES=("noble" "jammy")

TARBALL="trippy_${UPSTREAM}.orig.tar.gz"
PACKAGE="trippy"
CHANGES="New upstream release"
export DEBEMAIL="fujiapple852@gmail.com"
export DEBFULLNAME="Fuji Apple"

# Import GPG key securely
if [[ ! -f launchpad_secret_key.pgp ]]; then
    echo "Error: GPG key file 'launchpad_secret_key.pgp' not found." >&2
    exit 1
fi
gpg --batch --import launchpad_secret_key.pgp

# Extract GPG key ID
GPG_KEY_ID=$(gpg --with-colons --import-options show-only --import launchpad_secret_key.pgp | awk -F: '/^sec/ {print $5}')

# Check GPG key expiration
if gpg --list-keys --with-colons "${GPG_KEY_ID}" | grep '^pub' | grep '[e]'; then
    echo "GPG key has expired. Please update your GPG key." >&2
    exit 1
fi

# Download TARBALL
wget -O "${TARBALL}" "https://github.com/fujiapple852/trippy/archive/refs/tags/${VERSION}.tar.gz"
if [[ ! -f "${TARBALL}" ]]; then
    echo "Error: Failed to download TARBALL." >&2
    exit 1
fi

# Vendor the cargo dependencies
# We have to ensure we run cargo `vendor --locked` against the src in the tarball, not the src in the current directory.
tar -xf "${TARBALL}"
pushd "trippy-${VERSION}"
rm -f ../ubuntu-ppa/vendor.tar.xz
rm -rf vendor
cargo-1.82 vendor --locked
tar -cJf ../ubuntu-ppa/vendor.tar.xz vendor
popd
rm -rf "trippy-${VERSION}"

for series in "${SERIES[@]}"; do
    UBUNTU_VERSION=$(distro-info --series "${series}" -r | cut -d' ' -f1)
    BUILD_DIR="build-${series}"
    mkdir -p "${BUILD_DIR}"
    cp -r ubuntu-ppa "${BUILD_DIR}/debian"
    cd "${BUILD_DIR}"

    # Update changelog for the specific series
    rm -f debian/changelog
    dch --create --distribution "${series}" --PACKAGE "${PACKAGE}" \
        --newversion "${UPSTREAM}-ppa${REVISION}~ubuntu${UBUNTU_VERSION}" "$CHANGES"

    # Build the source PACKAGE
    debuild --prepend-path ~/.cargo/bin -S -sa

    cd ..
done

# The -ss flag can be added to simulate the upload
for changes_file in ./*.changes; do
    dput ppa:fujiapple/trippy "${changes_file}"
done
