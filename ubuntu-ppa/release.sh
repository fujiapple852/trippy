#!/bin/bash

set -o errexit -o pipefail -o nounset

# The Trippy version to release
VERSION="0.12.0"

# The revision number for the PPA
REVISION=2

# The Ubuntu series to build for
SERIES=("noble" "jammy")

TARBALL="trippy_${VERSION}.orig.tar.gz"
PACKAGE="trippy"
CHANGES="New upstream release"
export DEBEMAIL="fujiapple852@gmail.com"
export DEBFULLNAME="Fuji Apple"

# Download TARBALL
wget -O "${TARBALL}" "https://github.com/fujiapple852/trippy/archive/refs/tags/${VERSION}.tar.gz"
if [[ ! -f "${TARBALL}" ]]; then
    echo "Error: Failed to download TARBALL." >&2
    exit 1
fi

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

# Vendor the cargo dependencies
cargo-1.76 vendor
tar cJf ubuntu-ppa/vendor.tar.xz vendor

for series in "${SERIES[@]}"; do
    UBUNTU_VERSION=$(distro-info --series "${series}" -r | cut -d' ' -f1)
    BUILD_DIR="build-${series}"
    mkdir -p "${BUILD_DIR}"
    cp -r ubuntu-ppa "${BUILD_DIR}/debian"
    cd "${BUILD_DIR}"

    # Update changelog for the specific series
    rm -f debian/changelog
    dch --create --distribution "${series}" --PACKAGE "${PACKAGE}" \
        --newversion "${VERSION}-ppa${REVISION}~ubuntu${UBUNTU_VERSION}" "$CHANGES"

    # Build the source PACKAGE
    debuild --prepend-path ~/.cargo/bin -S -sa

    cd ..
done

# The -ss flag is used to simulate the upload, remove to actually upload
for changes_file in ./*.changes; do
    dput -ss ppa:fujiapple/trippy "${changes_file}"
done
