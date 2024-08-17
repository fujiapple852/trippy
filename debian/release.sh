#!/bin/bash

set -o errexit -o pipefail -o nounset

VERSION="0.11.0"
TARBALL="trippy_${VERSION}.orig.tar.gz"
export DEBEMAIL="fujiapple852@gmail.com"
export DEBFULLNAME="Fuji Apple"
SERIES="jammy"

wget "https://github.com/fujiapple852/trippy/archive/refs/tags/${VERSION}.tar.gz"
mv ${VERSION}.tar.gz $TARBALL

GPG_PRIVATE_KEY=$(cat launchpad_secret_key.pgp)
GPG_KEY_ID=$(echo "$GPG_PRIVATE_KEY" | gpg --import-options show-only --import | sed -n '2s/^\s*//p')
echo $GPG_KEY_ID
echo "$GPG_PRIVATE_KEY" | gpg --batch --import

echo "Checking GPG expirations..."
if [[ $(gpg --list-keys | grep expired) ]]; then
    echo "GPG key has expired. Please update your GPG key." >&2
    exit 1
fi

mkdir -p build
cp -r debian build/debian

ubuntu_version=$(distro-info --series ${SERIES} -r | cut -d' ' -f1)
package=$(dpkg-parsechangelog --show-field Source)
pkg_version=$(dpkg-parsechangelog --show-field Version | cut -d- -f1)
changes="New upstream release"
REVISION=1

cd build

rm -rf debian/changelog
dch --create --distribution ${SERIES} --package $package --newversion $pkg_version-ppa$REVISION~ubuntu$ubuntu_version "$changes"

./debian/rules vendor

debuild --prepend-path ~/.cargo/bin -S -sa

# The -ss flag is used to simulate the upload, remove to actually upload
dput -ss ppa:fujiapple/trippy ../*.changes