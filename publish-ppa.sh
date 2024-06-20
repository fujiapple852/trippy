#!/bin/bash

# This script automates the process of publishing a PPA for Trippy.

# Ensure the script exits on any error
set -e

# Define the supported Ubuntu versions
UBUNTU_VERSIONS=("jammy" "focal" "bionic")

# Define the PPA
PPA="ppa:fujiapple/trippy"

# Define the version of Trippy to publish
TRIPPY_VERSION="0.10.0"

# Loop through each Ubuntu version and publish the PPA
for VERSION in "${UBUNTU_VERSIONS[@]}"; do
    echo "Publishing for Ubuntu $VERSION"

    # Run the Docker container for the Ubuntu version
    docker run -it -v "$(pwd)":/data ubuntu:$VERSION bash -c "
        apt update && apt install -y build-essential devscripts debhelper cargo wget

        cd /data

        wget https://github.com/fujiapple852/trippy/archive/refs/tags/$TRIPPY_VERSION.tar.gz
        mv $TRIPPY_VERSION.tar.gz trippy_$TRIPPY_VERSION.orig.tar.gz

        mkdir build
        mv debian build
        cd build

        # Build vendored dependency crates
        ./debian/rules vendor

        # Setup gpg and import launchpad key pair
        # gpg --import ...

        # Build PPA source package
        debuild --prepend-path ~/.cargo/bin -S -sa

        # Publish to launchpad
        dput $PPA ../trippy_$TRIPPY_VERSION-1ubuntu0.1~${VERSION}1_source.changes
    "
done
