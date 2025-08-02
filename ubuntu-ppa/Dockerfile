FROM ubuntu:noble

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gpg debmake debhelper devscripts equivs \
    distro-info-data distro-info software-properties-common cargo cargo-1.82 wget

COPY release.sh release.sh

WORKDIR /data

CMD ["./ubuntu-ppa/release.sh"]
