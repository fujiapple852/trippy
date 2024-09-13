FROM ubuntu:noble

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update && apt-get install -y \
    gpg debmake debhelper devscripts equivs \
    distro-info-data distro-info software-properties-common cargo wget

COPY release.sh release.sh

WORKDIR /data

CMD ["./debian/release.sh"]