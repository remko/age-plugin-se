#!/bin/sh -x 

set -e

NAME=age-plugin-se
BIN_NAME=$NAME

if [ -z "$PREFIX"]; then
  PREFIX=/usr/local
fi
if [ -z "$DESTDIR"]; then
  DESTDIR=build
fi

CHROOT_DIR=/mnt/$NAME-build-chroot
SWIFT_PACKAGE_URL=https://download.swift.org/swift-5.10-release/ubuntu2204-aarch64/swift-5.10-RELEASE/swift-5.10-RELEASE-ubuntu22.04-aarch64.tar.gz
SWIFT_DIR=/usr/local/swift-5.10-RELEASE-ubuntu22.04-aarch64
SWIFT=$SWIFT_DIR/usr/bin/swift
CHROOT_BUILD_DIR=/opt/build
LINKER=ld-linux-aarch64.so.1
SOURCES="Sources Tests Package.swift"

################################################################################
# Create Debian chroot
################################################################################

if [ ! -d "$CHROOT_DIR" ]; then
  mkdir -p $CHROOT_DIR
  /usr/sbin/debootstrap --variant=minbase testing $CHROOT_DIR https://deb.debian.org/debian/
fi


################################################################################
# Install swift (+dependencies)
################################################################################

if [ ! -d "$CHROOT_DIR$SWIFT_DIR" ]; then
  curl -L -s $SWIFT_PACKAGE_URL | tar -C $CHROOT_DIR/usr/local -x -v -z 
fi
echo -e "$SWIFT_DIR/usr/lib/swift/linux\\n$SWIFT_DIR/usr/lib/swift/host" > $CHROOT_DIR/etc/ld.so.conf.d/swift.conf
/usr/sbin/chroot $CHROOT_DIR sh -c 'apt-get update && apt-get -y install sqlite3 libncurses6 libcurl4 libxml2 binutils libc6-dev libgcc-13-dev git libstdc++-13-dev'


################################################################################
# Add sources
################################################################################

mkdir -p $CHROOT_DIR$CHROOT_BUILD_DIR
rsync --delete -a $SOURCES $CHROOT_DIR$CHROOT_BUILD_DIR


################################################################################
# Build
################################################################################

/usr/sbin/chroot $CHROOT_DIR sh -c "mount -t proc /proc proc/"

set +e
/usr/sbin/chroot $CHROOT_DIR sh -c "set -e; cd $CHROOT_BUILD_DIR && $SWIFT build -c release --static-swift-stdlib -Xlinker '--dynamic-linker=$PREFIX/lib/$NAME/$LINKER' && cp \$($SWIFT build -c release --show-bin-path)/$BIN_NAME ."
set -e

/usr/sbin/chroot $CHROOT_DIR sh -c "umount /proc"


################################################################################
# Install
################################################################################

mkdir -p $DESTDIR$PREFIX/bin $DESTDIR$PREFIX/lib/$NAME
cp $CHROOT_DIR$CHROOT_BUILD_DIR/$BIN_NAME $DESTDIR$PREFIX/bin
cp $CHROOT_DIR/lib/$LINKER $DESTDIR$PREFIX/lib/$NAME
