#!/bin/sh
# This downloads all dependencies and builds them if needed

set -e

mkdir -p build
cd build/

if ! sha256sum -c ../checksums >/dev/null 2>&1; then
    wget https://busybox.net/downloads/busybox-1.36.1.tar.bz2
    wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.1/pspy64
    wget https://github.com/inotify-tools/inotify-tools/archive/refs/tags/4.23.9.0.tar.gz
    mv 4.23.9.0.tar.gz inotify-tools-4.23.9.0.tar.gz
    wget https://github.com/tstack/lnav/releases/download/v0.12.0/lnav-0.12.0-linux-musl-x86_64.zip
    wget https://github.com/G4Vi/Perl-Dist-APPerl/releases/download/v0.3.0/perl.com
fi

sha256sum -c ../checksums

# Compile busybox
# Config file for busybox uses default settings except:
#  - statically compiled
#  - sh standalone
#  - prefer applets
#  - enable inotifyd
tar -xf busybox-1.36.1.tar.bz2
cp ../busybox.config busybox-1.36.1/.config
cd busybox-1.36.1/
make
cd ..


# Statically compile inotifywait
tar -xf inotify-tools-4.23.9.0.tar.gz
cd inotify-tools-4.23.9.0
export CC=gcc
export CXX=g++
./autogen.sh
./configure --prefix=/usr --enable-static --disable-shared
make
unset CFLAGS
unset CXXFLAGS
unset LDFLAGS
cd ..

unzip lnav-0.12.0-linux-musl-x86_64.zip

cp busybox-1.36.1/busybox ../server/
cp busybox-1.36.1/busybox ../client/
cp inotify-tools-4.23.9.0/src/inotifywait ../client/
cp pspy64 ../client/
cp perl.com ../client/
cp lnav-0.12.0/lnav ../server/
chmod u+x ../server/*
chmod u+x ../client/*

cp ../src/*server* ../server/
cp ../src/*client* ../client/
