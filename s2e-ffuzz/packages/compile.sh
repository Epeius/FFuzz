#!/bin/sh

. ./config.sh

if [ "x$1" != "xnofakeroot" ]; then
if [ `id -u` != 0 ]; then
    echo "Must be run with fakeroot"
    exit 1
fi
fi

cd "$S2E_ROOT"
mkdir -p "$DIR_BUILD"
cd "$DIR_BUILD"

rm -r "$DIR_PACKAGE"
mkdir -p "$DIR_PACKAGE/$PREFIX"

make -f "$DIR_S2E_SRC"/Makefile all-release S2ESRC="$DIR_S2E_SRC" S2EPREFIX="$PREFIX" DESTDIR="$DIR_PACKAGE" EXTRA_QEMU_FLAGS="--enable-boost"
