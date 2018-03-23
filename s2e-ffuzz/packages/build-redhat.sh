#!/bin/sh

. ./config.sh

#Copy tools to s2e bin folder
cp "$DIR_BUILD"/tools-release/Release+Asserts/bin/* "$DIR_PACKAGE/$PREFIX/bin"

#Add KeyValueStore.py
cp "$DIR_S2E_SRC/qemu/s2e/Plugins/KeyValueStore.py" "$DIR_PACKAGE/$PREFIX/bin"

rpmbuild --buildroot "$DIR_PACKAGE" -bb  s2e.spec
