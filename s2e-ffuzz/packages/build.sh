#!/bin/sh

. ./config.sh

if [ `id -u` != 0 ]; then
    echo "Must be run with fakeroot"
    exit 1
fi

#Copy tools to s2e bin folder
cp "$DIR_BUILD"/tools-release/Release+Asserts/bin/* "$DIR_PACKAGE/$PREFIX/bin"

#Add KeyValueStore.py
cp "$DIR_S2E_SRC/qemu/s2e/Plugins/KeyValueStore.py" "$DIR_PACKAGE/$PREFIX/bin"
chmod 0755 "$DIR_PACKAGE/$PREFIX/bin/KeyValueStore.py"
chown root:root "$DIR_PACKAGE/$PREFIX/bin/KeyValueStore.py"

cd "$S2E_ROOT"

cp -vR "$CUR_PATH/DEBIAN" "$DIR_PACKAGE"
chmod 0755 "$DIR_PACKAGE/DEBIAN"
sed "s/Version:.*/Version: $(head -n1 $DIR_S2E_SRC.version)/" "$CUR_PATH"/DEBIAN/control > "$DIR_PACKAGE"/DEBIAN/control

#dpkg-deb -b "$DIR_PACKAGE" "$CUR_PATH/mvp1-${GIT_S2E_BRANCH}_$(head -n1 $DIR_S2E_SRC.version)_amd64.deb"
dpkg-deb -b "$DIR_PACKAGE" "$CUR_PATH"
