#!/bin/bash

./checkout.sh
rm -rf "$DIR_BUILD"
fakeroot ./compile.sh
fakeroot ./build.sh
