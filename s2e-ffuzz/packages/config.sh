#!/bin/bash
CUR_PATH=$(dirname $(readlink -f $0))
S2E_ROOT="$CUR_PATH/build/s2e-src-snapshot"

#GIT_S2E=https://${GITUSER}@github.com/codetickler/s2e-codetickler.git
GIT_S2E="$(pwd)/../"
GIT_S2E_BRANCH=origin/codetickler

#These are the git folders. It is very important that they do not end by a /, because .version is appended to create the version file.
DIR_S2E_SRC="$S2E_ROOT/s2e"

DIR_BUILD="$CUR_PATH/build/s2e-build"

PREFIX=/home/ctci/s2e

DIR_PACKAGE="$CUR_PATH/build/debian"

#export BUILD_ARCH=corei7
