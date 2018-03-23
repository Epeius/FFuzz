#!/bin/bash

# You can use this script to compile S2E remotely from another machine (e.g., a Mac).
# For instance, you can edit your code in Qt Creator running on Mac OS X,
# press build (Cmd b) and it will build S2E on a Linux box of your choice.
#
# Tested with Mac OS X -> Linux. It should work for Linux -> Linux too.
#
# Customize the config script appropriately ...
#
# Example usage:
# ./make-remotely.sh -f ../s2e/Makefile all-release

. config-remote-make.sh

S2E_ROOT=$REMOTE_PATH

rsync -avz --delete --exclude=.git   $LOCAL_PATH/s2e $REMOTE_USER@$HOST:$REMOTE_PATH/

build_qt()
{
  MAKE_ARGS=$(echo $* | sed  "s:$LOCAL_PATH:$REMOTE_PATH:")
  echo $MAKE_ARGS
  echo "building at $REMOTE_USER@$HOST:$REMOTE_PATH"
  ssh $REMOTE_USER@$HOST "rm -rf $REMOTE_BUILD_PATH/stamps/qemu-release-make"
  ssh -l "$REMOTE_USER" $HOST "S2E_ROOT=$REMOTE_S2E_ROOT && mkdir -p $REMOTE_BUILD_PATH && cd $REMOTE_BUILD_PATH  && (((make $MAKE_ARGS | sed -u s:$REMOTE_PATH:$LOCAL_PATH:) 3>&1 1>&2 2>&3 | sed -u s:$REMOTE_PATH:$LOCAL_PATH:) 3>&1 1>&2 2>&3)"
}

build_libs2e()
{
  CPLUS_INCLUDE_PATH=/usr/include:/usr/include/x86_64-linux-gnu:/usr/include/x86_64-linux-gnu/c++/4.8
  ssh -l "$REMOTE_USER" $HOST "cd $REMOTE_BUILD_PATH/libs2e-release && export CPLUS_INCLUDE_PATH=$CPLUS_INCLUDE_PATH && make clean && make -j40"
}

#build_qt $*
#build_libs2e $*
