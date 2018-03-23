#!/bin/bash

#Needed to build S2E on redhat:
#yum install make gcc gcc-c++ wget patch svn unzip rpm-build
#yum install glibc-devel.i686 libgcc.i686 gettext-devel zlib-devel bison flex binutils-devel elfutils-devel glib2-devel nasm SDL-devel boost boost-serialization boost-devel readline-devel libmemcached libmemcached-devel libpng-devel procps-devel 

./checkout.sh
rm -rf "$DIR_BUILD"
./compile.sh nofakeroot
./build-redhat.sh
mv ~/rpmbuild/RPMS/x86_64/*.rpm .
