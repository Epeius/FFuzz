#!/bin/sh

#CentOS/RHEL 6.4 don't seem to have an existing libdwarf package.
#This script builds it.

git clone git://libdwarf.git.sourceforge.net/gitroot/libdwarf/libdwarf libdwarf
mkdir -p libdwarf/dist
rpmbuild --buildroot $(pwd)/libdwarf/dist -bb  libdwarf.spec

#The package will be in whatever the ~/.rpmmacros specifies
