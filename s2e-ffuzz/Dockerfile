#
# Copyright (C) 2015-2016, Cyberhaven, Inc
# All rights reserved. Proprietary and confidential.
#
# Distributed under the terms of S2E-LICENSE
#

# Installs S2E and its associated libraries and tools to /opt/s2e

FROM ubuntu:16.04

# Install LLVM dependencies
RUN apt-get update &&                                                       \
    apt-get -y install build-essential cmake wget texinfo flex bison        \
    python-dev

# Build LLVM (to avoid rebuilding it every change)
RUN mkdir s2e
COPY Makefile s2e/Makefile
RUN mkdir s2e-build &&                                                      \
    cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/llvm-native-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/llvm-release-make

# Install S2E git
RUN apt-get -y install git

# Build S2E dependencies
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/soci-make

RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/z3-make

# Install S2E dependencies
RUN apt-get -y install libdwarf-dev libelf-dev libiberty-dev binutils-dev   \
    libreadline-dev libboost-dev zlib1g-dev libjemalloc-dev nasm pkg-config \
    libmemcached-dev libvdeplug-dev libpq-dev libc6-dev-i386 libprocps4-dev \
    libboost-system-dev libboost-serialization-dev libboost-regex-dev       \
    libprotobuf-dev protobuf-compiler libbsd-dev libsigc++-2.0-dev          \
    libsdl-dev libglib2.0-dev
RUN apt-get -y build-dep qemu

# Make the S2E codebase available in the container
COPY . s2e/

# Build libvmi
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e stamps/libvmi-release-make

# Build and install everything else
RUN cd s2e-build &&                                                         \
    make -f ../s2e/Makefile S2EPREFIX=/opt/s2e install

# Cleanup
RUN apt-get -y purge cmake wget texinfo flex bison git pkg-config           \
    libprotobuf-dev protobuf-compiler
RUN apt-get -y autoclean
RUN rm -rf build-s2e
RUN rm -rf s2e

# Create an unprivileged user to run S2E
RUN adduser --disabled-password -gecos "" s2e
RUN chown -R s2e:s2e /opt/s2e
USER s2e
ENV PATH /opt/s2e/bin:$PATH
