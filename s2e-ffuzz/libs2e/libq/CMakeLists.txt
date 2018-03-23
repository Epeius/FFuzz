# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

cmake_minimum_required(VERSION 3.4.3)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)

include_directories(${GLIB_PKG_INCLUDE_DIRS})

add_subdirectory(src)
