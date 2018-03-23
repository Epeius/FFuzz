# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

cmake_minimum_required(VERSION 3.4.3)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB_PKG glib-2.0)


option(WITH_SYMBEX "with(out) external symbolic execution engine support")
set(HOST_INCLUDE_DIR CACHE STRING "path to config-host directory")
set(TARGET_INCLUDE_DIR CACHE STRING "path to config-target directory")
set(SEUTILS_INCLUDE_DIR CACHE STRING "path to symbex utils include directory")
set(LIBQ_INCLUDE_DIR CACHE STRING "path to libq include directory")
set(LIBTCG_INCLUDE_DIR CACHE STRING "path to libtcg include directory")

# We want to keep NDEBUG in all builds
foreach (flags_var_to_scrub
    CMAKE_CXX_FLAGS_RELEASE
    CMAKE_CXX_FLAGS_RELWITHDEBINFO
    CMAKE_CXX_FLAGS_MINSIZEREL
    CMAKE_C_FLAGS_RELEASE
    CMAKE_C_FLAGS_RELWITHDEBINFO
    CMAKE_C_FLAGS_MINSIZEREL)
string (REGEX REPLACE "(^| )[/-]D *NDEBUG($| )" " "
    "${flags_var_to_scrub}" "${${flags_var_to_scrub}}")
endforeach()

include_directories(${GLIB_PKG_INCLUDE_DIRS} ${HOST_INCLUDE_DIR} ${TARGET_INCLUDE_DIR})
add_subdirectory(src)
