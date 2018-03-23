# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library(coroutine coroutine.c coroutine-ucontext.c)

target_include_directories (coroutine PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include ${GLIB_PKG_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "-Wall -fPIC")
