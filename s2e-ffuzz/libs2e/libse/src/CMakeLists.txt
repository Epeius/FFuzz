# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library (se x64.asm)

target_include_directories (se PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include)

set(CMAKE_C_FLAGS "-Wall -fPIC -Werror -Wno-zero-length-array")
set(CMAKE_CXX_FLAGS "-Wall -fPIC -Werror -Wno-zero-length-array")
