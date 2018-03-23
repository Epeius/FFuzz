# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

set (TCG_SOURCES)
list (APPEND TCG_SOURCES tcg.c optimize.c)

if (WITH_SYMBEX)
    list(APPEND TCG_SOURCES tcg-llvm.cpp)
endif (WITH_SYMBEX)

add_library(tcg ${TCG_SOURCES})

target_include_directories (tcg PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include ${GLIB_PKG_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -fPIC -Werror -Wno-zero-length-array")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fPIC -Wno-mismatched-tags -Werror -Wno-zero-length-array")

if (WITH_SYMBEX)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCONFIG_SYMBEX -DTCG_ENABLE_MEM_TRACING ${LLVM_CXXFLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DCONFIG_SYMBEX -DTCG_ENABLE_MEM_TRACING")
endif (WITH_SYMBEX)

MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} )
MESSAGE( STATUS "WITH_SYMBEX: " ${WITH_SYMBEX} )
