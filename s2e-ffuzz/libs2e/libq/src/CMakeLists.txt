# Copyright 2016 - Cyberhaven
# This work is licensed under the terms of the GNU LGPL, version 2.1 or later.

add_library (q qbool.c qdict.c qfloat.c qint.c qjson.c  qlist.c qstring.c json-lexer.c json-parser.c json-streamer.c)

target_include_directories (q PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/../include ${GLIB_PKG_INCLUDE_DIRS})

set(CMAKE_C_FLAGS "-Wall -Wno-initializer-overrides -fPIC")
