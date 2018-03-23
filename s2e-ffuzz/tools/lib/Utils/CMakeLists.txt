find_package(Protobuf REQUIRED)
protobuf_generate_cpp(CFG_PROTO_SRCS CFG_PROTO_HDRS cfg.proto)

add_library(utils STATIC BasicBlockListParser.cpp
                         BinaryCFGReader.cpp
                         Log.cpp
                         signals.cpp
                         ${CFG_PROTO_SRCS})
target_include_directories(utils PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(utils ${PROTOBUF_LIBRARIES})
