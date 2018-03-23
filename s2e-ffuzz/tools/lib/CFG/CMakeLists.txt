add_library(cfg STATIC BinaryCFG.cpp)
target_link_libraries(cfg ${LLVM_LIBS})
