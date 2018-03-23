add_library(binaryreaders STATIC BFDInterface.cpp
                                 Binary.cpp
                                 ExecutableFile.cpp
                                 Library.cpp
                                 Macho.cpp
                                 Pe.cpp
                                 TextModule.cpp)
target_link_libraries(binaryreaders ${LLVM_LIBS} bfd)
