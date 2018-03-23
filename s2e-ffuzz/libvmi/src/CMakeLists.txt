add_library(vmi STATIC BFDFile.cpp
                       CGCFile.cpp
                       ElfDwarf.cpp
                       ExecutableFile.cpp
                       FileProvider.cpp
                       PEFile.cpp
                       Vmi.cpp
                       WindowsCrashDumpGenerator.cpp
                       WinKernDumpFile.cpp)
target_link_libraries(vmi bfd)
install(TARGETS vmi ARCHIVE DESTINATION lib)
