add_executable(revgen64 InstructionLabeling.cpp
                        MemoryWrapperElimination.cpp
                        RegisterPromotion.cpp
                        RevGen.cpp)
target_include_directories(revgen64 PRIVATE ${CMAKE_BINARY_DIR})

target_link_libraries(revgen64 X8664Translator
                               cfg
                               utils
                               vmi
                               bfd
                               ${LLVM_LIBS}
                               ${GLIB2_LIBRARIES})

install(TARGETS revgen64 RUNTIME DESTINATION bin)
