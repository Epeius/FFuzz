set(REVGEN64_DIR ${CMAKE_SOURCE_DIR}/tools/revgen64)

add_executable(revgen32 ${REVGEN64_DIR}/RevGen.cpp
                        ${REVGEN64_DIR}/MemoryWrapperElimination.cpp
                        ${REVGEN64_DIR}/RegisterPromotion.cpp
                        ${REVGEN64_DIR}/InstructionLabeling.cpp)
target_include_directories(revgen32 PRIVATE ${CMAKE_BINARY_DIR})
target_link_libraries(revgen32 X86Translator
                               cfg
                               utils
                               vmi
                               bfd
                               ${LLVM_LIBS}
                               ${GLIB2_LIBRARIES})

install(TARGETS revgen32 RUNTIME DESTINATION bin)
