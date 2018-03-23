include(LLVMBitcode)

set(FLAGS -D_GNU_SOURCE -DNEED_CPU_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
          -DCONFIG_SYMBEX -DS2E_LLVM_LIB -DSTATIC_TRANSLATOR -g -m32 -w -Wundef
          -Wredundant-decls -Wendif-labels -Wwrite-strings -fno-strict-aliasing
          -Wno-sign-compare -Wno-missing-field-initializers)
set(INC_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
             ${CMAKE_SOURCE_DIR}/include
             ${S2E_SRC_DIR}
             ${S2E_SRC_DIR}/target-${QEMU_TARGET}
             ${S2E_SRC_DIR}/fpu
             ${S2E_SRC_DIR}/tcg
             ${S2E_SRC_DIR}/tcg/${QEMU_TARGET})

link_llvm_bitcode(X86RuntimeLibrary.bc "${FLAGS}" "${INC_DIRS}"
                                       ${CMAKE_CURRENT_SOURCE_DIR}/Runtime.cpp
                                       ${CMAKE_CURRENT_SOURCE_DIR}/LibraryFunctionDetector.c
                                       ${CMAKE_CURRENT_SOURCE_DIR}/StringFunctionTests.c
                                       ${CMAKE_CURRENT_SOURCE_DIR}/OutputFunctionTests.c)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/X86RuntimeLibrary.bc DESTINATION lib)
