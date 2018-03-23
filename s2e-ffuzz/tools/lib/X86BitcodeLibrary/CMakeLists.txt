include(LLVMBitcode)

set(FLAGS -D_GNU_SOURCE -DNEED_CPU_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
          -DCONFIG_SYMBEX -DS2E_LLVM_LIB -DSTATIC_TRANSLATOR -m32 -w -Wundef
          -Wredundant-decls -Wendif-labels -Wwrite-strings -fno-strict-aliasing
          -Wno-sign-compare -Wno-missing-field-initializers)
set(INC_DIRS ${CMAKE_SOURCE_DIR}/include
             ${CMAKE_CURRENT_SOURCE_DIR}
             ${S2E_SRC_DIR}
             ${S2E_SRC_DIR}/target-${QEMU_TARGET}
             ${S2E_SRC_DIR}/fpu
             ${S2E_SRC_DIR}/tcg
             ${S2E_SRC_DIR}/tcg/${QEMU_TARGET})

link_llvm_bitcode(X86BitcodeLibrary.bc "${FLAGS}" "${INC_DIRS}"
                                       ${S2E_SRC_DIR}/target-${QEMU_TARGET}/helper.c
                                       ${S2E_SRC_DIR}/target-${QEMU_TARGET}/op_helper.c
                                       ${S2E_SRC_DIR}/fpu/softfloat.c
                                       ${CMAKE_CURRENT_SOURCE_DIR}/BitcodeLibrary.cpp)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/X86BitcodeLibrary.bc DESTINATION lib)
