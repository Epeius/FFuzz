include(LLVMBitcode)

set(FLAGS -D_GNU_SOURCE -DNEED_CPU_H -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE
          -DCONFIG_SYMBEX -DS2E_LLVM_LIB -DSTATIC_TRANSLATOR -m64 -w -Wundef
          -Wredundant-decls -Wendif-labels -Wwrite-strings -Wno-sign-compare
          -fno-strict-aliasing -Wno-missing-field-initializers)
set(INC_DIRS ${CMAKE_CURRENT_SOURCE_DIR}
             ${S2E_SRC_DIR}
             ${S2E_SRC_DIR}/target-${QEMU_TARGET}
             ${S2E_SRC_DIR}/fpu
             ${S2E_SRC_DIR}/tcg
             ${S2E_SRC_DIR}/tcg/${QEMU_TARGET})

link_llvm_bitcode(X8664BitcodeLibrary.bc "${FLAGS}" "${INC_DIRS}"
                                         ${S2E_SRC_DIR}/target-${QEMU_TARGET}/helper.c
                                         ${S2E_SRC_DIR}/target-${QEMU_TARGET}/op_helper.c
                                         ${S2E_SRC_DIR}/fpu/softfloat.c)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/X8664BitcodeLibrary.bc DESTINATION lib)
