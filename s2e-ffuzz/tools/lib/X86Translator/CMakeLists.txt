add_definitions(-D__STDC_FORMAT_MACROS -D_GNU_SOURCE -DNEED_CPU_H
                -D_FILE_OFFSET_BITS=64 -D_LARGEFILE_SOURCE -DSTATIC_TRANSLATOR
                -DTARGET_PHYS_ADDR_BITS=64 -DCONFIG_SYMBEX)
add_library(X86Translator STATIC ${S2E_SRC_DIR}/target-${QEMU_TARGET}/translate.c
                                 ${S2E_SRC_DIR}/target-${QEMU_TARGET}/helper.c
                                 ${S2E_SRC_DIR}/target-${QEMU_TARGET}/op_helper.c
                                 ${S2E_SRC_DIR}/fpu/softfloat.c
                                 ${S2E_SRC_DIR}/tcg/tcg.c
                                 ${S2E_SRC_DIR}/tcg/optimize.c
                                 ${S2E_SRC_DIR}/tcg/tcg-llvm.cpp
                                 ${S2E_SRC_DIR}/translate-all.c
                                 ${S2E_SRC_DIR}/cutils.c
                                 Translator.cpp
                                 TranslatorWrapper.cpp)
target_include_directories(X86Translator PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}
                                                 ${GLIB2_INCLUDE_DIRS}
                                                 ${S2E_SRC_DIR}
                                                 ${S2E_SRC_DIR}/target-${QEMU_TARGET}
                                                 ${S2E_SRC_DIR}/qapi
                                                 ${S2E_SRC_DIR}/fpu
                                                 ${S2E_SRC_DIR}/tcg
                                                 ${S2E_SRC_DIR}/tcg/${QEMU_TARGET})
target_compile_options(X86Translator PRIVATE -Wredundant-decls -w -Wundef
                       -Wendif-labels -Wwrite-strings -fno-strict-aliasing
                       -Wno-sign-compare -Wno-missing-field-initializers
                       -fexceptions)
