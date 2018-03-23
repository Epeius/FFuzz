LEVEL := ../..
TESTNAME := AddressSpaceCache
USEDLIBS :=
LINK_COMPONENTS := support


include $(LEVEL)/Makefile.config
include $(PROJ_SRC_ROOT)/Makefile.unittest.coverage

LIBS := $(S2E_TARGET_OBJ)/AddressSpaceCache.o -lkleeCore  -lkleaverSolver -lkleaverExpr -lkleeSupport -lkleeBasic -lLLVMCore -lLLVMSupport $(LIBS)
LIBS += $(CLANG_LIBPROF_PATH)/libprofile_rt.a
