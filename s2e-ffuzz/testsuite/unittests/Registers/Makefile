LEVEL := ../..
TESTNAME := Registers
USEDLIBS := S2EMocks.a
LINK_COMPONENTS := support


include $(LEVEL)/Makefile.config
include $(PROJ_SRC_ROOT)/Makefile.unittest.coverage

LIBS := $(S2E_TARGET_OBJ)/S2EExecutionStateRegisters.o -lkleeCore  -lkleaverSolver -lkleaverExpr -lkleeSupport -lkleeBasic -lLLVMCore -lLLVMSupport $(LIBS)
LIBS += $(CLANG_LIBPROF_PATH)/libprofile_rt.a
