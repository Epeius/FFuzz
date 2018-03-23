LEVEL := ../..
TESTNAME := WindowsMonitor2
#USEDLIBS := S2EMocks.a
LINK_COMPONENTS := support


include $(LEVEL)/Makefile.config
include $(PROJ_SRC_ROOT)/Makefile.unittest.coverage

LIBS := $(S2E_TARGET_OBJ)/Plugins/WindowsMonitor2.o \
		$(S2E_TARGET_OBJ)/Plugins/WindowsInterceptor/WindowsInterceptor.o \
		$(S2E_TARGET_OBJ)/Plugin.o \
		$(S2E_TARGET_OBJ)/Signals/signals.o \
		$(S2E_TARGET_OBJ)/../../qdict.o \
		$(S2E_TARGET_OBJ)/../../qbool.o \
		$(S2E_TARGET_OBJ)/../../qfloat.o \
		$(S2E_TARGET_OBJ)/../../qint.o \
		$(S2E_TARGET_OBJ)/../../qlist.o \
		$(S2E_TARGET_OBJ)/../../qstring.o \
		-lkleeCore  -lkleaverSolver -lkleaverExpr -lkleeSupport -lkleeBasic -lLLVMCore -lLLVMSupport $(LIBS)
LIBS +=  $(CLANG_LIBPROF_PATH)/libprofile_rt.a
