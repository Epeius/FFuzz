LEVEL := ../..
TESTNAME := Plugins
USEDLIBS :=
LINK_COMPONENTS := support

include $(LEVEL)/Makefile.config
include $(LLVM_SRC_ROOT)/unittests/Makefile.unittest

LIBS += -lkleaverExpr -lkleeBasic
LIBS += -lstp $(CLANG_LIBPROF_PATH)/libprofile_rt.a
