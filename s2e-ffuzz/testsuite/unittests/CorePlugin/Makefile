LEVEL := ../..
TESTNAME := CorePluginTest
#USEDLIBS := S2EMocks.a
LINK_COMPONENTS := support jit bitreader bitwriter ipo linker engine


include $(LEVEL)/Makefile.config
include $(PROJ_SRC_ROOT)/Makefile.unittest.coverage

LIBS := \
	$(S2E_TARGET_OBJ)/Plugin.o \
        $(S2E_TARGET_OBJ)/Plugins/CorePlugin.o \
        $(S2E_TARGET_OBJ)/PluginManager.o \
	$(S2E_TARGET_OBJ)/Signals/signals.o \
        $(S2E_TARGET_OBJ)/Synchronization.o \
	$(S2E_TARGET_OBJ)/../../qdict.o \
	$(S2E_TARGET_OBJ)/../../qbool.o \
	$(S2E_TARGET_OBJ)/../../qfloat.o \
	$(S2E_TARGET_OBJ)/../../qint.o \
	$(S2E_TARGET_OBJ)/../../qlist.o \
	$(S2E_TARGET_OBJ)/../../qstring.o \
        $(LIBS)

#-lkleeCore -lkleeModule  -lkleaverSolver -lkleaverExpr -lkleeSupport -lkleeBasic \
#-lLLVMX86AsmParser -lLLVMX86Disassembler -lLLVMX86CodeGen -lLLVMSelectionDAG -lLLVMAsmPrinter \
#-lLLVMMCParser -lLLVMX86Desc -lLLVMX86Info -lLLVMX86AsmPrinter -lLLVMX86Utils -lLLVMLinker -lLLVMArchive \
#-lLLVMipo -lLLVMVectorize -lLLVMBitWriter -lLLVMBitReader -lLLVMJIT -lLLVMRuntimeDyld -lLLVMExecutionEngine \
#-lLLVMCodeGen -lLLVMScalarOpts -lLLVMInstCombine -lLLVMTransformUtils -lLLVMipa -lLLVMAnalysis \
#-lLLVMTarget -lLLVMMC -lLLVMObject -lLLVMCore -lLLVMSupport \

LIBS +=  $(CLANG_LIBPROF_PATH)/libprofile_rt.a
