LEVEL = ..

include $(LEVEL)/Makefile.config

LIBRARYNAME = UnitTestMain
BUILD_ARCHIVE = 1
CPP.Flags += -Wno-variadic-macros

# FIXME: Parallel dirs is broken?
DIRS = Plugins AddressSpaceCache Registers Tlb CorePlugin
# WindowsMonitor2

include $(LEVEL)/Makefile.common

clean::
	$(Verb) $(RM) -f *Tests
