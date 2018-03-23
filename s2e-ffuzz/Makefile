# Environment variables:
#
#  PARALLEL=no
#      Turn off build parallelization.
#
#  BUILD_ARCH=corei7, etc...
#      Overrides the default clang -march settings.
#      Useful to build S2E in VirtualBox or in other VMs that do not support
#      some advanced instruction sets.
#
#  EXTRA_QEMU_FLAGS=...
#      Pass additional flags to QEMU's configure script.
#
#  LLVMBUILD=...
#      Contains llvm-native, llvm-debug, llvm-release, and llvm source folders
#      Can be used to avoid rebuilding clang/llvm for every branch of S2E
#

S2ESRC?=$(CURDIR)/../s2e
S2EPREFIX?=$(CURDIR)/opt
DESTDIR?=/
S2EBUILD:=$(CURDIR)

# corei7 avoids instructions not supported by VirtualBox
# Use "native" instead to optimize for your current CPU.
BUILD_ARCH?=x86-64

LLVMBUILD?=$(S2EBUILD)

OS := $(shell uname)

ifeq ($(PARALLEL), no)
JOBS := 1
else ifeq ($(OS),Darwin)
JOBS := $(patsubst hw.ncpu:%,%,$(shell sysctl hw.ncpu))
else ifeq ($(OS),Linux)
JOBS := $(shell grep -c ^processor /proc/cpuinfo)
endif

MAKE = make -j$(JOBS)

CFLAGS_ARCH:=-march=$(BUILD_ARCH) -mno-sse4.1
CXXFLAGS_ARCH:=-march=$(BUILD_ARCH) -mno-sse4.1

all: all-release guest-tools

all-testsuite: stamps/testsuite-debug-make stamps/testsuite-release-make
all-release: stamps/qemu-release-make stamps/tools-release-make stamps/libs2e-release-make
all-debug: stamps/qemu-debug-make stamps/tools-debug-make stamps/libs2e-debug-make

guest-tools: stamps/guest-tools32-make stamps/guest-tools64-make
guest-tools-install: stamps/guest-tools32-install stamps/guest-tools64-install

install: all-release stamps/qemu-release-install stamps/tools-release-install

ifeq ($(shell ls qemu/vl.c 2>&1),qemu/vl.c)
    $(error You should not run make in the S2E source directory!)
endif

# LLVM variables
LLVM_VERSION=3.9.0
LLVM_SRC=llvm-$(LLVM_VERSION).src.tar.xz
LLVM_SRC_DIR=llvm-$(LLVM_VERSION).src
LLVM_SRC_URL = http://llvm.org/releases/$(LLVM_VERSION)

CLANG_SRC=cfe-$(LLVM_VERSION).src.tar.xz
CLANG_SRC_DIR=cfe-$(LLVM_VERSION).src
CLANG_DEST_DIR=$(LLVM_SRC_DIR)/tools/clang

COMPILER_RT_SRC=compiler-rt-$(LLVM_VERSION).src.tar.xz
COMPILER_RT_SRC_DIR=compiler-rt-$(LLVM_VERSION).src
COMPILER_RT_DEST_DIR=$(LLVM_SRC_DIR)/projects/compiler-rt

# Z3 variables
Z3_VERSION=4.5.0
Z3_SRC=z3-$(Z3_VERSION).tar.gz
Z3_SRC_DIR=z3-z3-$(Z3_VERSION)
Z3_BUILD_DIR=z3
Z3_URL=https://github.com/Z3Prover/z3

# Lua variables
LUA_SRC=lua-5.2.4.tar.gz
LUA_DIR=lua-5.2.4

# Binutils variables
BINUTILS_VERSION=2.27
BINUTILS_SRC=binutils-$(BINUTILS_VERSION).tar.gz
BINUTILS_SRC_DIR=binutils-$(BINUTILS_VERSION)
BINUTILS_SRC_URL=http://ftp.gnu.org/gnu/binutils

# SOCI variables
SOCI_SRC_DIR=soci-src
SOCI_BUILD_DIR=soci
SOCI_GIT_REV=f0c0d25a9160a237c9ef8eddf9f28651621192f3
SOCI_GIT_URL=https://github.com/SOCI/soci.git

KLEE_QEMU_DIRS = $(foreach suffix,-debug -release,$(addsuffix $(suffix),klee qemu))

ifeq ($(LLVMBUILD),$(S2EBUILD))
LLVM_DIRS = llvm-native llvm-debug llvm-release
endif

clean:
	-rm -Rf $(KLEE_QEMU_DIRS)
	-rm -Rf $(Z3_SRC_DIR) $(Z3_BUILD_DIR)
	-rm -Rf stamps

guestclean:
	-$(MAKE) -C $(S2ESRC)/guest clean
	-rm -f stamps/guest-tools

distclean: clean guestclean
	-rm -Rf guest-tools $(LLVM_SRC_DIR) $(LLVM_DIRS) tools-debug tools-release

.PHONY: all all-debug all-release
.PHONY: clean distclean guestclean

ALWAYS:

guest-tools $(KLEE_QEMU_DIRS) $(LLVM_DIRS) libvmi-debug libvmi-release stamps	\
binutils libs2e-debug libs2e-release tools-debug tools-release guest-tools32	\
guest-tools64 testsuite-release testsuite-debug:
	mkdir -p $@

stamps/%-configure: | % stamps
	cd $* && $(CONFIGURE_COMMAND)
	touch $@

stamps/%-make:
	$(MAKE) -C $* $(BUILD_OPTS)
	touch $@

#############
# Downloads #
#############

ifeq ($(LLVMBUILD),$(S2EBUILD))
# Download LLVM
$(LLVM_SRC) $(CLANG_SRC) $(COMPILER_RT_SRC):
	wget $(LLVM_SRC_URL)/$@

.INTERMEDIATE: $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR)

$(LLVM_SRC_DIR): $(LLVM_SRC) $(CLANG_SRC_DIR) $(COMPILER_RT_SRC_DIR)
	tar -xmf $<
	mv $(CLANG_SRC_DIR) $(CLANG_DEST_DIR)
	mv $(COMPILER_RT_SRC_DIR) $(COMPILER_RT_DEST_DIR)

$(CLANG_SRC_DIR): $(CLANG_SRC)
	tar -xmf $<

$(COMPILER_RT_SRC_DIR): $(COMPILER_RT_SRC)
	tar -xmf $<

# Download Binutils
$(BINUTILS_SRC):
	wget $(BINUTILS_SRC_URL)/$@

$(BINUTILS_SRC_DIR): $(BINUTILS_SRC)
	tar -xmzf $<
else
# Use the specified LLVM build folder, don't build LLVM
endif

# Download Lua
$(LUA_SRC):
	wget http://www.lua.org/ftp/$(LUA_SRC)

$(LUA_DIR): $(LUA_SRC)
	tar -zxf $(LUA_SRC)
	cp $(S2ESRC)/lua/luaconf.h $(LUA_DIR)/src

# Download Z3
$(Z3_BUILD_DIR):
	wget $(Z3_URL)/archive/$(Z3_SRC)
	tar -zxf $(Z3_SRC)
	mkdir -p $(S2EBUILD)/$(Z3_BUILD_DIR)

# Download SOCI
$(SOCI_BUILD_DIR):
	git clone $(SOCI_GIT_URL) $(SOCI_SRC_DIR)
	cd $(SOCI_SRC_DIR) && git checkout $(SOCI_GIT_REV)
	mkdir -p $(S2EBUILD)/$(SOCI_BUILD_DIR)

ifeq ($(LLVMBUILD),$(S2EBUILD))

############
# Binutils #
############

BINUTILS_CONFIGURE_FLAGS = --prefix=$(S2EPREFIX)    \
                           --enable-gold            \
                           --enable-plugins

stamps/binutils-configure: $(BINUTILS_SRC_DIR)
stamps/binutils-configure: CONFIGURE_COMMAND = CFLAGS="-fPIC"                               \
                                               CXXFLAGS="-fPIC"                             \
                                               $(S2EBUILD)/$(BINUTILS_SRC_DIR)/configure    \
                                               $(BINUTILS_CONFIGURE_FLAGS)

stamps/binutils-make: stamps/binutils-configure
	$(MAKE) -C binutils
	$(MAKE) -C binutils install
	touch $@

########
# LLVM #
########

# First build LLVM with the system's compiler
stamps/llvm-native-configure: stamps/binutils-make $(LLVM_SRC_DIR)
stamps/llvm-native-configure: CONFIGURE_COMMAND = cmake -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)     \
                                                  -DLLVM_BINUTILS_INCDIR=$(S2EPREFIX)/include   \
                                                  -DLLVM_ENABLE_ASSERTIONS=Off                  \
                                                  -DCMAKE_BUILD_TYPE=Release                    \
                                                  -DLLVM_INCLUDE_EXAMPLES=Off                   \
                                                  -DLLVM_INCLUDE_DOCS=Off                       \
                                                  -DLLVM_TARGETS_TO_BUILD="X86"                 \
                                                  -LLVM_TARGET_ARCH="X86_64"                    \
                                                  -G "Unix Makefiles"                           \
                                                  $(LLVMBUILD)/$(LLVM_SRC_DIR)

stamps/llvm-native-make: stamps/llvm-native-configure
	$(MAKE) -C llvm-native
	$(MAKE) -C llvm-native install
	touch $@

CLANG_CC = $(S2EPREFIX)/bin/clang
CLANG_CXX = $(S2EPREFIX)/bin/clang++
CLANG_LIB = $(S2EPREFIX)/lib

# Then build LLVM with the clang compiler

LLVM_CONFIGURE_FLAGS = -DLLVM_TARGETS_TO_BUILD="X86"        \
                       -DLLVM_TARGET_ARCH="X86_64"          \
                       -DLLVM_INCLUDE_EXAMPLES=Off          \
                       -DLLVM_INCLUDE_DOCS=Off              \
                       -DLLVM_ENABLE_RTTI=On                \
                       -DLLVM_ENABLE_EH=On                  \
                       -DENABLE_ASSERTIONS=On               \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS=$(CFLAGS_ARCH)       \
                       -DCMAKE_CXX_FLAGS=$(CXXFLAGS_ARCH)   \
                       -G "Unix Makefiles"

stamps/llvm-debug-configure: stamps/llvm-native-make
stamps/llvm-debug-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)  \
                                                 -DCMAKE_BUILD_TYPE=Debug       \
                                                 $(LLVMBUILD)/$(LLVM_SRC_DIR)

stamps/llvm-release-configure: stamps/llvm-native-make
stamps/llvm-release-configure: CONFIGURE_COMMAND = cmake $(LLVM_CONFIGURE_FLAGS)\
                                                   -DCMAKE_BUILD_TYPE=Release   \
                                                   $(LLVMBUILD)/$(LLVM_SRC_DIR)

stamps/llvm-debug-make: stamps/llvm-debug-configure

stamps/llvm-release-make: stamps/llvm-release-configure

else
stamps/llvm-release-make:
	echo "Won't build"
stamps/llvm-debug-make:
	echo "Won't build"
stamps/llvm-native-make:
	echo "Won't build"
endif

########
# SOCI #
########

SOCI_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)  \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)    \
                       -DCMAKE_C_FLAGS="-fPIC"              \
                       -G "Unix Makefiles"

stamps/soci-configure: stamps/llvm-native-make $(SOCI_BUILD_DIR)
stamps/soci-configure: CONFIGURE_COMMAND = cmake $(SOCI_CONFIGURE_FLAGS)    \
                                           $(S2EBUILD)/$(SOCI_SRC_DIR)/src

stamps/soci-make: stamps/soci-configure
	$(MAKE) -C $(SOCI_BUILD_DIR)
	$(MAKE) -C $(SOCI_BUILD_DIR) install
	touch $@

######
# Z3 #
######

Z3_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)                \
                     -DCMAKE_C_COMPILER=$(CLANG_CC)                     \
                     -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                  \
                     -DCMAKE_C_FLAGS="-fno-omit-frame-pointer -fPIC"    \
                     -DCMAKE_CXX_FLAGS="-fno-omit-frame-pointer -fPIC"  \
                     -DBUILD_LIBZ3_SHARED=Off                           \
                     -G "Unix Makefiles"

stamps/z3-configure: stamps/llvm-native-make $(Z3_BUILD_DIR)
	cd $(Z3_SRC_DIR) &&                                         \
	python contrib/cmake/bootstrap.py create
	cd $(Z3_BUILD_DIR) &&                                       \
	cmake $(Z3_CONFIGURE_FLAGS) $(S2EBUILD)/$(Z3_SRC_DIR)
	touch $@

stamps/z3-make: stamps/z3-configure
	$(MAKE) -C $(Z3_BUILD_DIR)
	$(MAKE) -C $(Z3_BUILD_DIR) install
	touch $@

#######
# Lua #
#######

stamps/lua-make: $(LUA_DIR)
	$(MAKE) -C $^ linux CFLAGS="-DLUA_USE_LINUX -O2 -g -fPIC"
	touch $@

########
# KLEE #
########

KLEE_CONFIGURE_FLAGS = -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)                                  \
                       -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"       \
                       -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fno-omit-frame-pointer -fPIC"   \
                       -DCMAKE_C_COMPILER=$(CLANG_CC)                                       \
                       -DCMAKE_CXX_COMPILER=$(CLANG_CXX)                                    \
                       -DUSE_CMAKE_FIND_PACKAGE_LLVM=On                                     \
                       -DENABLE_TESTS=Off                                                   \
                       -DENABLE_DOCS=Off                                                    \
                       -DENABLE_SOLVER_Z3=On                                                \
                       -DZ3_INCLUDE_DIRS=$(S2EPREFIX)/include                               \
                       -DZ3_LIBRARIES=$(S2EPREFIX)/lib/libz3.a

stamps/klee-debug-configure: stamps/llvm-debug-make stamps/z3-make
stamps/klee-debug-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                      \
                                                 -DCMAKE_BUILD_TYPE=Debug                           \
                                                 -DLLVM_DIR=$(LLVMBUILD)/llvm-debug/lib/cmake/llvm  \
                                                 $(S2ESRC)/klee

stamps/klee-release-configure: stamps/llvm-release-make stamps/z3-make
stamps/klee-release-configure: CONFIGURE_COMMAND = cmake $(KLEE_CONFIGURE_FLAGS)                        \
                                                   -DCMAKE_BUILD_TYPE=Release                           \
                                                   -DLLVM_DIR=$(LLVMBUILD)/llvm-release/lib/cmake/llvm  \
                                                   $(S2ESRC)/klee

stamps/klee-debug-make: stamps/klee-debug-configure

stamps/klee-release-make: stamps/klee-release-configure

##########
# LibVMI #
##########

LIBVMI_COMMON_FLAGS = -DCMAKE_MODULE_PATH=$(S2ESRC)/cmake           \
                      -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX)           \
                      -DCMAKE_C_COMPILER=$(CLANG_CC)                \
                      -DCMAKE_CXX_COMPILER=$(CLANG_CXX)             \
                      -DCMAKE_C_FLAGS="$(CFLAGS_ARCH) -fPIC"        \
                      -DCMAKE_CXX_FLAGS="$(CXXFLAGS_ARCH) -fPIC"    \
                      -G "Unix Makefiles"

stamps/libvmi-debug-configure: stamps/llvm-debug-make
stamps/libvmi-debug-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                         \
                                                   -DLLVM_DIR=$(LLVMBUILD)/llvm-debug/lib/cmake/llvm    \
                                                   -DCMAKE_BUILD_TYPE=Debug                             \
                                                   $(S2ESRC)/libvmi

stamps/libvmi-release-configure: stamps/llvm-release-make
stamps/libvmi-release-configure: CONFIGURE_COMMAND = cmake $(LIBVMI_COMMON_FLAGS)                           \
                                                     -DLLVM_DIR=$(LLVMBUILD)/llvm-release/lib/cmake/llvm    \
                                                     -DCMAKE_BUILD_TYPE=Release                             \
                                                     $(S2ESRC)/libvmi

stamps/libvmi-debug-make: stamps/libvmi-debug-configure
	$(MAKE) -C libvmi-debug
	$(MAKE) -C libvmi-debug install
	touch $@

stamps/libvmi-release-make: stamps/libvmi-release-configure
	$(MAKE) -C libvmi-release
	$(MAKE) -C libvmi-release install
	touch $@

########
# QEMU #
########

ifdef $(CGC)
QEMU_TARGETS=i386-s2e-softmmu,i386-softmmu
else
QEMU_TARGETS=x86_64-s2e-softmmu,x86_64-softmmu,x86_64-s2e_sp-softmmu,i386-s2e-softmmu,i386-softmmu,i386-s2e_sp-softmmu
endif

QEMU_CONFIGURE_FLAGS = --prefix=$(S2EPREFIX)                                               \
                       --cc=$(CLANG_CC)                                                    \
                       --cxx=$(CLANG_CXX)                                                  \
                       --target-list=$(QEMU_TARGETS)                                       \
                       --enable-s2e                                                        \
                       --with-pkgversion=S2E                                               \
                       --enable-boost                                                      \
                       --enable-database                                                   \
                       --with-soci-incdir=$(S2EPREFIX)/include                             \
                       --with-soci-libdir=$(S2EPREFIX)/lib64                               \
                       --with-liblua=$(S2EBUILD)/$(LUA_DIR)/src                            \
                       --extra-cxxflags="-Wno-deprecated -std=c++11 -Wno-c++11-narrowing"  \
                       --extra-ldflags="-ljemalloc"                                        \
                       --with-libvmi-incdir=$(S2ESRC)/libvmi/include                       \
                       --with-z3-incdir=$(S2EPREFIX)/include                               \
                       --with-z3-libdir=$(S2EPREFIX)/lib                                   \
                       --disable-virtfs                                                    \
                       --disable-sdl                                                    \
                       --disable-bluez                                                     \
                       --disable-vde                                                       \
                       --disable-libiscsi                                                  \
                       $(EXTRA_QEMU_FLAGS)

QEMU_DEBUG_FLAGS = --with-llvm=$(LLVMBUILD)/llvm-debug                  \
                   --with-libvmi-libdir=$(S2EBUILD)/libvmi-debug        \
                   --with-klee=$(S2EBUILD)/klee-debug                   \
                   --enable-debug

QEMU_RELEASE_FLAGS = --with-llvm=$(LLVMBUILD)/llvm-release/             \
                     --with-libvmi-libdir=$(S2EBUILD)/libvmi-release    \
                     --with-klee=$(S2EBUILD)/klee-release

stamps/qemu-debug-configure: stamps/lua-make stamps/libvmi-debug-make stamps/klee-debug-make stamps/soci-make
stamps/qemu-debug-configure: export CFLAGS:=$(CFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-debug-configure: CONFIGURE_COMMAND = $(S2ESRC)/qemu/configure   \
                                                 $(QEMU_CONFIGURE_FLAGS)    \
                                                 $(QEMU_DEBUG_FLAGS)

stamps/qemu-release-configure: stamps/lua-make stamps/libvmi-release-make stamps/klee-release-make stamps/soci-make
stamps/qemu-release-configure: export CFLAGS:=$(CFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-release-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH) -fno-omit-frame-pointer
stamps/qemu-release-configure: CONFIGURE_COMMAND = $(S2ESRC)/qemu/configure \
                                                   $(QEMU_CONFIGURE_FLAGS)  \
                                                   $(QEMU_RELEASE_FLAGS)

stamps/qemu-debug-make:  stamps/qemu-debug-configure
	$(MAKE) -C qemu-debug $(BUILD_OPTS) install
	touch $@

stamps/qemu-release-make: stamps/qemu-release-configure
	$(MAKE) -C qemu-release $(BUILD_OPTS) install
	touch $@

stamps/qemu-release-install: stamps/qemu-release-make
	install $(S2EBUILD)/qemu-release/i386-s2e-softmmu/op_helper.bc $(S2EPREFIX)/share/qemu/op_helper.bc.i386
	install $(S2EBUILD)/qemu-release/i386-softmmu/qemu-system-i386 $(S2EPREFIX)/bin/qemu-system-i386
	install $(S2EBUILD)/qemu-release/i386-s2e-softmmu/qemu-system-i386 $(S2EPREFIX)/bin/qemu-system-i386-s2e

ifndef $(CGC)
	install $(S2EBUILD)/qemu-release/i386-s2e_sp-softmmu/qemu-system-i386 $(S2EPREFIX)/bin/qemu-system-i386-s2e_sp
	install $(S2EBUILD)/qemu-release/i386-s2e_sp-softmmu/op_helper.bc $(S2EPREFIX)/share/qemu/op_helper_sp.bc.i386
	install $(S2EBUILD)/qemu-release/x86_64-s2e-softmmu/op_helper.bc $(S2EPREFIX)/share/qemu/op_helper.bc.x86_64
	install $(S2EBUILD)/qemu-release/x86_64-softmmu/qemu-system-x86_64 $(S2EPREFIX)/bin/qemu-system-x86_64
	install $(S2EBUILD)/qemu-release/x86_64-s2e-softmmu/qemu-system-x86_64 $(S2EPREFIX)/bin/qemu-system-x86_64-s2e
	install $(S2EBUILD)/qemu-release/x86_64-s2e_sp-softmmu/qemu-system-x86_64 $(S2EPREFIX)/bin/qemu-system-x86_64-s2e_sp
	install $(S2EBUILD)/qemu-release/x86_64-s2e_sp-softmmu/op_helper.bc $(S2EPREFIX)/share/qemu/op_helper_sp.bc.x86_64
endif

	install $(S2ESRC)/qemu/s2e/Plugins/KeyValueStore.py $(S2EPREFIX)/bin/
	cd $(S2ESRC) && if [ -d ".git" ]; then git rev-parse HEAD > $(S2EPREFIX)/share/qemu/git-sha1; fi
	touch $@

##########
# libs2e #
##########

LIBS2E_CONFIGURE_FLAGS = --with-liblua=$(S2EBUILD)/$(LUA_DIR)/src  \
                         --with-libvmi-src=$(S2ESRC)/libvmi        \
                         --with-z3-incdir=$(S2EPREFIX)/include     \
                         --with-z3-libdir=$(S2EPREFIX)/lib         \
                         --enable-s2e                              \
                         $(EXTRA_QEMU_FLAGS)

LIBS2E_DEBUG_FLAGS = --with-llvm=$(LLVMBUILD)/llvm-debug           \
                     --with-klee=$(S2EBUILD)/klee-debug            \
                     --with-libvmi-lib=$(S2EBUILD)/libvmi-debug    \
                     --enable-debug

LIBS2E_RELEASE_FLAGS = --with-llvm=$(LLVMBUILD)/llvm-release       \
                       --with-klee=$(S2EBUILD)/klee-release        \
                       --with-libvmi-lib=$(S2EBUILD)/libvmi-release

stamps/libs2e-debug-configure: $(S2ESRC)/libs2e/configure
stamps/libs2e-debug-configure: export CFLAGS:=$(CFLAGS_ARCH)
stamps/libs2e-debug-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH)
stamps/libs2e-debug-configure: export CC:=$(CLANG_CC)
stamps/libs2e-debug-configure: export CXX:=$(CLANG_CXX)
stamps/libs2e-debug-configure: stamps/lua-make stamps/libvmi-debug-make stamps/klee-debug-make stamps/soci-make
stamps/libs2e-debug-configure: CONFIGURE_COMMAND = $(S2ESRC)/libs2e/configure   \
                                                   $(LIBS2E_CONFIGURE_FLAGS)    \
                                                   $(LIBS2E_DEBUG_FLAGS)

stamps/libs2e-release-configure: $(S2ESRC)/libs2e/configure
stamps/libs2e-release-configure: export CFLAGS:=$(CFLAGS_ARCH)
stamps/libs2e-release-configure: export CXXFLAGS:=$(CXXFLAGS_ARCH)
stamps/libs2e-release-configure: export CC:=$(CLANG_CC)
stamps/libs2e-release-configure: export CXX:=$(CLANG_CXX)
stamps/libs2e-release-configure: stamps/lua-make stamps/libvmi-release-make stamps/klee-release-make stamps/soci-make
stamps/libs2e-release-configure: CONFIGURE_COMMAND = $(S2ESRC)/libs2e/configure \
                                                     $(LIBS2E_CONFIGURE_FLAGS)  \
                                                     $(LIBS2E_RELEASE_FLAGS)

stamps/libs2e-debug-make:  stamps/libs2e-debug-configure

stamps/libs2e-release-make:  stamps/libs2e-release-configure

#########
# Tools #
#########

TOOLS_CONFIGURE_FLAGS = -DCMAKE_MODULE_PATH=$(S2ESRC)/cmake \
                        -DCMAKE_INSTALL_PREFIX=$(S2EPREFIX) \
                        -DCMAKE_C_COMPILER=$(CLANG_CC)      \
                        -DCMAKE_CXX_COMPILER=$(CLANG_CXX)   \
                        -DCMAKE_C_FLAGS=$(CFLAGS_ARCH)      \
                        -DCMAKE_CXX_FLAGS=$(CXXFLAGS_ARCH)  \
                        -DS2E_SRC_DIR=$(S2ESRC)/qemu        \
                        -G "Unix Makefiles"

stamps/tools-debug-configure: stamps/llvm-debug-make stamps/libvmi-debug-make
stamps/tools-debug-configure: CONFIGURE_COMMAND = cmake $(TOOLS_CONFIGURE_FLAGS)                    \
                                                  -DLLVM_DIR=$(LLVMBUILD)/llvm-debug/lib/cmake/llvm \
                                                  -DVMI_DIR=$(S2EBUILD)/libvmi-debug                \
                                                  -DCMAKE_BUILD_TYPE=Debug                          \
                                                  $(S2ESRC)/tools

stamps/tools-release-configure: stamps/llvm-release-make stamps/libvmi-release-make
stamps/tools-release-configure: CONFIGURE_COMMAND = cmake $(TOOLS_CONFIGURE_FLAGS)                      \
                                                    -DLLVM_DIR=$(LLVMBUILD)/llvm-release/lib/cmake/llvm \
                                                    -DVMI_DIR=$(S2EBUILD)/libvmi-release                \
                                                    -DCMAKE_BUILD_TYPE=Release                          \
                                                    $(S2ESRC)/tools

stamps/tools-debug-make: stamps/tools-debug-configure

stamps/tools-release-make: stamps/tools-release-configure

stamps/tools-release-install: stamps/tools-release-make
	$(MAKE) -C tools-release install

###############
# Guest tools #
###############

GUEST_CONFIGURE_COMMAND = $(S2ESRC)/guest/configure

stamps/guest-tools%-configure: CONFIGURE_COMMAND = $(GUEST_CONFIGURE_COMMAND)

stamps/guest-tools32-make: stamps/guest-tools32-configure
stamps/guest-tools32-make: BUILD_OPTS = CFLAGS="-m32"

stamps/guest-tools64-make: stamps/guest-tools64-configure
stamps/guest-tools64-make: BUILD_OPTS = CFLAGS="-m64"

stamps/guest-tools%-install: stamps/guest-tools%-make
	mkdir -p $(DESTDIR)/$(S2EPREFIX)/bin/guest-tools$*
	$(MAKE) -C guest-tools$* INSTALL_DIR=$(DESTDIR)/$(S2EPREFIX)/bin/guest-tools$* install
	touch $@

#############
# Testsuite #
#############

GMOCK_BUILD = $(S2EBUILD)/gmock-1.6.0
GTEST_DIR = $(LLVMBUILD)/$(LLVM_SRC_DIR)/utils/unittest/googletest/
GMOCK_DIR = $(GMOCK_BUILD)

gmock-1.6.0.zip:
	wget http://googlemock.googlecode.com/files/gmock-1.6.0.zip

gmock-1.6.0: gmock-1.6.0.zip
	unzip $^

stamps/gmock-configure: gmock-1.6.0 stamps/llvm-native-make
	cd $(GMOCK_BUILD) && $(GMOCK_BUILD)/configure \
	CC=$(CLANG_CC)                                \
	CXX=$(CLANG_CXX)
	touch $@

stamps/gmock-build: stamps/gmock-configure
	cd $(GMOCK_BUILD) && make -j$(JOBS)
#	cd $(GMOCK_BUILD)/lib && $(LLVMBUILD)/llvm-native/Release/bin/clang++ -I$(GTEST_DIR)/include -I$(GTEST_DIR) -I$(GMOCK_DIR)/include \
#      -I$(GMOCK_DIR) -c $(GTEST_DIR)/src/gtest-all.cc
	cd $(GMOCK_BUILD)/lib && $(CLANG_CC)  -D__STDC_LIMIT_MACROS -D__STDC_CONSTANT_MACROS -I	$(LLVMBUILD)/$(LLVM_SRC_DIR)/include -I$(LLVMBUILD)/llvm-native/include -I$(GTEST_DIR)/include -I$(GTEST_DIR) -I$(GMOCK_DIR)/include \
      -I$(GMOCK_DIR) -c $(GMOCK_DIR)/src/gmock-all.cc
	cd $(GMOCK_BUILD)/lib && ar -rv libgmock.a gmock-all.o
	touch $@

TESTSUITE_CONFIGURE_COMMAND = $(S2ESRC)/testsuite/configure                             \
                              --with-llvmsrc=$(LLVMBUILD)/$(LLVM_SRC_DIR)               \
                              --with-s2e-src=$(S2ESRC)/qemu                             \
                              --with-klee-src=$(S2ESRC)/klee                            \
                              --with-s2eobj-debug=$(S2EBUILD)/qemu-debug                \
                              --with-s2eobj-release=$(S2EBUILD)/qemu-release            \
                              --with-gmock=$(GMOCK_BUILD)                               \
                              --with-libvmi-src=$(S2ESRC)/libvmi                        \
                              --with-libvmi-obj=$(S2EBUILD)/libvmi-debug                \
                              --with-clang-profile-lib=$(CLANG_LIB)                     \
                              --target=x86_64                                           \
                              CC=$(CLANG_CC)                                            \
                              CXX=$(CLANG_CXX)                                          \
                              CXXFLAGS="-g -O0 -fsanitize=address"                      \
                              LDFLAGS="-g -fsanitize=address"                           \
                              REQUIRES_EH=1

stamps/testsuite-release-configure: stamps/llvm-release-make stamps/qemu-release-make stamps/qemu-debug-make stamps/gmock-build
stamps/testsuite-release-configure: CONFIGURE_COMMAND = $(TESTSUITE_CONFIGURE_COMMAND)              \
                                                        --with-klee-obj=$(S2EBUILD)/klee-release    \
                                                        --with-llvmobj=$(LLVMBUILD)/llvm-release

stamps/testsuite-debug-configure: stamps/llvm-debug-make stamps/qemu-release-make stamps/qemu-debug-make stamps/gmock-build
stamps/testsuite-debug-configure: CONFIGURE_COMMAND = $(TESTSUITE_CONFIGURE_COMMAND)            \
                                                      --with-klee-obj=$(S2EBUILD)/klee-debug    \
                                                      --with-llvmobj=$(LLVMBUILD)/llvm-debug


stamps/testsuite-release-make:  stamps/testsuite-release-configure
stamps/testsuite-release-make: BUILD_OPTS = ENABLE_OPTIMIZED=1 REQUIRES_RTTI=1 REQUIRES_EH=1
stamps/testsuite-debug-make:  stamps/testsuite-debug-configure
stamps/testsuite-debug-make: BUILD_OPTS = ENABLE_OPTIMIZED=0 REQUIRES_RTTI=1 REQUIRES_EH=1

stamps/testsuite-run: stamps/testsuite-make-debug
	cd testsuite && make ENABLE_OPTIMIZED=0 REQUIRES_RTTI=1 REQUIRES_EH=1 unittests

stamps/testsuite-run-coverage: stamps/testsuite-make-debug
	cd testsuite && make ENABLE_OPTIMIZED=0 REQUIRES_RTTI=1 REQUIRES_EH=1 unittests coverage-report
