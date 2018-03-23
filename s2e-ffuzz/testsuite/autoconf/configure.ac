dnl **************************************************************************
dnl * Initialize
dnl **************************************************************************
AC_INIT([[S2E]],[[0.01]],[vitaly.chipounov@epfl.ch])

AC_DEFUN([LLVM_PROG_PERL], [
AC_PATH_PROG(PERL, [perl], [none])
if test "$PERL" != "none"; then
  AC_MSG_CHECKING(for Perl $1 or newer)
  if $PERL -e 'use $1;' 2>&1 > /dev/null; then
    AC_MSG_RESULT(yes)
  else
    PERL=none
    AC_MSG_RESULT(not found)
  fi
fi
])


dnl Identify where LLVM source tree is (this is patched by
dnl AutoRegen.sh)
LLVM_SRC_ROOT=XXX

dnl Tell autoconf that the auxilliary files are actually located in
dnl the LLVM autoconf directory, not here.
AC_CONFIG_AUX_DIR($LLVM_SRC_ROOT/autoconf)

dnl Tell autoconf that this is an LLVM project being configured
dnl This provides the --with-llvmsrc and --with-llvmobj options
LLVM_CONFIG_PROJECT("","")

dnl Verify that the source directory is valid
AC_CONFIG_SRCDIR(["Makefile.config.in"])

dnl Configure a common Makefile
AC_CONFIG_FILES(Makefile.config)

dnl Configure project makefiles
dnl List every Makefile that exists within your source tree
AC_CONFIG_HEADERS([include/testsuite/config.h])

dnl FIXME: Make out of tree builds work.
AC_CONFIG_MAKEFILE(Makefile)
AC_CONFIG_MAKEFILE(Makefile.common)

dnl Do the first stage of configuration for testsuite-config.in.
AC_CONFIG_FILES([tools/testsuite-config/testsuite-config.in])

AC_LANG([C++])

dnl **************************************************************************
dnl Find the host

AC_CANONICAL_TARGET

dnl Determine the platform type and cache its value. This helps us configure
dnl the System library to the correct build platform.
AC_CACHE_CHECK([type of operating system we're going to host on],
               [testsuite_cv_os_type],
[case $host in
  *-*-linux*)
    host_supports_posix_runtime=yes ;;
  *)
    host_supports_posix_runtime=no ;;
esac])

OS=`uname -a`
case "$OS" in
  MINGW*) OS=mingw
    ;;
  mingw*) OS=mingw
  ;;
  Linux*) OS=linux
  ;;
  *) OS=
  ;;
esac

dnl **************************************************************************
dnl Verify that we can find s2e

AC_ARG_WITH(s2e_src,
  AS_HELP_STRING([--with-s2e-src],
    [Location of S2E source code]),,)

dnl Make the paths absolute.
s2e_src=`cd $with_s2e_src 2> /dev/null; pwd`

AC_MSG_RESULT([$s2e_src])
AC_SUBST(S2E_SRC,$s2e_src)

dnl **************************************************************************
dnl Verify that we can find s2e debug objects

AC_ARG_WITH(s2eobj_debug,
  AS_HELP_STRING([--with-s2eobj-debug],
    [Location of S2E debug object files]),,)

AC_MSG_CHECKING([S2E debug build])

if test ! -d "$with_s2eobj_debug"; then
  AC_MSG_ERROR([$with_s2eobj_debug does not exist])
fi

dnl Make the paths absolute.
s2eobj_debug=`cd "$with_s2eobj_debug" 2> /dev/null; pwd`

AC_MSG_RESULT([$s2eobj_debug])
AC_SUBST(S2E_OBJ_DEBUG,$s2eobj_debug)

dnl **************************************************************************
dnl Verify that we can find s2e release objects

AC_ARG_WITH(s2eobj_release,
  AS_HELP_STRING([--with-s2eobj-release],
    [Location of S2E relase object files]),,)

AC_MSG_CHECKING([S2E release build])

if test ! -d "$with_s2eobj_release"; then
  AC_MSG_ERROR([$with_s2eobj_release does not exist])
fi

dnl Make the paths absolute.
s2eobj_release=`cd "$with_s2eobj_release" 2> /dev/null; pwd`

AC_MSG_RESULT([$s2eobj_release])
AC_SUBST(S2E_OBJ_RELEASE,$s2eobj_release)

dnl **************************************************************************
dnl Check path to libprofile_rt.a

AC_ARG_WITH(clang_profile_lib,
  AS_HELP_STRING([--with-clang-profile-lib],
    [Path to libprofile_rt.a]),,)

AC_MSG_CHECKING([libprofile_rt.a])

if test ! -f "$with_clang_profile_lib/libprofile_rt.a"; then
  AC_MSG_ERROR([$with_clang_profile_lib/libprofile_rt.a does not exist])
fi

dnl Make the paths absolute.
s2eobj_release=`cd "$with_clang_profile_lib" 2> /dev/null; pwd`

AC_MSG_RESULT([$with_clang_profile_lib])
AC_SUBST(CLANG_LIBPROF_PATH,$with_clang_profile_lib)

dnl **************************************************************************
dnl Verify that we can find glib

AC_MSG_CHECKING([glib])

glib_req_ver=2.12

if pkg-config --atleast-version=$glib_req_ver gthread-2.0 > /dev/null 2>&1
then
    glib_cflags=`pkg-config --cflags gthread-2.0 2>/dev/null`
    glib_libs=`pkg-config --libs gthread-2.0 2>/dev/null`
else
  AC_MSG_ERROR([glib required])
fi

AC_MSG_RESULT([$glib_cflags])
AC_SUBST(GLIB_CFLAGS,$glib_cflags)

AC_MSG_RESULT([$glib_libs])
AC_SUBST(GLIB_LIBS,$glib_libs)

dnl **************************************************************************
dnl Header include paths

AC_ARG_WITH(bfd-incdir,
  AS_HELP_STRING([--with-bfd-incdir],
    [Location of BFD headers]),,)

AC_ARG_WITH(libiberty-incdir,
  AS_HELP_STRING([--with-libiberty-incdir],
    [Location of libiberty headers]),,)

if test X${with_bfd_incdir} != X; then
    AC_SUBST(CXXFLAGS, "$CXXFLAGS -I\"${with_bfd_incdir}\"")
fi

if test X${with_libiberty_incdir} != X; then
    AC_SUBST(CXXFLAGS, "$CXXFLAGS -I\"${with_libiberty_incdir}\"")
fi

dnl **************************************************************************
dnl Library paths

AC_ARG_WITH(bfd-libdir,
  AS_HELP_STRING([--with-bfd-libdir],
    [Location of BFD libraries]),,)

AC_ARG_WITH(libiberty-libdir,
  AS_HELP_STRING([--with-libiberty-libdir],
    [Location of libiberty libraries]),,)

if test X${with_bfd_libdir} != X; then
    AC_SUBST(LDFLAGS, "$LDFLAGS -L\"${with_bfd_libdir}\"")
fi

if test X${with_libiberty_libdir} != X; then
    AC_SUBST(LDFLAGS, "$LDFLAGS -L\"${with_libiberty_libdir}\"")
fi

dnl **************************************************************************
dnl Add OS-specific libraries

echo "$OS"
if test "x$OS" = "xmingw" ; then
tool_libs="-lbfd -lintl -liberty -lz"
elif test "x$OS" = "xlinux" ; then
tool_libs="-lbfd -liberty -lz -lgettextpo"
else
tool_libs="-lbfd -lintl -liberty -lz -lgettextpo"
fi

AC_SUBST(TOOL_LIBS,$tool_libs)

dnl **************************************************************************
dnl Verify that we can find gmock

AC_ARG_WITH(gmock,
  AS_HELP_STRING([--with-gmock],
    [Location of Google Mock source and object code]),,)

AC_MSG_CHECKING([Google Mock])

if test X${with_gmock} != X; then
dnl Make the paths absolute.
gmock_root="`cd $with_gmock 2> /dev/null; pwd`"

AC_MSG_RESULT([$gmock_root])
AC_SUBST(GMOCK_ROOT,$gmock_root)
else
  AC_MSG_ERROR([Google Mock is required])
fi

dnl **************************************************************************
dnl Verify that we can find KLEE

AC_ARG_WITH(klee_src,
  AS_HELP_STRING([--with-klee-src],
    [Location of KLEE source code]),,)

AC_MSG_CHECKING([KLEE source directory])

if test X${with_klee_src} != X; then
dnl Make the paths absolute.
klee_src_root="`cd $with_klee_src 2> /dev/null; pwd`"

AC_MSG_RESULT([$klee_src_root])
AC_SUBST(KLEE_SRC,$klee_src_root)
else
  AC_MSG_ERROR([KLEE sources are required])
fi

dnl **************************************************************************
dnl Verify that we can find KLEE objects

AC_ARG_WITH(klee_obj,
  AS_HELP_STRING([--with-klee-obj],
    [Location of KLEE source code]),,)

AC_MSG_CHECKING([KLEE build directory])

if test X${with_klee_obj} != X; then
dnl Make the paths absolute.
klee_obj_root="`cd $with_klee_obj 2> /dev/null; pwd`"

AC_MSG_RESULT([$klee_obj_root])
AC_SUBST(KLEE_OBJ,$klee_obj_root)
else
  AC_MSG_ERROR([KLEE libraries are required])
fi

dnl **************************************************************************
dnl Verify that we can find libvmi source

AC_ARG_WITH(libvmi_src,
  AS_HELP_STRING([--with-libvmi-src],
    [Location of VMI Source code]),,)

AC_MSG_CHECKING([libvmi source dir])

dnl Make the paths absolute.
libvmi_src=`cd $with_libvmi_src 2> /dev/null; pwd`

AC_MSG_RESULT([$libvmi_src])
AC_SUBST(LIBVMI_SRC,$libvmi_src)

dnl **************************************************************************
dnl Verify that we can find libvmi binaries

AC_ARG_WITH(libvmi_obj,
  AS_HELP_STRING([--with-libvmi-obj],
    [Location of VMI binaries]),,)

AC_MSG_CHECKING([libvmi binary dir])

dnl Make the paths absolute.
libvmi_obj=`cd $with_libvmi_obj 2> /dev/null; pwd`

AC_MSG_RESULT([$libvmi_obj])
AC_SUBST(LIBVMI_OBJ,$libvmi_obj)

dnl **************************************************************************
dnl Verify that we can find llvm

dnl --with-llvm is a shortcut for setting srcdir and objdir.
AC_ARG_WITH(llvm,
  AS_HELP_STRING([--with-llvm],
    [Location of LLVM Source and Object code]),,)

AC_MSG_CHECKING([llvm source dir])

if test X${with_llvm} != X; then
    dnl Verify that --with-llvm{src,obj} were not given.
    if test X${with_llvmsrc} != X; then
       AC_MSG_ERROR([--with-llvmsrc cannot be specified when using --with-llvm])
    fi
    if test X${with_llvmobj} != X; then
       AC_MSG_ERROR([--with-llvmobj cannot be specified when using --with-llvm])
    fi
    with_llvmsrc=$with_llvm
    with_llvmobj=$with_llvm
fi

dnl If one of with_llvmsrc or with_llvmobj was given, we must have both.
if (test X${with_llvmsrc} != X || test X${with_llvmobj} != X); then
    dnl Verify that with_llvmobj was given as well.
    if test X${with_llvmsrc} = X; then
       AC_MSG_ERROR([--with-llvmsrc must be specified when using --with-llvmobj])
    fi
    if test X${with_llvmobj} = X; then
       AC_MSG_ERROR([--with-llvmobj must be specified when using --with-llvmsrc])
    fi
else
    dnl Otherwise try and use llvm-config to find.
    llvm_version=`llvm-config --version`
    if test X${llvm_version} = X; then
       AC_MSG_ERROR([unable to find llvm, use --with-llvmsrc and --with-llvmobj])
    fi

    with_llvmsrc=`llvm-config --src-root`
    with_llvmobj=`llvm-config --obj-root`
fi

dnl Try to validate directories.
if test ! -f ${with_llvmsrc}/Makefile.rules; then
   AC_MSG_ERROR([invalid llvmsrc directory: ${with_llvmsrc}])
fi
if test ! -f ${with_llvmobj}/Makefile.config; then
   AC_MSG_ERROR([invalid llvmobj directory: ${with_llvmobj}])
fi

dnl Make the paths absolute.
llvm_src=`cd $with_llvmsrc 2> /dev/null; pwd`
llvm_obj=`cd $with_llvmobj 2> /dev/null; pwd`

AC_MSG_RESULT([$llvm_src])

dnl Report obj dir as well.
AC_MSG_CHECKING([llvm obj dir])
AC_MSG_RESULT([$llvm_obj])

AC_SUBST(LLVM_SRC,$llvm_src)
AC_SUBST(LLVM_OBJ,$llvm_obj)

dnl Determine LLVM version.
AC_MSG_CHECKING([llvm package version])
llvm_package_version=`grep PACKAGE_VERSION= $with_llvmsrc/configure | cut -d\' -f 2`
AC_MSG_RESULT([$llvm_package_version])

llvm_version_split=`python -c "import re; print '\t'.join(map(str, re.match('([[0-9]]+)[.]([[0-9]]+)(svn)?', \"$llvm_package_version\").groups()))"`

AC_MSG_CHECKING([llvm version major])
llvm_version_major=`echo "$llvm_version_split" | cut -f 1`
AC_MSG_RESULT([$llvm_version_major])

AC_MSG_CHECKING([llvm version minor])
llvm_version_minor=`echo "$llvm_version_split" | cut -f 2`
AC_MSG_RESULT([$llvm_version_minor])

AC_MSG_CHECKING([llvm is release version])
llvm_version_svn=`echo "$llvm_version_split" | cut -f 3`
if test "$llvm_version_svn" == "svn"; then
  llvm_is_release=0
else
  llvm_is_release=1
fi
AC_MSG_RESULT([$llvm_is_release])

AC_DEFINE_UNQUOTED(LLVM_VERSION_MAJOR, $llvm_version_major, [LLVM major version number])
AC_SUBST(LLVM_VERSION_MAJOR,$llvm_version_major)
AC_DEFINE_UNQUOTED(LLVM_VERSION_MINOR, $llvm_version_minor, [LLVM minor version number])
AC_SUBST(LLVM_VERSION_MINOR,$llvm_version_minor)
AC_DEFINE_UNQUOTED(LLVM_IS_RELEASE, $llvm_is_release, [LLVM version is release (instead of development)])
AC_SUBST(LLVM_IS_RELEASE,$llvm_is_release)

dnl Look for a sufficiently recent version of Perl.
LLVM_PROG_PERL([5.006])
AC_SUBST(PERL)
if test x"$PERL" = xnone; then
  AC_SUBST(HAVE_PERL,0)
  AC_MSG_ERROR([perl is required but was not found, please install it])
else
  AC_SUBST(HAVE_PERL,1)
fi


dnl **************************************************************************
dnl Verify that we can find STP
AC_ARG_WITH(stp,
  AS_HELP_STRING([--with-stp],
    [Location of STP installation directory]),,)

if test X$with_stp = X ; then
  AC_SUBST(ENABLE_EXT_STP,[[0]])
else
  stp_root=`cd $with_stp 2> /dev/null; pwd`

  old_CPPFLAGS="$CPPFLAGS"
  CPPFLAGS="$CPPFLAGS -I$stp_root/include"
  AC_CHECK_HEADER(stp/c_interface.h,, [
         AC_MSG_ERROR([Unable to use stp/c_interface.h header])
  ])
  CPPFLAGS="$old_CPPFLAGS"

  AC_CHECK_LIB(stp, vc_setInterfaceFlags,"true", [
         AC_MSG_ERROR([Unable to link with libstp])
  ], -L$stp_root/lib -L$stp_root/cryptominisat/lib/ -l:libcryptominisat4.a -L$stp_root/cryptominisat/m4ri/ -l:libm4ri.a -L$stp_root/minisat/build/release/lib/ -lminisat)

  STP_CFLAGS="-I$stp_root/include"
  STP_LDFLAGS="-L$stp_root/lib  -lstp -L$stp_root/cryptominisat/lib/ -l:libcryptominisat4.a -L$stp_root/cryptominisat/m4ri/ -l:libm4ri.a -L$stp_root/minisat/build/release/lib/ -lminisat"
  LDFLAGS="$LDFLAGS $STP_LDFLAGS"
  LIBS+=" $STP_LDFLAGS"
  AC_DEFINE(HAVE_EXT_STP, 1, [Using external STP])
  AC_SUBST(STP_CFLAGS)
  AC_SUBST(STP_LDFLAGS)
  AC_SUBST(ENABLE_EXT_STP,[[1]])
  AC_SUBST(STP_ROOT,$stp_root)
fi


dnl **************************************************************************
dnl Checks for header files.

dnl NOTE: This is mostly just to force autoconf to make CFLAGS defines
dnl for us.
AC_LANG_PUSH([C])

AC_CHECK_HEADERS([sys/acl.h])

AC_LANG_POP([C])

AC_CHECK_HEADERS([selinux/selinux.h],
        AC_SUBST(HAVE_SELINUX, 1),
        AC_SUBST(HAVE_SELINUX, 0))


# Translate the various configuration directories and other basic
# information into substitutions that will end up in Makefile.config.in
# that these configured values can be used by the makefiles
if test "${prefix}" = "NONE" ; then
      prefix="/usr/local"
fi
eval testsuite_PREFIX="${prefix}";
testsuite_CONFIGTIME=`date`
AC_SUBST(testsuite_PREFIX)
AC_SUBST(testsuite_CONFIGTIME)

dnl **************************************************************************
dnl * Create the output files
dnl **************************************************************************

dnl This must be last
AC_OUTPUT
