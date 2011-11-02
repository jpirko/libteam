#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([libteam], [0.1], [jpirko@redhat.com])
AC_CONFIG_MACRO_DIR([m4])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
#m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)], [])

# Checks for programs.
AC_PROG_CC
LT_INIT

PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0 libnl-cli-3.0])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])
AC_CHECK_HEADERS([linux/if_team.h], [], [AC_MSG_FAILURE( \
[Kernel not support teaming or kernel-headers is not installed.])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_CONFIG_FILES([Makefile
include/Makefile \
lib/Makefile \
src/Makefile \
lib/libteam.pc \
binding/Makefile \
binding/python/Makefile \
binding/python/setup.py \
binding/python/team/Makefile \
binding/python/team/capi.i])
AC_OUTPUT
