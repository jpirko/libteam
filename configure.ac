#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([libteam], [1.31], [jiri@resnulli.us])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES(yes)], [])
AM_PROG_AR

# Here are a set of rules to help you update your library version information:
# 1. Start with version information of ‘0:0:0’ for each libtool library.
# 2. Update the version information only immediately before a public release
#    of your software. More frequent updates are unnecessary, and only guarantee
#    that the current interface number gets larger faster.
# 3. If the library source code has changed at all since the last update,
#    then increment revision (‘c:r:a’ becomes ‘c:r+1:a’).
# 4. If any interfaces have been added, removed, or changed since the last
#    update, increment current, and set revision to 0.
# 5. If any interfaces have been added since the last public release, then
#    increment age.
# 6. If any interfaces have been removed or changed since the last public
#    release, then set age to 0.

AC_SUBST(LIBTEAM_CURRENT, 11)
AC_SUBST(LIBTEAM_REVISION, 1)
AC_SUBST(LIBTEAM_AGE, 6)

AC_SUBST(LIBTEAMDCTL_CURRENT, 1)
AC_SUBST(LIBTEAMDCTL_REVISION, 5)
AC_SUBST(LIBTEAMDCTL_AGE, 1)

CFLAGS="$CFLAGS -Wall"

# Checks for programs.
AC_PROG_CC
LT_INIT

PKG_CHECK_MODULES([LIBNL], [libnl-3.0 libnl-genl-3.0 libnl-route-3.0 libnl-cli-3.0])
	TMP_CFLAGS="$CFLAGS"
	TMP_LDFLAGS="$LDFLAGS"
	TMP_LIBS="$LIBS"
	CFLAGS="$CPPFLAGS $LIBNL_CFLAGS"
	LDFLAGS=""
	LIBS="$LIBS $LIBNL_LIBS"
	AC_CHECK_LIB([nl-route-3], [rtnl_link_get_phys_port_id],
		     AC_DEFINE(HAVE_RTNL_LINK_GET_PHYS_ID, [1], [Define to 1 if you have rtnl_link_get_phys_port_id function.]))
	AC_CHECK_LIB([nl-route-3], [rtnl_link_set_carrier],
		     AC_DEFINE(HAVE_RTNL_LINK_SET_CARRIER, [1], [Define to 1 if you have rtnl_link_set_carrier.]))
	AC_CHECK_LIB([nl-route-3], [rtnl_link_get_carrier],
		     AC_DEFINE(HAVE_RTNL_LINK_GET_CARRIER, [1], [Define to 1 if you have rtnl_link_get_carrier.]))
	CFLAGS="$TMP_CFLAGS"
	LDFLAGS="$TMP_LDFLAGS"
	LIBS="$TMP_LIBS"

PKG_CHECK_MODULES([LIBDAEMON], [libdaemon])
PKG_CHECK_MODULES([JANSSON], [jansson])

# Checks for header files.
AC_CHECK_HEADERS([stdint.h stdlib.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE

# Checks for library functions.
AC_FUNC_MALLOC

AC_ARG_ENABLE([logging],
	AS_HELP_STRING([--disable-logging], [disable system logging @<:@default=enabled@:>@]),
	[], enable_logging=yes)
AS_IF([test "x$enable_logging" = "xyes"], [
	AC_DEFINE(ENABLE_LOGGING, [1], [System logging.])
])

AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug], [enable debug messages @<:@default=disabled@:>@]),
	[], [enable_debug=no])
AS_IF([test "x$enable_debug" = "xyes"], [
	AC_DEFINE(ENABLE_DEBUG, [1], [Debug messages.])
])

user=root
dbus_policy_template="teamd/teamd.conf.in"
dbus_policy_file="teamd/dbus/teamd.conf"
AC_ARG_WITH([user],
	[AS_HELP_STRING([--with-user@<:@=username@:>@], [Set default daemon user @<:@default=root@:>@])],
	[case "$withval" in
		root|yes|no|"") ;;
		*) user="$withval"
		   sed -e "s|[@]teamd_user[@]|$user|g" \
			< $dbus_policy_template > $dbus_policy_file ;;
	esac]
)
AC_DEFINE_UNQUOTED(TEAMD_USER, "${user}", [TEAMD USER.])

group=root
AC_ARG_WITH([group],
	[AS_HELP_STRING([--with-group@<:@=groupname@:>@], [Specify the system group @<:@default=root@:>@])],
	[case "$withval" in
		yes|no|"") ;;
		*) group="$withval" ;;
	esac]
)
AC_DEFINE_UNQUOTED(TEAMD_GROUP, "${group}", [TEAMD GROUP.])

AM_CONDITIONAL([LIBCAP], [test "x$user" != "xroot" -o "x$group" != "xroot"])
AM_COND_IF([LIBCAP],
	[AC_CHECK_LIB([cap], [cap_init],,
		AC_MSG_ERROR([*** Non-root daemon support requested but libcap-devel library not found]))])

have_dbus=no
AC_ARG_ENABLE([dbus],
	AS_HELP_STRING([--disable-dbus], [disable D-Bus API @<:@default=enabled@:>@]))
	if test "x$enable_dbus" != "xno"; then
		PKG_CHECK_MODULES([DBUS], [dbus-1],
				  [AC_DEFINE(ENABLE_DBUS, [1], [D-Bus API.]) have_dbus=yes],
				  have_dbus=no)
	if test "x$have_dbus$enable_dbus" = xnoyes; then
		AC_MSG_ERROR([*** D-Bus support requested but libraries not found])
	fi
fi

have_zmq=no
AC_ARG_ENABLE([zmq],
	AS_HELP_STRING([--disable-zmq], [disable ZeroMQ API @<:@default=enabled@:>@]))
	if test "x$enable_zmq" != "xno"; then
		PKG_CHECK_MODULES([ZMQ], [libzmq >= 3.2.0],
				  [AC_DEFINE(ENABLE_ZMQ, [1], [ZMQ API.]) have_zmq=yes],
				  have_zmq=no)
	if test "x$have_zmq$enable_zmq" = xnoyes; then
		AC_MSG_ERROR([*** ZeroMQ support requested but libraries not found])
	fi
fi

AC_ARG_WITH([run-dir],
	[AS_HELP_STRING([--with-run-dir@<:@=DIR@:>@], [Teamd run time directory @<:@default=${localstatedir}@:>@])],
	[case "$withval" in
		yes|no|"") ;;
		*) AC_DEFINE_UNQUOTED(TEAMD_RUN_DIR, "${withval}/", [TEAMD RUN DIR.]) ;;
	esac]
)

AC_CHECK_PROGS([DOXYGEN], [doxygen])
if test -z "$DOXYGEN";
	then AC_MSG_WARN([Doxygen not found - continuing without Doxygen support])
fi

AM_CONDITIONAL([HAVE_DOXYGEN],
[test -n "$DOXYGEN"])AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([doc/Doxyfile])])

AC_CONFIG_FILES([Makefile
include/Makefile \
libteam/Makefile \
libteamdctl/Makefile \
utils/Makefile \
teamd/Makefile \
man/Makefile \
libteam/libteam.pc \
libteamdctl/libteamdctl.pc \
binding/Makefile \
binding/python/Makefile \
binding/python/setup.py \
binding/python/team/Makefile \
binding/python/team/capi.i \
examples/Makefile \
doc/Makefile])
AC_OUTPUT
