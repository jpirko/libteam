MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -fvisibility=hidden -ffunction-sections -fdata-sections
AM_LDFLAGS = -Wl,--gc-sections -Wl,--as-needed

lib_LTLIBRARIES = libteamdctl.la
libteamdctl_la_SOURCES = libteamdctl.c cli_usock.c cli_dbus.c cli_zmq.c
libteamdctl_la_CFLAGS= $(AM_CFLAGS) $(JANSSON_CFLAGS) $(DBUS_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
libteamdctl_la_LIBADD= $(JANSSON_LIBS) $(DBUS_LIBS) $(ZMQ_LIBS) $(LIBDAEMON_LIBS)
libteamdctl_la_LDFLAGS = $(AM_LDFLAGS) -version-info @LIBTEAMDCTL_CURRENT@:@LIBTEAMDCTL_REVISION@:@LIBTEAMDCTL_AGE@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libteamdctl.pc

EXTRA_DIST = teamdctl_private.h
