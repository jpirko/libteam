MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -fvisibility=hidden -ffunction-sections -fdata-sections
AM_LDFLAGS = -Wl,--gc-sections -Wl,--as-needed

lib_LTLIBRARIES = libteam.la
libteam_la_SOURCES = libteam.c ports.c options.c ifinfo.c stringify.c
libteam_la_CFLAGS= $(AM_CFLAGS) $(LIBNL_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
libteam_la_LIBADD= $(LIBNL_LIBS)
libteam_la_LDFLAGS = $(AM_LDFLAGS) -version-info @LIBTEAM_CURRENT@:@LIBTEAM_REVISION@:@LIBTEAM_AGE@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libteam.pc

EXTRA_DIST = team_private.h nl_updates.h
