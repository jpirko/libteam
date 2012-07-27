MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libteam.la
libteam_la_SOURCES = libteam.c ports.c options.c ifinfo.c
libteam_la_CFLAGS= $(LIBNL_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
libteam_la_LIBADD= $(LIBNL_LIBS)
libteam_la_LDFLAGS = -version-info @LIBTEAM_CURRENT@:@LIBTEAM_REVISION@:@LIBTEAM_AGE@

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libteam.pc

EXTRA_DIST = team_private.h nl_updates.h
