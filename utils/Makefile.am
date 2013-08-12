MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamnl_CFLAGS= -I${top_srcdir}/include -D_GNU_SOURCE
teamnl_LDADD = $(top_builddir)/libteam/libteam.la
teamdctl_CFLAGS= $(JANSSON_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
teamdctl_LDADD = $(top_builddir)/libteamdctl/libteamdctl.la $(JANSSON_LIBS)

bin_PROGRAMS=teamnl teamdctl
teamnl_SOURCES=teamnl.c
teamdctl_SOURCES=teamdctl.c

bin_SCRIPTS = bond2team
EXTRA_DIST = bond2team
