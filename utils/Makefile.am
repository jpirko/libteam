MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamnl_LDADD = $(top_builddir)/libteam/libteam.la
teamdctl_LDADD = $(top_builddir)/libteamdctl/libteamdctl.la

bin_PROGRAMS=teamnl teamdctl
teamnl_SOURCES=teamnl.c
teamdctl_SOURCES=teamdctl.c

bin_SCRIPTS = bond2team
EXTRA_DIST = bond2team
