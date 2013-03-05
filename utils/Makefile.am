MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamnl_LDADD = $(top_builddir)/libteam/libteam.la
teamdctlx_LDADD = $(top_builddir)/libteamdctl/libteamdctl.la

bin_PROGRAMS=teamnl teamdctlx
teamnl_SOURCES=teamnl.c
teamdctlx_SOURCES=teamdctlx.c
