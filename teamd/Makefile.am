MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamd_CFLAGS= $(LIBDAEMON_CFLAGS) $(LIBJSON_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE

teamd_LDADD = $(top_builddir)/lib/libteam.la $(LIBDAEMON_LIBS) $(LIBJSON_LIBS)

bin_PROGRAMS=teamd
teamd_SOURCES=teamd.c teamd_json_extras.c teamd_runner_basic_ones.c teamd_runner_activebackup.c
