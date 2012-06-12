MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

teamd_CFLAGS= $(LIBDAEMON_CFLAGS) $(JANSSON_CFLAGS) $(DBUS_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE

teamd_LDADD = $(top_builddir)/lib/libteam.la $(LIBDAEMON_LIBS) $(JANSSON_LIBS) $(DBUS_LIBS)

bin_PROGRAMS=teamd
teamd_SOURCES=teamd.c teamd_common.c teamd_per_port.c teamd_dbus.c \
	      teamd_link_watch.c teamd_bpf_chef.c teamd_hash_func.c \
	      teamd_runner_basic_ones.c teamd_runner_activebackup.c \
	      teamd_runner_loadbalance.c teamd_runner_lacp.c \
	      teamd_balancer.c

EXTRA_DIST = example_configs

noinst_HEADERS = teamd.h teamd_bpf_chef.h
