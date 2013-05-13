MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

AM_CPPFLAGS='-DLOCALSTATEDIR="$(localstatedir)"'

teamd_CFLAGS= $(LIBDAEMON_CFLAGS) $(JANSSON_CFLAGS) $(DBUS_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE

teamd_LDADD = $(top_builddir)/libteam/libteam.la $(LIBDAEMON_LIBS) $(JANSSON_LIBS) $(DBUS_LIBS)

bin_PROGRAMS=teamd
teamd_SOURCES=teamd.c teamd_common.c teamd_json.c teamd_config.c teamd_state.c \
	      teamd_events.c teamd_per_port.c teamd_option_watch.c \
	      teamd_ifinfo_watch.c teamd_link_watch.c \
	      teamd_ctl_methods.c teamd_dbus.c teamd_usock.c \
	      teamd_bpf_chef.c teamd_hash_func.c teamd_balancer.c \
	      teamd_runner_basic_ones.c teamd_runner_activebackup.c \
	      teamd_runner_loadbalance.c teamd_runner_lacp.c

EXTRA_DIST = example_configs dbus redhat

noinst_HEADERS = teamd.h teamd_bpf_chef.h teamd_ctl_methods.h teamd_json.h \
		 teamd_dbus.h teamd_usock.h teamd_dbus_common.h \
		 teamd_usock_common.h teamd_config.h teamd_state.h
