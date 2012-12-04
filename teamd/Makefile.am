MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

AM_CPPFLAGS='-DLOCALSTATEDIR="$(localstatedir)"'

teamd_CFLAGS= $(LIBDAEMON_CFLAGS) $(JANSSON_CFLAGS) $(DBUS_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE
teamdctl_CFLAGS= $(JANSSON_CFLAGS) $(DBUS_CFLAGS) -I${top_srcdir}/include -D_GNU_SOURCE

teamd_LDADD = $(top_builddir)/lib/libteam.la $(LIBDAEMON_LIBS) $(JANSSON_LIBS) $(DBUS_LIBS)
teamdctl_LDADD = $(top_builddir)/lib/libteam.la $(JANSSON_LIBS) $(DBUS_LIBS)

bin_PROGRAMS=teamd teamdctl
teamd_SOURCES=teamd.c teamd_common.c teamd_events.c \
	      teamd_per_port.c teamd_option_watch.c teamd_state_json.c \
	      teamd_ctl_methods.c teamd_dbus.c teamd_usock.c \
	      teamd_link_watch.c \
	      teamd_bpf_chef.c teamd_hash_func.c teamd_balancer.c \
	      teamd_runner_basic_ones.c teamd_runner_activebackup.c \
	      teamd_runner_loadbalance.c teamd_runner_lacp.c
teamdctl_SOURCES=teamdctl.c

EXTRA_DIST = example_configs dbus redhat

noinst_HEADERS = teamd.h teamd_bpf_chef.h teamd_ctl_methods.h teamd_dbus.h
