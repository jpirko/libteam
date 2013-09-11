MAINTAINERCLEANFILES = Makefile.in

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I${top_srcdir}/include

LDADD = $(top_builddir)/libteam/libteam.la

noinst_PROGRAMS=team_manual_control team_monitor
team_manual_control_SOURCES=team_manual_control.c
team_monitor_SOURCES=team_monitor.c

EXTRA_DIST = python
