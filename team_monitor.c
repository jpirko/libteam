/*
 * team_monitor.c - Network team device dummy event monitor
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <team.h>

#define APPNAME "team_monitor"

static int die = 0;

static void sigint_handler(int signum)
{
	die = 1;
}

static void do_main_loop(struct team_handle *th)
{
	fd_set rfds;
	fd_set rfds_tmp;
	int fdmax;
	int ret;
	int tfd = team_get_event_fd(th);
	int i;

	FD_ZERO(&rfds);
	FD_SET(tfd, &rfds);

	fdmax = tfd + 1;

	while (1) {
		rfds_tmp = rfds;
		ret = select(fdmax, &rfds_tmp, NULL, NULL, NULL);
		if (die)
			break;
		if (ret == -1) {
			perror("select()");
		}
		for (i = 0; i < fdmax; i++) {
			if (FD_ISSET(i, &rfds_tmp)) {
				if (i == tfd)
					team_process_event(th);
			}
		}
	}

}

static void port_change_handler_func(struct team_handle *th, void *arg)
{
	struct team_port *port;

	printf("------------------\nport change\n\tport list:\n");
	team_for_each_port(port, th) {
		printf("\tifindex %d, linkup %d, changed %d, speed %d, "
		       "duplex %d\n", port->ifindex, port->linkup,
		       port->changed, port->speed, port->duplex);
	}
}

static struct team_change_handler port_change_handler = {
	.func		= port_change_handler_func,
	.type		= TEAM_PORT_CHANGE,
};

static void option_change_handler_func(struct team_handle *th, void *arg)
{
	struct team_option *option;

	printf("------------------\noption change\n\toption list:\n");
	team_for_each_option(option, th) {
		printf("\topt_name: %s, changed %d\n",
		       option->name, option->changed);
	}
}

static struct team_change_handler option_change_handler = {
	.func		= option_change_handler_func,
	.type		= TEAM_OPTION_CHANGE,
};

int main(int argc, char *argv[])
{
	struct team_handle *th;
	int err;
	char *mode_name;
	struct team_mode *mode;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s TEAMDEV\n", APPNAME);
		return 1;
	}

	th = team_alloc();
	if (!th) {
		fprintf(stderr, "team alloc failed.\n");
		return 1;
	}

	err = team_init(th, argv[1]);
	if (err) {
		fprintf(stderr, "team init failed\n");
		err = 1;
		goto out;
	}

	team_change_handler_register(th, &port_change_handler);
	team_change_handler_register(th, &option_change_handler);

	signal(SIGINT, sigint_handler);

	do_main_loop(th);

	team_change_handler_unregister(th, &option_change_handler);
	team_change_handler_unregister(th, &port_change_handler);
out:
	team_free(th);

	return err;
}
