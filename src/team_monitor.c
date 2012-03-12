/*
 *   team_monitor.c - Network team device dummy event monitor
 *   Copyright (C) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public
 *   License as published by the Free Software Foundation; either
 *   version 2.1 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with this library; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#include <stdio.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <team.h>

#define APPNAME "team_monitor"

static char *get_port_name(struct team_handle *th, uint32_t ifindex)
{
	static char ifname[32];

	return team_ifindex2ifname(th, ifindex, ifname, sizeof(ifname));
}

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

static int port_change_handler_func(struct team_handle *th, void *arg,
				    team_change_type_mask_t type_mask)
{
	struct team_port *port;

	printf("------------------\nport change\n\tport list:\n");
	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		printf("\tifname %s, linkup %d, changed %d, speed %d, "
		       "duplex %d\n",
		       get_port_name(th, ifindex),
		       team_is_port_link_up(port),
		       team_is_port_changed(port),
		       team_get_port_speed(port),
		       team_get_port_duplex(port));
	}
	return 0;
}

static struct team_change_handler port_change_handler = {
	.func		= port_change_handler_func,
	.type_mask	= TEAM_PORT_CHANGE,
};

static int option_change_handler_func(struct team_handle *th, void *arg,
				      team_change_type_mask_t type_mask)
{
	struct team_option *option;

	printf("------------------\noption change\n\toption list:\n");
	team_for_each_option(option, th) {
		printf("\topt_name: %s, changed %d\n",
		       team_get_option_name(option),
		       team_is_option_changed(option));
	}
	return 0;
}

static struct team_change_handler option_change_handler = {
	.func		= option_change_handler_func,
	.type_mask	= TEAM_OPTION_CHANGE,
};

int main(int argc, char *argv[])
{
	struct team_handle *th;
	int err;
	char *ifname;
	uint32_t ifindex;

	if (argc < 2) {
		fprintf(stderr, "Usage: %s TEAMDEV\n", APPNAME);
		return 1;
	}

	th = team_alloc();
	if (!th) {
		fprintf(stderr, "team alloc failed.\n");
		return 1;
	}

	ifname = argv[1];
	ifindex = team_ifname2ifindex(th, ifname);
	if (!ifindex) {
		fprintf(stderr, "Netdevice %s not found.\n", ifname);
		return 1;
	}

	err = team_init(th, ifindex);
	if (err) {
		fprintf(stderr, "team init failed\n");
		err = 1;
		goto err_team_init;
	}

	err = team_change_handler_register(th, &port_change_handler);
	if (err) {
		fprintf(stderr, "port change handler register failed\n");
		err = 1;
		goto err_port_change_register;
	}

	err = team_change_handler_register(th, &option_change_handler);
	if (err) {
		fprintf(stderr, "option change handler register failed\n");
		err = 1;
		goto err_option_change_register;
	}

	signal(SIGINT, sigint_handler);

	do_main_loop(th);

	team_change_handler_unregister(th, &option_change_handler);
err_option_change_register:
	team_change_handler_unregister(th, &port_change_handler);
err_port_change_register:
err_team_init:
	team_free(th);

	return err;
}
