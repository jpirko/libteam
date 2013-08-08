/*
 *   team_manual_control.c - Network team device dummy manual control
 *   Copyright (C) 2011-2013 Jiri Pirko <jiri@resnulli.us>
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
#include <stdlib.h>
#include <string.h>
#include <team.h>

#define APPNAME "team_manual_control"

static void usage(void)
{
	fprintf(stderr,
"Usage: " APPNAME " help\n"
"       " APPNAME " TEAMDEV dumplist { ports }\n"
"       " APPNAME " TEAMDEV get { mode | activeport }\n"
"       " APPNAME " TEAMDEV set { mode | activeport } value\n");
	exit(1);
}

static char *get_port_name(struct team_handle *th, uint32_t ifindex)
{
	static char ifname[32];

	return team_ifindex2ifname(th, ifindex, ifname, sizeof(ifname));
}

static int cmd_dumplist(struct team_handle *th, int argc, char **argv)
{
	char *opt;

	if (argc == 1) {
		fprintf(stderr, "List name not specified\n");
		usage();
	}

	opt = argv[1];

	if (strcmp(opt, "ports") == 0) {
		struct team_port *port;

		team_for_each_port(port, th) {
			uint32_t ifindex = team_get_port_ifindex(port);

			printf("ifname %s, linkup %d, changed %d, speed %d, "
			       "duplex %d\n",
			       get_port_name(th, ifindex),
			       team_is_port_link_up(port),
			       team_is_port_changed(port),
			       team_get_port_speed(port),
			       team_get_port_duplex(port));
		}
	} else {
		fprintf(stderr, "Unknown option name \"%s\"\n", opt);
		usage();
	}
	return 0;
}

static int cmd_get(struct team_handle *th, int argc, char **argv)
{
	int err;
	char *opt;

	if (argc == 1) {
		fprintf(stderr, "Option name not specified\n");
		usage();
	}

	opt = argv[1];
	if (strcmp(opt, "mode") == 0) {
		char *mode_name;

		err = team_get_mode_name(th, &mode_name);
		if (err) {
			fprintf(stderr, "Get mode failed, %d\n", err);
			return 1;
		}
		printf("%s\n", mode_name);
	} else if (strcmp(opt, "activeport") == 0) {
		uint32_t ifindex;

		err = team_get_active_port(th, &ifindex);
		if (err) {
			fprintf(stderr, "Get active port failed, %d\n", err);
			return 1;
		}
		printf("%s\n", ifindex ? get_port_name(th, ifindex) : "NONE");
	} else {
		fprintf(stderr, "Unknown option name \"%s\"\n", opt);
		usage();
	}
	return 0;
}

static int cmd_set(struct team_handle *th, int argc, char **argv)
{
	int err;
	char *opt;
	char *val;

	if (argc == 1) {
		fprintf(stderr, "Option name not specified\n");
		usage();
	}
	opt = argv[1];
	argc--;	argv++;
	val = argv[1];
	if (argc == 1) {
		fprintf(stderr, "Option value to be set not specified\n");
		usage();
	}

	if (strcmp(opt, "mode") == 0) {
		err = team_set_mode_name(th, val);
		if (err) {
			fprintf(stderr, "Set mode failed, %d\n", err);
			return 1;
		}
	} else if (strcmp(opt, "activeport") == 0) {
		uint32_t ifindex;

		ifindex = team_ifname2ifindex(th, val);
		if (!ifindex) {
			fprintf(stderr, "Netdevice %s not found.\n", val);
			usage();
		}

		err = team_set_active_port(th, ifindex);
		if (err) {
			fprintf(stderr, "Set active port failed, %d\n", err);
			return 1;
		}
	} else {
		fprintf(stderr, "Unknown option name \"%s\"\n", opt);
		usage();
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct team_handle *th;
	int err;
	char *ifname = NULL;
	uint32_t ifindex;
	char *cmd = NULL;

	while (argc > 1) {
		char *opt = argv[1];

		argc--;	argv++;
		if (strcmp(opt, "help") == 0) {
			usage();
		} else if (!ifname) {
			ifname = opt;
		} else {
			cmd = opt;
			break;
		}
	}

	if (!ifname) {
		fprintf(stderr, "Team device name not specified.\n");
		usage();
	}

	if (!cmd) {
		fprintf(stderr, "Command not specified.\n");
		usage();
	}

	th = team_alloc();
	if (!th) {
		fprintf(stderr, "Team alloc failed.\n");
		return 1;
	}

	ifindex = team_ifname2ifindex(th, ifname);
	if (!ifindex) {
		fprintf(stderr, "Netdevice %s not found.\n", ifname);
		return 1;
	}

	err = team_init(th, ifindex);
	if (err) {
		fprintf(stderr, "Team init failed.\n");
		return 1;
	}

	if (strcmp(cmd, "dumplist") == 0) {
		err = cmd_dumplist(th, argc, argv);
	} else if (strcmp(cmd, "set") == 0) {
		err = cmd_set(th, argc, argv);
	} else if (strcmp(cmd, "get") == 0) {
		err = cmd_get(th, argc, argv);
	} else {
		fprintf(stderr, "Unknown command \"%s\".\n", cmd);
		usage();
	}

	team_free(th);
	return 0;
}
