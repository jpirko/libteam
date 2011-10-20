/*
 * team_manual_control.c - Network team device dummy manual control
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#include <stdio.h>
#include <stdlib.h>
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

static char *get_port_name(uint32_t ifindex)
{
	static char ifname[32];

	return team_ifindex2ifname(ifindex, ifname, sizeof(ifname));
}

static int cmd_dumplist(struct team_handle *th, int argc, char **argv)
{
	int err;
	char *opt;

	if (argc == 1) {
		fprintf(stderr, "List name not specified\n");
		usage();
	}

	opt = argv[1];

	if (strcmp(opt, "ports") == 0) {
		struct team_port *port;

		team_for_each_port(port, th) {
			printf("ifname %s, linkup %d, changed %d, speed %d, "
			       "duplex %d\n", get_port_name(port->ifindex),
			       port->linkup, port->changed, port->speed,
			       port->duplex);
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
		printf("%s\n", ifindex ? get_port_name(ifindex) : "NONE");
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

		ifindex = team_ifname2ifindex(val);
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

	ifindex = team_ifname2ifindex(ifname);
	if (!ifindex) {
		fprintf(stderr, "Netdevice %s not found.\n", ifname);
		return 1;
	}

	th = team_alloc();
	if (!th) {
		fprintf(stderr, "Team alloc failed.\n");
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

out:
	team_free(th);
}
