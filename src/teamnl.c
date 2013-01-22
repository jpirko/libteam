/*
 *   teamnl.c - Team device Netlink tool
 *   Copyright (C) 2012 Jiri Pirko <jpirko@redhat.com>
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
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>
#include <team.h>

#include <private/misc.h>

#define CMD_PARAM_MAX_CNT 8

struct cmd_ctx {
	int argc;
	char **argv;
	char *port_devname_arg;
	char *array_index_arg;
	bool port_ifindex_present;
	uint32_t port_ifindex;
	bool array_index_present;
	uint32_t array_index;
};

typedef int (*run_cmd_t)(char *cmd_name, struct team_handle *th,
			 struct cmd_ctx *cmd_ctx);

struct cmd_type {
	char *name;
	char *params[CMD_PARAM_MAX_CNT];
	run_cmd_t run_cmd;
};

static int run_cmd_ports(char *cmd_name, struct team_handle *th,
			 struct cmd_ctx *cmd_ctx)
{
	struct team_port *port;
	char buf[120];
	bool trunc;

	team_for_each_port(port, th) {
		trunc = team_port_str(port, buf, sizeof(buf));
		printf("%s %s\n", buf, trunc ? "<trunc>" : "");
	}
	return 0;
}

static int run_cmd_options(char *cmd_name, struct team_handle *th,
			   struct cmd_ctx *cmd_ctx)
{
	struct team_option *option;
	char buf[120];
	bool trunc;

	team_for_each_option(option, th) {
		trunc = team_option_str(th, option, buf, sizeof(buf));
		printf("%s %s\n", buf, trunc ? "<trunc>" : "");
	}
	return 0;
}

static struct team_option *__find_option(struct team_handle *th, char *opt_name,
					 struct cmd_ctx *cmd_ctx)
{
	if (cmd_ctx->array_index_present && cmd_ctx->port_ifindex_present)
		return team_get_option(th, "npa", opt_name,
				       cmd_ctx->port_ifindex,
				       cmd_ctx->array_index);
	else if (cmd_ctx->array_index_present)
		return team_get_option(th, "na", opt_name,
				       cmd_ctx->array_index);
	else if (cmd_ctx->port_ifindex_present)
		return team_get_option(th, "np", opt_name,
				       cmd_ctx->port_ifindex);
	else
		return team_get_option(th, "n", opt_name);
}

#define BUFSIZSTEP 1024

static int run_cmd_getoption(char *cmd_name, struct team_handle *th,
			     struct cmd_ctx *cmd_ctx)
{
	struct team_option *option;
	char *buf = NULL;
	size_t bufsiz = 0;
	bool trunc;

	if (cmd_ctx->argc < 1) {
		fprintf(stderr, "%s: Option name as a command line parameter expected.\n",
			cmd_name);
		return -EINVAL;
	}
	option = __find_option(th, cmd_ctx->argv[0], cmd_ctx);
	if (!option)
		return -ENOENT;

	do {
		bufsiz += BUFSIZSTEP;
		buf = realloc(buf, bufsiz);
		if (!buf)
			return -ENOMEM;
		trunc = team_option_value_str(option, buf, bufsiz);
	} while(trunc);

	printf("%s\n", buf);
	return 0;
}

static int run_cmd_setoption(char *cmd_name, struct team_handle *th,
			     struct cmd_ctx *cmd_ctx)
{
	struct team_option *option;

	if (cmd_ctx->argc < 1) {
		fprintf(stderr, "%s: Option name as a command line parameter expected.\n",
			cmd_name);
		return -EINVAL;
	}
	if (cmd_ctx->argc < 2) {
		fprintf(stderr, "%s: Option value as a command line parameter expected.\n",
			cmd_name);
		return -EINVAL;
	}
	option = __find_option(th, cmd_ctx->argv[0], cmd_ctx);
	if (!option)
		return -ENOENT;

	return team_set_option_value_from_string(th, option, cmd_ctx->argv[1]);
}

static struct cmd_type cmd_types[] = {
	{
		.name = "ports",
		.params = { NULL },
		.run_cmd = run_cmd_ports,
	},
	{
		.name = "options",
		.params = { NULL },
		.run_cmd = run_cmd_options,
	},
	{
		.name = "getoption",
		.params = { "OPT_NAME", NULL },
		.run_cmd = run_cmd_getoption,
	},
	{
		.name = "setoption",
		.params = { "OPT_NAME", "OPT_VALUE", NULL },
		.run_cmd = run_cmd_setoption,
	},
};
#define CMD_TYPE_COUNT ARRAY_SIZE(cmd_types)

static int process_port_devname_arg(struct team_handle *th,
				    struct cmd_ctx *cmd_ctx)
{
	uint32_t port_ifindex;
	struct team_port *port;

	if (!cmd_ctx->port_devname_arg)
		return 0;
	port_ifindex = team_ifname2ifindex(th, cmd_ctx->port_devname_arg);
	if (!port_ifindex) {
		fprintf(stderr, "Netdevice \"%s\" not found.\n",
			cmd_ctx->port_devname_arg);
		return -ENODEV;
	}
	team_for_each_port(port, th) {
		if (port_ifindex == team_get_port_ifindex(port)) {
			cmd_ctx->port_ifindex_present = true;
			cmd_ctx->port_ifindex = port_ifindex;
			return 0;
		}
	}
	fprintf(stderr, "Netdevice \"%s\" is not port of this team.\n",
			cmd_ctx->port_devname_arg);
	return -ENODEV;
}

static int process_array_index_arg(struct team_handle *th,
				   struct cmd_ctx *cmd_ctx)
{
	uint32_t array_index;
	unsigned long int tmp;
	char *endptr;

	if (!cmd_ctx->array_index_arg)
		return 0;

	tmp = strtoul(cmd_ctx->array_index_arg, &endptr, 10);
	if (tmp == ULONG_MAX) {
		fprintf(stderr, "Failed to parse array index.\n");
		return -errno;
	}
	if (strlen(endptr) != 0) {
		fprintf(stderr, "Failed to parse array index.\n");
		return -EINVAL;
	}
	array_index = tmp;
	if (tmp != array_index) {
		fprintf(stderr, "Array index too big.\n");
		return -ERANGE;
	}
	cmd_ctx->array_index_present = true;
	cmd_ctx->array_index = array_index;
	return 0;
}

static int process_args(struct team_handle *th, struct cmd_ctx *cmd_ctx)
{
	int err;

	err = process_port_devname_arg(th, cmd_ctx);
	if (err)
		return err;
	return process_array_index_arg(th, cmd_ctx);
}

static int call_cmd(char *team_devname, char *cmd_name,
		    struct cmd_ctx *cmd_ctx, run_cmd_t run_cmd)
{
	struct team_handle *th;
	uint32_t ifindex;
	int err;

	th = team_alloc();
	if (!th) {
		fprintf(stderr, "Team alloc failed.\n");
		return -ENOMEM;
	}

	ifindex = team_ifname2ifindex(th, team_devname);
	if (!ifindex) {
		fprintf(stderr, "Netdevice \"%s\" not found.\n", team_devname);
		err = -ENODEV;
		goto team_free;
	}

	err = team_init(th, ifindex);
	if (err) {
		fprintf(stderr, "Team init failed.\n");
		goto team_free;
	}

	err = process_args(th, cmd_ctx);
	if (err)
		goto team_free;

	err = run_cmd(cmd_name, th, cmd_ctx);

team_free:
	team_free(th);
	return err;
}

static void print_help(const char *argv0) {
	int i, j;

	printf(
            "%s [options] teamdevname command [command args]\n"
            "\t-h --help                Show this help\n",
            argv0);
	printf("Commands:\n");
	for (i = 0; i < CMD_TYPE_COUNT; i++) {
		printf("\t%s", cmd_types[i].name);
		for (j = 0; cmd_types[i].params[j]; j++)
			printf(" %s", cmd_types[i].params[j]);
		printf("\n");
	}
}

int main(int argc, char **argv)
{
	char *argv0 = argv[0];
	char *team_devname;
	char *cmd_name;
	struct cmd_ctx cmd_ctx;
	static const struct option long_options[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ "port_name",		required_argument,	NULL, 'p' },
		{ "array_index",	required_argument,	NULL, 'a' },
		{ NULL, 0, NULL, 0 }
	};
	int opt;
	int err;
	int i;
	int res = EXIT_FAILURE;

	memset(&cmd_ctx, 0, sizeof(cmd_ctx));

	while ((opt = getopt_long(argc, argv, "hp:a:",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			print_help(argv0);
			return EXIT_SUCCESS;
		case 'p':
			free(cmd_ctx.port_devname_arg);
			cmd_ctx.port_devname_arg = strdup(optarg);
			break;
		case 'a':
			free(cmd_ctx.array_index_arg);
			cmd_ctx.array_index_arg = strdup(optarg);
			break;
		case '?':
			fprintf(stderr, "unknown option.\n");
			print_help(argv0);
			return EXIT_FAILURE;
		default:
			fprintf(stderr, "unknown option \"%c\".\n", opt);
			print_help(argv0);
			return EXIT_FAILURE;
		}
	}

	if (optind >= argc) {
		fprintf(stderr, "No team device specified.\n");
		printf("\n");
		print_help(argv0);
		goto errout;
	}
	if (optind + 1 >= argc) {
		fprintf(stderr, "No command specified.\n");
		printf("\n");
		print_help(argv0);
		goto errout;
	}

	argv += optind;
	team_devname = *argv++;
	cmd_name = *argv++;
	argc -= optind + 2;
	cmd_ctx.argc = argc;
	cmd_ctx.argv = argv;
	for (i = 0; i < CMD_TYPE_COUNT; i++) {
		if (strncmp(cmd_types[i].name, cmd_name, strlen(cmd_name)))
			continue;
		err = call_cmd(team_devname, cmd_name, &cmd_ctx,
			       cmd_types[i].run_cmd);
		if (err) {
			fprintf(stderr, "Command failed: %s\n", strerror(-err));
			goto errout;
		}
		break;
	}
	if (i == CMD_TYPE_COUNT) {
		fprintf(stderr, "Unknown command \"%s\".\n", cmd_name);
		printf("\n");
		print_help(argv0);
		goto errout;
	}
	res = EXIT_SUCCESS;
errout:
	free(cmd_ctx.port_devname_arg);
	free(cmd_ctx.array_index_arg);
	return res;
}
