/*
 *   teamnl.c - Team device Netlink tool
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
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
#include <sys/signalfd.h>
#include <signal.h>
#include <unistd.h>
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
		if (!buf) {
			free(buf);
			return -ENOMEM;
		}
		trunc = team_option_value_str(option, buf, bufsiz);
	} while(trunc);

	printf("%s\n", buf);
	free(buf);
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

static int run_main_loop(struct team_handle *th)
{
	fd_set rfds;
	fd_set rfds_tmp;
	int fdmax;
	int ret;
	sigset_t mask;
	int sfd;
	int tfd;
	int err = 0;

	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	sigaddset(&mask, SIGQUIT);

	ret = sigprocmask(SIG_BLOCK, &mask, NULL);
	if (ret == -1) {
		fprintf(stderr, "Failed to set blocked signals\n");
		return -errno;
	}

	sfd = signalfd(-1, &mask, 0);
	if (sfd == -1) {
		fprintf(stderr, "Failed to open signalfd\n");
		return -errno;
	}

	FD_ZERO(&rfds);
	FD_SET(sfd, &rfds);
	fdmax = sfd;

	tfd = team_get_event_fd(th);
	FD_SET(tfd, &rfds);
	if (tfd > fdmax)
		fdmax = tfd;

	fdmax++;

	for (;;) {
		rfds_tmp = rfds;
		ret = select(fdmax, &rfds_tmp, NULL, NULL, NULL);
		if (ret == -1) {
			fprintf(stderr, "Select failed\n");
			err = -errno;
			goto out;
		}
		if (FD_ISSET(sfd, &rfds_tmp)) {
			struct signalfd_siginfo fdsi;
			ssize_t len;

			len = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
		        if (len != sizeof(struct signalfd_siginfo)) {
				fprintf(stderr, "Unexpected data length came from signalfd\n");
				err = -EINVAL;
				goto out;
			}
			switch (fdsi.ssi_signo) {
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				goto out;
			default:
				fprintf(stderr, "Read unexpected signal\n");
				err = -EINVAL;
				goto out;
			}

		}
		if (FD_ISSET(tfd, &rfds_tmp)) {
			err = team_handle_events(th);
			if (err) {
				fprintf(stderr, "Team handle events failed\n");
				return err;
			}
		}
	}
out:
	close(sfd);
	return err;
}

enum {
	MONITOR_STYLE_CHANGED,
	MONITOR_STYLE_ALL,
};

struct monitor_priv {
	unsigned int style;
};

static bool __should_show(struct monitor_priv *mpriv, bool changed)
{
	if (mpriv->style == MONITOR_STYLE_ALL)
		return true;
	if (mpriv->style == MONITOR_STYLE_CHANGED && changed)
		return true;
	return false;
}

static void monitor_port_list(struct team_handle *th,
			      struct monitor_priv *mpriv)
{
	struct team_port *port;
	char buf[120];
	bool trunc;
	bool skip = true;

	team_for_each_port(port, th) {
		if (__should_show(mpriv, team_is_port_changed(port))) {
			skip = false;
			break;
		}
	}
	if (skip)
		return;

	printf("ports:\n");
	team_for_each_port(port, th) {
		if (!__should_show(mpriv, team_is_port_changed(port)))
			continue;
		trunc = team_port_str(port, buf, sizeof(buf));
		printf("  %s %s\n", buf, trunc ? "..." : "");
	}
}

static void monitor_option_list(struct team_handle *th,
				struct monitor_priv *mpriv)
{
	struct team_option *option;
	char buf[120];
	bool trunc;
	bool skip = true;

	team_for_each_option(option, th) {
		if (__should_show(mpriv, team_is_option_changed(option))) {
			skip = false;
			break;
		}
	}
	if (skip)
		return;

	printf("options:\n");
	team_for_each_option(option, th) {
		if (!__should_show(mpriv, team_is_option_changed(option)))
			continue;
		trunc = team_option_str(th, option, buf, sizeof(buf));
		printf("  %s%s%s\n", buf, trunc ? "..." : "",
		       team_is_option_changed(option) ? " changed" : "");
	}
}

static void monitor_ifinfo_list(struct team_handle *th,
				struct monitor_priv *mpriv)
{
	struct team_ifinfo *ifinfo;
	char buf[120];
	bool trunc;
	bool skip = true;

	team_for_each_ifinfo(ifinfo, th) {
		if (__should_show(mpriv, team_is_ifinfo_changed(ifinfo))) {
			skip = false;
			break;
		}
	}
	if (skip)
		return;

	printf("ifinfos:\n");
	team_for_each_ifinfo(ifinfo, th) {
		if (!__should_show(mpriv, team_is_ifinfo_changed(ifinfo)))
			continue;
		trunc = team_ifinfo_str(ifinfo, buf, sizeof(buf));
		printf("  %s %s\n", buf, trunc ? "..." : "");
	}
}

static int debug_change_handler_func(struct team_handle *th, void *priv,
				     team_change_type_mask_t type_mask)
{
	struct monitor_priv *mpriv = priv;

	if (type_mask & TEAM_PORT_CHANGE)
		monitor_port_list(th, mpriv);
	if (type_mask & TEAM_OPTION_CHANGE)
		monitor_option_list(th, mpriv);
	if (type_mask & TEAM_IFINFO_CHANGE)
		monitor_ifinfo_list(th, mpriv);
	return 0;
}

static const struct team_change_handler debug_change_handler = {
	.func = debug_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE | TEAM_IFINFO_CHANGE,
};

static int run_cmd_monitor(char *cmd_name, struct team_handle *th,
			   struct cmd_ctx *cmd_ctx)
{
	struct monitor_priv mpriv;
	int err;

	mpriv.style = MONITOR_STYLE_CHANGED;
	if (cmd_ctx->argc > 0) {
		char *monitor_style_str = cmd_ctx->argv[0];

		if (!strncmp(monitor_style_str, "all",
			     strlen(monitor_style_str))) {
			mpriv.style = MONITOR_STYLE_ALL;
		} else if (!strncmp(monitor_style_str, "changed",
			     strlen(monitor_style_str))) {
			mpriv.style = MONITOR_STYLE_CHANGED;
		} else {
			fprintf(stderr, "Unknown monitor style \"%s\"\n",
					monitor_style_str);
			return -EINVAL;
		}
	}

	err = team_change_handler_register(th, &debug_change_handler, &mpriv);
	if (err) {
		fprintf(stderr, "Failed to register change handler\n");
		return err;
	}
	err = run_main_loop(th);
	team_change_handler_unregister(th, &debug_change_handler, &mpriv);
	return err;
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
	{
		.name = "monitor",
		.params = { "OPT_STYLE", NULL },
		.run_cmd = run_cmd_monitor,
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
