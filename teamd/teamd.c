/*
 * teamd.c - Network team device daemon
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/syslog.h>
#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <json/json.h>
#include <team.h>

#define teamd_log_err(args...) daemon_log(LOG_ERR, ##args)
#define teamd_log_warn(args...) daemon_log(LOG_WARNING, ##args)
#define teamd_log_info(args...) daemon_log(LOG_INFO, ##args)
#define teamd_log_dbg(args...) daemon_log(LOG_DEBUG, ##args)

enum daemon_command {
	DAEMON_CMD_RUN,
	DAEMON_CMD_KILL,
	DAEMON_CMD_VERSION,
	DAEMON_CMD_HELP,
	DAEMON_CMD_CHECK
};

struct daemon_context {
	enum daemon_command	cmd;
	bool			daemonize;
	bool			debug;
	char *			config_file;
	char *			config_text;
	json_object *		config_jso;
	char *			pid_file;
	char *			argv0;
};

static struct daemon_context ctx;

static const char *teamd_cfg_get_str(const char *query)
{
	json_object *jso;

	jso = json_object_simple_query(ctx.config_jso, query);
	if (!jso) {
		teamd_log_err("Config string get failed. No such object (query: %s)", query);
		return NULL;
	}
	if (json_object_get_type(jso) != json_type_string) {
		teamd_log_err("Config string get failed. Object has different type (query: %s)", query);
		return NULL;
	}

	return json_object_get_string(jso);
}

static void print_help(void) {
	printf(
            "%s [options]\n"
            "    -h --help                Show this help\n"
            "    -d --daemonize           Daemonize after startup (implies -s)\n"
            "    -k --kill                Kill a running daemon\n"
            "    -e --check               Return 0 if a daemon is already running\n"
            "    -V --version             Show version\n"
            "    -f --config-file=FILE    Load the specified configuration file\n"
            "    -c --config=TEXT         Use given config string (This causes configuration\n"
	    "                             file will be ignored)\n"
            "    -p --pid-file=FILE       Use the specified PID file\n"
            "    -g --debug               Increase verbosity\n",
            ctx.argv0);
}

static int parse_command_line(int argc, char *argv[]) {
	int opt;
	static const struct option long_options[] = {
		{ "help",		no_argument,		NULL, 'h' },
		{ "daemonize",		no_argument,		NULL, 'd' },
		{ "kill",		no_argument,		NULL, 'k' },
		{ "check",		no_argument,		NULL, 'e' },
		{ "version",		no_argument,		NULL, 'v' },
		{ "config-file",	required_argument,	NULL, 'f' },
		{ "config",		required_argument,	NULL, 'c' },
		{ "pid-file",		required_argument,	NULL, 'p' },
		{ "debug",		no_argument,		NULL, 'g' },
		{ NULL, 0, NULL, 0 }
	};
	char *argv0;

	if ((argv0 = strrchr(argv[0], '/')))
		argv0 = strdup(argv0 + 1);
	else
		argv0 = strdup(argv[0]);
	ctx.argv0 = argv0;

	while ((opt = getopt_long(argc, argv, "hdkevf:c:p:g",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			ctx.cmd = DAEMON_CMD_HELP;
			break;
		case 'd':
			ctx.daemonize = true;
			break;
		case 'k':
			ctx.cmd = DAEMON_CMD_KILL;
			break;
		case 'e':
			ctx.cmd = DAEMON_CMD_CHECK;
			break;
		case 'v':
			ctx.cmd = DAEMON_CMD_VERSION;
			break;
		case 'f':
			free(ctx.config_file);
			ctx.config_file = strdup(optarg);
			break;
		case 'c':
			free(ctx.config_text);
			ctx.config_text = strdup(optarg);
			break;
		case 'p':
			free(ctx.pid_file);
			ctx.pid_file = strdup(optarg);
			break;
		case 'g':
			ctx.debug = true;
			break;
		default:
			return -1;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "Too many arguments\n");
		return -1;
	}

	return 0;
}

static void context_init(void)
{
	memset(&ctx, sizeof(ctx), 0);
}

static void context_fini(void)
{
	free(ctx.config_text);
	free(ctx.config_file);
	free(ctx.pid_file);
	free(ctx.argv0);
}

static const char *pid_file_proc(void) {
	return ctx.pid_file;
}

static int teamd_run()
{
	bool quit = false;
	int sig_fd;
        fd_set fds;
	int fdmax;

	FD_ZERO(&fds);
	sig_fd = daemon_signal_fd();
	FD_SET(sig_fd, &fds);
	fdmax = sig_fd + 1;

	while (!quit) {
		fd_set fds_tmp = fds;

		if (select(fdmax, &fds_tmp, NULL, NULL, NULL) < 0) {
			if (errno == EINTR)
				continue;

			teamd_log_err("select() failed.");
			return -errno;
		}

		if (FD_ISSET(sig_fd, &fds_tmp)) {
			int sig;

			/* Get signal */
			if ((sig = daemon_signal_next()) <= 0) {
				teamd_log_err("daemon_signal_next() failed.");
				return -errno;
			}

			/* Dispatch signal */
			switch (sig) {
			case SIGINT:
			case SIGQUIT:
			case SIGTERM:
				teamd_log_warn("Got SIGINT, SIGQUIT or SIGTERM.");
				quit = true;
				break;

			}
		}
	}
	return 0;
}

static int load_config()
{
	if (ctx.config_text) {
		if (ctx.config_file)
			teamd_log_warn("Command line configuration is present, ignoring give config file.");
		ctx.config_jso = json_tokener_parse(ctx.config_text);
		if (!ctx.config_jso) {
			teamd_log_err("Failed to load configuration from command line.");
			return -EIO;
		}
	} else if (ctx.config_file) {
		ctx.config_jso = json_object_from_file(ctx.config_file);
		if (!ctx.config_jso) {
			teamd_log_err("Failed to load configuration from file \"%s\".", ctx.config_file);
			return -EIO;
		}
	} else {
		teamd_log_err("Either configuration file or command line configuration string must be present.");
		return -ENOENT;
	}
	return 0;
}

static int teamd_init()
{
	int err;
	const char *team_name;

	err = load_config();
	if (err) {
		teamd_log_err("Failed to load config.");
		return err;
	}
	team_name = teamd_cfg_get_str("['device']");
	if (!team_name) {
		teamd_log_err("Failed to get team device name.");
		return -ENOENT;
	}

	teamd_log_dbg("Using team device \"%s\".", team_name);

	return 0;
}

static int teamd_start()
{
	pid_t pid;
	int err = 0;

	if (getuid() != 0) {
		teamd_log_err("This program is intended to be run as root.");
		return -EPERM;
	}

	if (daemon_reset_sigs(-1) < 0) {
		teamd_log_err("Failed to reset all signal handlers.");
		return -errno;
	}

	if (daemon_unblock_sigs(-1) < 0) {
		teamd_log_err("Failed to unblock all signals.");
		return -errno;
	}

	pid = daemon_pid_file_is_running();
	if (pid >= 0) {
		teamd_log_err("Daemon already running on PID %u.", pid);
		return -EEXIST;
	}

	if (ctx.daemonize) {
		daemon_retval_init();

		pid = daemon_fork();
		if (pid < 0) {
			teamd_log_err("Daemon fork failed.");
			daemon_retval_done();
			return -errno;
		}
		else if (pid != 0) {
			int ret;

			/* Parent */
			ret = daemon_retval_wait(20);
			if (ret < 0) {
				teamd_log_err("Could not receive return value from daemon process.");
				return -errno;
			}
			if (ret > 0)
				teamd_log_err("Daemon process failed.");
			return -ret;
		}

	/* Child */
	}

	if (daemon_close_all(-1) < 0) {
		teamd_log_err("Failed to close all file descriptors.");
		daemon_retval_send(errno);
		return -errno;
        }

	if (daemon_pid_file_create() < 0) {
		teamd_log_err("Could not create PID file.");
		daemon_retval_send(errno);
		return -errno;
	}

	if (daemon_signal_init(SIGINT, SIGTERM, SIGQUIT, SIGHUP, 0) < 0) {
		teamd_log_err("Could not register signal handlers.");
		daemon_retval_send(errno);
		err = -errno;
		goto pid_file_remove;
	}

	err = teamd_init();
	if (err) {
		teamd_log_err("teamd_init() failed.");
		daemon_retval_send(-err);
		goto signal_done;
	}

        daemon_retval_send(0);

        teamd_log_info(PACKAGE_VERSION" sucessfully started.");

	err = teamd_run();

        teamd_log_info("Exiting...");

signal_done:
	daemon_signal_done();

pid_file_remove:
	daemon_pid_file_remove();

	return err;
}

int main(int argc, char **argv)
{
	int ret = 255;
	int err;

	context_init();

	err = parse_command_line(argc, argv);
	if (err)
		goto finish;

	if (ctx.debug)
		daemon_set_verbosity(LOG_DEBUG);

	daemon_log_ident = ctx.argv0;
	daemon_pid_file_ident = ctx.argv0;

	if (ctx.pid_file)
		daemon_pid_file_proc = pid_file_proc;

	teamd_log_dbg("Using PID file \"%s\"", daemon_pid_file_proc());

	switch (ctx.cmd) {
	case DAEMON_CMD_HELP:
		print_help();
		ret = 0;
		break;
	case DAEMON_CMD_VERSION:
		printf("%s "PACKAGE_VERSION"\n", ctx.argv0);
		ret = 0;
		break;
	case DAEMON_CMD_KILL:
		err = daemon_pid_file_kill_wait(SIGTERM, 5);
		if (err)
			teamd_log_warn("Failed to kill daemon: %s", strerror(errno));
		else
			ret = 0;
		break;
	case DAEMON_CMD_CHECK:
		ret = (daemon_pid_file_is_running() >= 0) ? 0 : 1;
		break;
	case DAEMON_CMD_RUN:
		err = teamd_start();
		if (err)
			teamd_log_err("Failed to start daemon: %s", strerror(-err));
		else
			ret = 0;
		break;
	}

finish:

	context_fini();
	return ret;
}
