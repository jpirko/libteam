/*
 *   teamd.c - Network team device daemon
 *   Copyright (C) 2011-2015 Jiri Pirko <jiri@resnulli.us>
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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/select.h>
#include <linux/netdevice.h>
#include <sys/syslog.h>
#include <sys/timerfd.h>
#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "config.h"
#include "teamd.h"
#include "teamd_workq.h"
#include "teamd_config.h"
#include "teamd_state.h"
#include "teamd_usock.h"
#include "teamd_dbus.h"
#include "teamd_zmq.h"
#include "teamd_phys_port_check.h"

enum teamd_exit_code {
	TEAMD_EXIT_SUCCESS,
	TEAMD_EXIT_FAILURE,
	TEAMD_EXIT_RUNTIME_FAILURE,
};

static const struct teamd_runner *teamd_runner_list[] = {
	&teamd_runner_broadcast,
	&teamd_runner_roundrobin,
	&teamd_runner_random,
	&teamd_runner_activebackup,
	&teamd_runner_loadbalance,
	&teamd_runner_lacp,
};

#define TEAMD_RUNNER_LIST_SIZE ARRAY_SIZE(teamd_runner_list)

static const struct teamd_runner *teamd_find_runner(const char *runner_name)
{
	int i;

	for (i = 0; i < TEAMD_RUNNER_LIST_SIZE; i++) {
		if (strcmp(teamd_runner_list[i]->name, runner_name) == 0)
			return teamd_runner_list[i];
	}
	return NULL;
}

#define TEAMD_DEFAULT_RUNNER_NAME "roundrobin"
#define TEAMD_DEFAULT_DEVNAME_PREFIX "team"

static void libteam_log_daemon(struct team_handle *th, int priority,
			       const char *file, int line, const char *fn,
			       const char *format, va_list args)
{
	daemon_logv(priority, format, args);
}

static char **__g_pid_file;

static void print_help(const struct teamd_context *ctx) {
	int i;

	printf(
            "%s [options]\n"
            "    -h --help                Show this help\n"
            "    -d --daemonize           Daemonize after startup\n"
            "    -k --kill                Kill running daemon instance\n"
            "    -e --check               Return 0 if a daemon is already running\n"
            "    -v --version             Show version\n"
            "    -f --config-file=FILE    Load the specified configuration file\n"
            "    -c --config=TEXT         Use given config string (This causes configuration\n"
            "                             file will be ignored)\n"
            "    -p --pid-file=FILE       Use the specified PID file\n"
            "    -g --debug               Increase verbosity\n"
            "    -l --log-output          Force teamd log output to stdout, stderr or syslog\n"
            "    -r --force-recreate      Force team device recreation in case it\n"
            "                             already exists\n"
            "    -o --take-over           Take over the device if it already exists\n"
            "    -N --no-quit-destroy     Do not destroy the device on quit\n"
            "    -t --team-dev=DEVNAME    Use the specified team device\n"
            "    -n --no-ports            Start without ports\n"
            "    -D --dbus-enable         Enable D-Bus interface\n"
            "    -Z --zmq-enable=ADDRESS  Enable ZeroMQ interface\n"
            "    -U --usock-enable        Enable UNIX domain socket interface\n"
            "    -u --usock-disable       Disable UNIX domain socket interface\n",
            ctx->argv0);
	printf("Available runners: ");
	for (i = 0; i < TEAMD_RUNNER_LIST_SIZE; i++) {
		if (i != 0)
			printf(", ");
		printf("%s", teamd_runner_list[i]->name);
	}
	printf("\n");
}

static int parse_command_line(struct teamd_context *ctx,
			      int argc, char *argv[]) {
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
		{ "log-output",		required_argument,	NULL, 'l' },
		{ "force-recreate",	no_argument,		NULL, 'r' },
		{ "take-over",		no_argument,		NULL, 'o' },
		{ "no-quit-destroy",	no_argument,		NULL, 'N' },
		{ "team-dev",		required_argument,	NULL, 't' },
		{ "no-ports",		no_argument,		NULL, 'n' },
		{ "dbus-enable",	no_argument,		NULL, 'D' },
		{ "zmq-enable",		required_argument,	NULL, 'Z' },
		{ "usock-enable",	no_argument,		NULL, 'U' },
		{ "usock-disable",	no_argument,		NULL, 'u' },
		{ NULL, 0, NULL, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hdkevf:c:p:gl:roNt:nDZ:Uu",
				  long_options, NULL)) >= 0) {

		switch(opt) {
		case 'h':
			ctx->cmd = DAEMON_CMD_HELP;
			break;
		case 'd':
			ctx->daemonize = true;
			break;
		case 'k':
			ctx->cmd = DAEMON_CMD_KILL;
			break;
		case 'e':
			ctx->cmd = DAEMON_CMD_CHECK;
			break;
		case 'v':
			ctx->cmd = DAEMON_CMD_VERSION;
			break;
		case 'f':
			free(ctx->config_file);
			ctx->config_file = realpath(optarg, NULL);
			if (!ctx->config_file) {
				fprintf(stderr, "Failed to get absolute path of \"%s\": %s\n",
					optarg, strerror(errno));
				return -1;
			}
			break;
		case 'c':
			free(ctx->config_text);
			ctx->config_text = strdup(optarg);
			break;
		case 'p':
			free(ctx->pid_file);
			ctx->pid_file = strdup(optarg);
			break;
		case 'g':
			ctx->debug++;
			break;
		case 'l':
			free(ctx->log_output);
			ctx->log_output = strdup(optarg);
			break;
		case 'r':
			ctx->force_recreate = true;
			break;
		case 'o':
			ctx->take_over = true;
			break;
		case 'N':
			ctx->no_quit_destroy = true;
			break;
		case 't':
			free(ctx->team_devname);
			ctx->team_devname = strdup(optarg);
			break;
		case 'n':
			ctx->init_no_ports = true;
			break;
		case 'D':
#ifndef ENABLE_DBUS
			fprintf(stderr, "D-Bus support is not compiled-in\n");
			return -1;
#else
			ctx->dbus.enabled = true;
#endif
			break;
		case 'Z':
#ifndef ENABLE_ZMQ
			fprintf(stderr, "ZeroMQ support is not compiled-in\n");
			return -1;
#else
			ctx->zmq.enabled = true;
			ctx->zmq.addr = optarg;
#endif
			break;
		case 'U':
			ctx->usock.enabled = true;
			break;
		case 'u':
			ctx->usock.enabled = false;
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

static const char *teamd_pid_file_proc(void) {
	return *__g_pid_file;
}

static int handle_period_fd(int fd)
{
	ssize_t ret;
	uint64_t exp;

	ret = read(fd, &exp, sizeof(uint64_t));
	if (ret == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		teamd_log_err("read() failed.");
		return -errno;
	}
	if (ret == 0) {
		teamd_log_warn("read() for timer_fd returned 0.");
		return 0;
	}
	if (ret != sizeof(uint64_t)) {
		teamd_log_err("read() returned unexpected number of bytes.");
		return -EINVAL;
	}
	if (exp > 1)
		teamd_log_warn("some periodic function calls missed (%" PRIu64 ")",
			       exp - 1);
	return 0;
}

struct teamd_loop_callback {
	struct list_item list;
	char *name;
	void *priv;
	teamd_loop_callback_func_t func;
	int fd;
	int fd_event;
	bool is_period;
	bool enabled;
};

static void teamd_run_loop_set_fds(struct list_item *lcb_list,
				   fd_set *fds, int *fdmax)
{
	struct teamd_loop_callback *lcb;
	int i;

	list_for_each_node_entry(lcb, lcb_list, list) {
		if (!lcb->enabled)
			continue;
		for (i = 0; i < 3; i++) {
			if (lcb->fd_event & (1 << i)) {
				FD_SET(lcb->fd, &fds[i]);
				if (lcb->fd >= *fdmax)
					*fdmax = lcb->fd + 1;
			}
		}
	}
}

static int teamd_check_ctrl(struct teamd_context *ctx)
{
	int ctrl_fd = ctx->run_loop.ctrl_pipe_r;
	struct timeval tv;
	fd_set rfds;

	FD_ZERO(&rfds);
	FD_SET(ctrl_fd, &rfds);
	tv.tv_sec = tv.tv_usec = 0;

	return select(ctrl_fd + 1, &rfds, NULL, NULL, &tv);
}

static int teamd_run_loop_do_callbacks(struct list_item *lcb_list, fd_set *fds,
				       struct teamd_context *ctx)
{
	struct teamd_loop_callback *lcb;
	int i;
	int events;
	int err;

	list_for_each_node_entry(lcb, lcb_list, list) {
		for (i = 0; i < 3; i++) {
			if (!(lcb->fd_event & (1 << i)))
				continue;
			events = 0;
			if (FD_ISSET(lcb->fd, &fds[i]))
				events |= (1 << i);
			if (!events)
				continue;
			if (lcb->is_period) {
				err = handle_period_fd(lcb->fd);
				if (err)
					return err;
			}
			err = lcb->func(ctx, events, lcb->priv);
			if (err) {
				teamd_log_warn("Loop callback failed with: %s",
					       strerror(-err));
				teamd_log_dbg(ctx, "Failed loop callback: %s, %p",
					      lcb->name, lcb->priv);
			}

			/*
			 * If there's a control byte ready, it's possible that
			 * one or more entries have been removed from the
			 * callback list and restart has been requested. In any
			 * case, let the main loop deal with it first so that
			 * we know we're safe to proceed.
			 */
			if (teamd_check_ctrl(ctx))
				return 0;
		}
	}
	return 0;
}

static int teamd_flush_ports(struct teamd_context *ctx)
{
	if (!ctx->no_quit_destroy)
		return teamd_port_remove_all(ctx);
	else
		teamd_port_obj_remove_all(ctx);
	return 0;
}

static int teamd_run_loop_run(struct teamd_context *ctx)
{
	int err;
	int ctrl_fd = ctx->run_loop.ctrl_pipe_r;
	fd_set fds[3];
	int fdmax;
	char ctrl_byte;
	int i;
	bool quit_in_progress = false;

	/*
	 * To process all things correctly during cleanup, on quit command
	 * received via control pipe ('q') do flush all existing ports.
	 * After that wait until all ports are gone and return.
	 */

	while (true) {
		if (quit_in_progress && !teamd_has_ports(ctx))
			return ctx->run_loop.err;

		for (i = 0; i < 3; i++)
			FD_ZERO(&fds[i]);
		FD_SET(ctrl_fd, &fds[0]);
		fdmax = ctrl_fd + 1;

		teamd_run_loop_set_fds(&ctx->run_loop.callback_list,
				       fds, &fdmax);

		while (select(fdmax, &fds[0], &fds[1], &fds[2], NULL) < 0) {
			if (errno == EINTR)
				continue;

			teamd_log_err("select() failed.");
			return -errno;
		}

		if (FD_ISSET(ctrl_fd, &fds[0])) {
			err = read(ctrl_fd, &ctrl_byte, 1);
			if (err != -1) {
				switch(ctrl_byte) {
				case 'q':
					if (quit_in_progress)
						return -EBUSY;
					err = teamd_flush_ports(ctx);
					if (err)
						return err;
					quit_in_progress = true;
					continue;
				case 'r':
					continue;
				}
			} else if (errno == EINTR || errno == EAGAIN) {
				continue;
			} else {
				teamd_log_err("read() failed.");
				return -errno;
			}
		}

		err = teamd_run_loop_do_callbacks(&ctx->run_loop.callback_list,
						  fds, ctx);
		if (err)
			return err;
	}
	return 0;
}

static void teamd_run_loop_sent_ctrl_byte(struct teamd_context *ctx,
					  const char ctrl_byte)
{
	int err;

retry:
	err = write(ctx->run_loop.ctrl_pipe_w, &ctrl_byte, 1);
	if (err == -1 && errno == EINTR)
		goto retry;
}

void teamd_run_loop_quit(struct teamd_context *ctx, int err)
{
	ctx->run_loop.err = err;
	teamd_run_loop_sent_ctrl_byte(ctx, 'q');
}

void teamd_run_loop_restart(struct teamd_context *ctx)
{
	teamd_run_loop_sent_ctrl_byte(ctx, 'r');
}

static struct teamd_loop_callback *__get_lcb(struct teamd_context *ctx,
					     const char *cb_name, void *priv,
					     struct teamd_loop_callback *last)
{
	struct teamd_loop_callback *lcb;
	bool last_found;

	last_found = last == NULL ? true: false;
	list_for_each_node_entry(lcb, &ctx->run_loop.callback_list, list) {
		if (!last_found) {
			if (lcb == last)
				last_found = true;
			continue;
		}
		if (cb_name && strcmp(lcb->name, cb_name))
			continue;
		if (priv && lcb->priv != priv)
			continue;
		return lcb;
	}
	return NULL;
}

static struct teamd_loop_callback *get_lcb(struct teamd_context *ctx,
					   const char *cb_name, void *priv)
{
	return __get_lcb(ctx, cb_name, priv, NULL);
}

static struct teamd_loop_callback *get_lcb_multi(struct teamd_context *ctx,
						 const char *cb_name,
						 void *priv,
						 struct teamd_loop_callback *last)
{
	return __get_lcb(ctx, cb_name, priv, last);
}

#define for_each_lcb_multi_match(lcb, ctx, cb_name, priv)		\
	for (lcb = get_lcb_multi(ctx, cb_name, priv, NULL); lcb;	\
	     lcb = get_lcb_multi(ctx, cb_name, priv, lcb))

#define for_each_lcb_multi_match_safe(lcb, tmp, ctx, cb_name, priv)	\
	for (lcb = get_lcb_multi(ctx, cb_name, priv, NULL),		\
	     tmp = get_lcb_multi(ctx, cb_name, priv, lcb);		\
	     lcb;							\
	     lcb = tmp,							\
	     tmp = get_lcb_multi(ctx, cb_name, priv, lcb))

static int __teamd_loop_callback_fd_add(struct teamd_context *ctx,
					const char *cb_name, void *priv,
					teamd_loop_callback_func_t func,
					int fd, int fd_event, bool tail)
{
	int err;
	struct teamd_loop_callback *lcb;

	if (!cb_name || !priv)
		return -EINVAL;
	if (get_lcb(ctx, cb_name, priv)) {
		teamd_log_err("Callback named \"%s\" is already registered.",
			      cb_name);
		return -EEXIST;
	}
	lcb = myzalloc(sizeof(*lcb));
	if (!lcb) {
		teamd_log_err("Failed alloc memory for callback.");
		return -ENOMEM;
	}
	lcb->name = strdup(cb_name);
	if (!lcb->name) {
		err = -ENOMEM;
		goto lcb_free;
	}
	lcb->priv = priv;
	lcb->func = func;
	lcb->fd = fd;
	lcb->fd_event = fd_event & TEAMD_LOOP_FD_EVENT_MASK;
	if (tail)
		list_add_tail(&ctx->run_loop.callback_list, &lcb->list);
	else
		list_add(&ctx->run_loop.callback_list, &lcb->list);
	teamd_log_dbg(ctx, "Added loop callback: %s, %p", lcb->name, lcb->priv);
	return 0;

lcb_free:
	free(lcb);
	return err;
}

int teamd_loop_callback_fd_add(struct teamd_context *ctx,
			       const char *cb_name, void *priv,
			       teamd_loop_callback_func_t func,
			       int fd, int fd_event)
{
	return __teamd_loop_callback_fd_add(ctx, cb_name, priv, func,
					    fd, fd_event, false);
}

int teamd_loop_callback_fd_add_tail(struct teamd_context *ctx,
				    const char *cb_name, void *priv,
				    teamd_loop_callback_func_t func,
				    int fd, int fd_event)
{
	return __teamd_loop_callback_fd_add(ctx, cb_name, priv, func,
					    fd, fd_event, true);
}

static int __timerfd_reset(int fd, struct timespec *interval,
			   struct timespec *initial)
{
	struct itimerspec its;

	memset(&its, 0, sizeof(its));
	if (interval)
		its.it_interval = *interval;
	if (initial)
		its.it_value = *initial;
	else
		its.it_value.tv_nsec = 1; /* to enable that */
	if (timerfd_settime(fd, 0, &its, NULL) < 0) {
		teamd_log_err("Failed to set timerfd.");
		return -errno;
	}
	return 0;
}

int teamd_loop_callback_timer_add_set(struct teamd_context *ctx,
				      const char *cb_name, void *priv,
				      teamd_loop_callback_func_t func,
				      struct timespec *interval,
				      struct timespec *initial)
{
	int err;
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		teamd_log_err("Failed to create timerfd.");
		return -errno;
	}
	if (interval || initial) {
		err = __timerfd_reset(fd, interval, initial);
		if (err) {
			close(fd);
			return err;
		}
	}
	err = teamd_loop_callback_fd_add(ctx, cb_name, priv, func, fd,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		close(fd);
		return err;
	}
	get_lcb(ctx, cb_name, priv)->is_period = true;
	return 0;
}

int teamd_loop_callback_timer_add(struct teamd_context *ctx,
				  const char *cb_name, void *priv,
				  teamd_loop_callback_func_t func)
{
	return teamd_loop_callback_timer_add_set(ctx, cb_name, priv, func,
						 NULL, NULL);
}

int teamd_loop_callback_timer_set(struct teamd_context *ctx,
				  const char *cb_name,
				  void *priv,
				  struct timespec *interval,
				  struct timespec *initial)
{
	struct teamd_loop_callback *lcb;

	if (!cb_name || !priv)
		return -EINVAL;
	lcb = get_lcb(ctx, cb_name, priv);
	if (!lcb) {
		teamd_log_err("Callback named \"%s\" not found.", cb_name);
		return -ENOENT;
	}
	if (!lcb->is_period) {
		teamd_log_err("Can't reset non-periodic callback.");
		return -EINVAL;
	}
	return __timerfd_reset(lcb->fd, interval, initial);
}

void teamd_loop_callback_del(struct teamd_context *ctx, const char *cb_name,
			     void *priv)
{
	struct teamd_loop_callback *lcb;
	struct teamd_loop_callback *tmp;
	bool found = false;

	for_each_lcb_multi_match_safe(lcb, tmp, ctx, cb_name, priv) {
		list_del(&lcb->list);
		if (lcb->is_period)
			close(lcb->fd);
		teamd_log_dbg(ctx, "Removed loop callback: %s, %p",
			      lcb->name, lcb->priv);
		free(lcb->name);
		free(lcb);
		found = true;
	}
	if (found)
		teamd_run_loop_restart(ctx);
	else
		teamd_log_dbg(ctx, "Callback named \"%s\" not found.", cb_name);
}

int teamd_loop_callback_enable(struct teamd_context *ctx, const char *cb_name,
			       void *priv)
{
	struct teamd_loop_callback *lcb;
	bool found = false;

	for_each_lcb_multi_match(lcb, ctx, cb_name, priv) {
		lcb->enabled = true;
		found = true;
	}
	if (!found)
		return -ENOENT;
	teamd_run_loop_restart(ctx);
	return 0;
}

int teamd_loop_callback_disable(struct teamd_context *ctx, const char *cb_name,
				void *priv)
{
	struct teamd_loop_callback *lcb;
	bool found = false;

	for_each_lcb_multi_match(lcb, ctx, cb_name, priv) {
		lcb->enabled = false;
		found = true;
	}
	if (!found)
		return -ENOENT;
	teamd_run_loop_restart(ctx);
	return 0;
}

static int callback_daemon_signal(struct teamd_context *ctx, int events,
				  void *priv)
{
	int sig;

	/* Get signal */
	if ((sig = daemon_signal_next()) <= 0) {
		teamd_log_err("daemon_signal_next() failed.");
		return -EINVAL;
	}

	/* Dispatch signal */
	switch (sig) {
	case SIGINT:
	case SIGQUIT:
	case SIGTERM:
		teamd_log_warn("Got SIGINT, SIGQUIT or SIGTERM.");
		teamd_run_loop_quit(ctx, 0);
		break;
	}
	return 0;
}

static int callback_libteam_event(struct teamd_context *ctx, int events,
				  void *priv)
{
	return team_handle_events(ctx->th);
}

#define DAEMON_CB_NAME "daemon"
#define LIBTEAM_EVENTS_CB_NAME "libteam_events"

static int teamd_run_loop_init(struct teamd_context *ctx)
{
	int fds[2];
	int err;

	list_init(&ctx->run_loop.callback_list);
	err = pipe(fds);
	if (err)
		return -errno;
	ctx->run_loop.ctrl_pipe_r = fds[0];
	ctx->run_loop.ctrl_pipe_w = fds[1];

	err = teamd_loop_callback_fd_add(ctx, DAEMON_CB_NAME, ctx,
					 callback_daemon_signal,
					 daemon_signal_fd(),
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed to add daemon loop callback");
		goto close_pipe;
	}

	err = teamd_loop_callback_fd_add(ctx, LIBTEAM_EVENTS_CB_NAME, ctx,
					 callback_libteam_event,
					 team_get_event_fd(ctx->th),
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed to add libteam event loop callback");
		goto del_daemon_callback;
	}

	teamd_loop_callback_enable(ctx, DAEMON_CB_NAME, ctx);
	teamd_loop_callback_enable(ctx, LIBTEAM_EVENTS_CB_NAME, ctx);

	return 0;

del_daemon_callback:
	teamd_loop_callback_del(ctx, DAEMON_CB_NAME, ctx);

close_pipe:
	close(ctx->run_loop.ctrl_pipe_r);
	close(ctx->run_loop.ctrl_pipe_w);
	return err;
}

static void teamd_run_loop_fini(struct teamd_context *ctx)
{
	teamd_loop_callback_del(ctx, LIBTEAM_EVENTS_CB_NAME, NULL);
	teamd_loop_callback_del(ctx, DAEMON_CB_NAME, ctx);
	close(ctx->run_loop.ctrl_pipe_r);
	close(ctx->run_loop.ctrl_pipe_w);
}

static int parse_hwaddr(const char *hwaddr_str, char **phwaddr,
			unsigned int *plen)
{
	const char *pos = hwaddr_str;
	unsigned int byte_count = 0;
	unsigned int tmp;
	int err;
	char *hwaddr = NULL;
	char *new_hwaddr;
	char *endptr;

	while (true) {
		errno = 0;
		tmp = strtoul(pos, &endptr, 16);
		if (errno != 0 || tmp > 0xFF) {
			err = -EINVAL;
			goto err_out;
		}
		byte_count++;
		new_hwaddr = realloc(hwaddr, sizeof(char) * byte_count);
		if (!new_hwaddr) {
			err = -ENOMEM;
			goto err_out;
		}
		hwaddr = new_hwaddr;
		hwaddr[byte_count - 1] = (char) tmp;
		while (isspace(endptr[0]) && endptr[0] != '\0')
			endptr++;
		if (endptr[0] == ':') {
			pos = endptr + 1;
		} else if (endptr[0] == '\0') {
			break;
		} else {
			err = -EINVAL;
			goto err_out;
		}
	}
	*phwaddr = hwaddr;
	*plen = byte_count;
	return 0;
err_out:
	free(hwaddr);
	return err;
}

static int teamd_set_hwaddr(struct teamd_context *ctx)
{
	int err;
	const char *hwaddr_str;
	char *hwaddr;
	unsigned int hwaddr_len;

	err = teamd_config_string_get(ctx, &hwaddr_str, "$.hwaddr");
	if (err)
		return 0; /* addr is not defined in config, no change needed */

	teamd_log_dbg(ctx, "Hwaddr string: \"%s\".", hwaddr_str);
	err = parse_hwaddr(hwaddr_str, &hwaddr, &hwaddr_len);
	if (err) {
		teamd_log_err("Failed to parse hardware address.");
		return err;
	}

	if (hwaddr_len != ctx->hwaddr_len) {
		teamd_log_err("Passed hardware address has different length (%d) than team device has (%d).",
			      hwaddr_len, ctx->hwaddr_len);
		err = -EINVAL;
		goto free_hwaddr;
	}

	if (memcmp(hwaddr, ctx->hwaddr, hwaddr_len))
		err = team_hwaddr_set(ctx->th, ctx->ifindex, hwaddr, hwaddr_len);
	else {
		err = 0;
		teamd_log_dbg(ctx, "Skip setting same hwaddr string: \"%s\".", hwaddr_str);
	}

	if (!err)
		ctx->hwaddr_explicit = true;
free_hwaddr:
	free(hwaddr);
	return err;
}

static int teamd_add_ports(struct teamd_context *ctx)
{
	int err;
	const char *key;

	ctx->pre_add_ports = false;
	if (ctx->init_no_ports)
		return 0;

	teamd_config_for_each_key(key, ctx, "$.ports") {
		err = teamd_port_add_ifname(ctx, key);
		if (err == -ENODEV) {
			teamd_log_warn("%s: Skipped adding a missing port.", key);
			continue;
		} else if (err) {
			teamd_log_err("%s: Failed to add port (%s).", key,
				      strerror(-err));
			return err;
		}
	}
	return 0;
}

static int teamd_hwaddr_check_change(struct teamd_context *ctx,
				     struct teamd_port *tdport)
{
	char *hwaddr;
	unsigned char hwaddr_len;
	int err;

	if (ctx->port_obj_list_count != 1 || ctx->hwaddr_explicit)
		return 0;
	hwaddr = team_get_ifinfo_orig_hwaddr(tdport->team_ifinfo);
	hwaddr_len = team_get_ifinfo_orig_hwaddr_len(tdport->team_ifinfo);
	if (hwaddr_len != ctx->hwaddr_len) {
		teamd_log_err("%s: Port original hardware address has different length (%d) than team device has (%d).",
			      tdport->ifname, hwaddr_len, ctx->hwaddr_len);
		return -EINVAL;
	}
	err = team_hwaddr_set(ctx->th, ctx->ifindex, hwaddr, hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set team device hardware address.");
		return err;
	}
	memcpy(ctx->hwaddr, hwaddr, hwaddr_len);
	ctx->hwaddr_len = hwaddr_len;
	return 0;
}

static int teamd_event_watch_port_added(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	int err;
	int tmp;

	if (!ctx->pre_add_ports) {
		err = teamd_hwaddr_check_change(ctx, tdport);
		if (err)
			return err;
	}

	err = teamd_config_int_get(ctx, &tmp, "$.ports.%s.queue_id",
				   tdport->ifname);
	if (!err) {
		uint32_t queue_id;

		if (tmp < 0) {
			teamd_log_err("%s: \"queue_id\" must not be negative number.",
				      tdport->ifname);
			return -EINVAL;
		}
		queue_id = tmp;
		err = team_set_port_queue_id(ctx->th, tdport->ifindex,
					     queue_id);
		if (err) {
			teamd_log_err("%s: Failed to set \"queue_id\".",
				      tdport->ifname);
			return err;
		}
	}
	err = teamd_config_int_get(ctx, &tmp, "$.ports.%s.prio",
				   tdport->ifname);
	if (err)
		tmp = 0;
	err = team_set_port_priority(ctx->th, tdport->ifindex, tmp);
	if (err) {
		teamd_log_err("%s: Failed to set \"priority\".",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static const struct teamd_event_watch_ops teamd_port_watch_ops = {
	.port_added = teamd_event_watch_port_added,
};

static int teamd_port_watch_init(struct teamd_context *ctx)
{
	return teamd_event_watch_register(ctx, &teamd_port_watch_ops, NULL);
}

static void teamd_port_watch_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &teamd_port_watch_ops, NULL);
}

static int teamd_runner_init(struct teamd_context *ctx)
{
	int err;
	const char *runner_name;

	err = teamd_config_string_get(ctx, &runner_name, "$.runner.name");
	if (err) {
		teamd_log_dbg(ctx, "Failed to get team runner name from config.");
		runner_name = TEAMD_DEFAULT_RUNNER_NAME;
		err = teamd_config_string_set(ctx, runner_name, "$.runner.name");
		if (err) {
			teamd_log_err("Failed to set default team runner name in config.");
			return err;
		}
		teamd_log_dbg(ctx, "Using default team runner \"%s\".", runner_name);
	} else {
		teamd_log_dbg(ctx, "Using team runner \"%s\".", runner_name);
	}
	ctx->runner = teamd_find_runner(runner_name);
	if (!ctx->runner) {
		teamd_log_err("No runner named \"%s\" available.", runner_name);
		return -EINVAL;
	}

	if (ctx->runner->team_mode_name) {
		char *cur_mode;
		const char *new_mode = ctx->runner->team_mode_name;

		err = team_get_mode_name(ctx->th, &cur_mode);
		if (err) {
			teamd_log_err("Failed to det team mode.");
			return err;
		}
		if (strcmp(cur_mode, new_mode)) {
			err = team_set_mode_name(ctx->th, new_mode);
			if (err) {
				teamd_log_err("Failed to set team mode \"%s\".",
					      new_mode);
				return err;
			}
		}
	} else {
		teamd_log_warn("Note \"%s\" runner does not select team mode resulting in no functionality!",
			       runner_name);
	}

	if (ctx->runner->priv_size) {
		ctx->runner_priv = myzalloc(ctx->runner->priv_size);
		if (!ctx->runner_priv)
			return -ENOMEM;
	}

	if (ctx->runner->init) {
		err = ctx->runner->init(ctx, ctx->runner_priv);
		if (err)
			goto free_runner_priv;
	}
	return 0;

free_runner_priv:
	free(ctx->runner_priv);
	return err;
}

static void teamd_runner_fini(struct teamd_context *ctx)
{
	if (ctx->runner->fini)
		ctx->runner->fini(ctx, ctx->runner_priv);
	free(ctx->runner_priv);
	ctx->runner = NULL;
}

static int teamd_post_runner_init(struct teamd_context *ctx)
{
	int err;
	int tmp;

	err = teamd_config_int_get(ctx, &tmp, "$.notify_peers.count");
	if (!err) {
		uint32_t count;

		if (tmp < 0) {
			teamd_log_err("\"count\" must not be negative number.");
			return -EINVAL;
		}
		count = tmp;
		err = team_set_notify_peers_count(ctx->th, count);
		if (err) {
			if (err == -ENOENT) {
				teamd_log_warn("Failed to set \"notify_peers_count\". Kernel probably does not support this option yet.");
			} else {
				teamd_log_err("Failed to set \"notify_peers_count\".");
				return err;
			}
		}
	}
	err = teamd_config_int_get(ctx, &tmp, "$.notify_peers.interval");
	if (!err) {
		uint32_t interval;

		if (tmp < 0) {
			teamd_log_err("\"interval\" must not be negative number.");
			return -EINVAL;
		}
		interval = tmp;
		err = team_set_notify_peers_interval(ctx->th, interval);
		if (err) {
			if (err == -ENOENT) {
				teamd_log_warn("Failed to set \"notify_peers_interval\". Kernel probably does not support this option yet.");
			} else {
				teamd_log_err("Failed to set \"notify_peers_interval\".");
				return err;
			}
		}
	}
	err = teamd_config_int_get(ctx, &tmp, "$.mcast_rejoin.count");
	if (!err) {
		uint32_t count;

		if (tmp < 0) {
			teamd_log_err("\"count\" must not be negative number.");
			return -EINVAL;
		}
		count = tmp;
		err = team_set_mcast_rejoin_count(ctx->th, count);
		if (err) {
			if (err == -ENOENT) {
				teamd_log_warn("Failed to set \"mcast_rejoin_count\". Kernel probably does not support this option yet.");
			} else {
				teamd_log_err("Failed to set \"mcast_rejoin_count\".");
				return err;
			}
		}
	}
	err = teamd_config_int_get(ctx, &tmp, "$.mcast_rejoin.interval");
	if (!err) {
		uint32_t interval;

		if (tmp < 0) {
			teamd_log_err("\"interval\" must not be negative number.");
			return -EINVAL;
		}
		interval = tmp;
		err = team_set_mcast_rejoin_interval(ctx->th, interval);
		if (err) {
			if (err == -ENOENT) {
				teamd_log_warn("Failed to set \"mcast_rejoin_interval\". Kernel probably does not support this option yet.");
			} else {
				teamd_log_err("Failed to set \"mcast_rejoin_interval\".");
				return err;
			}
		}
	}
	return 0;
}

static void debug_log_port_list(struct teamd_context *ctx)
{
	struct team_port *port;
	char buf[120];
	bool trunc;

	teamd_log_dbg(ctx, "<port_list>");
	team_for_each_port(port, ctx->th) {
		trunc = team_port_str(port, buf, sizeof(buf));
		teamd_log_dbg(ctx, "%s %s", buf, trunc ? "<trunc>" : "");
	}
	teamd_log_dbg(ctx, "</port_list>");
}

static void debug_log_option_list(struct teamd_context *ctx)
{
	struct team_option *option;
	char buf[120];
	bool trunc;

	teamd_log_dbgx(ctx, 2, "<changed_option_list>");
	team_for_each_option(option, ctx->th) {
		if (!team_is_option_changed(option) ||
		    team_is_option_changed_locally(option))
			continue;
		trunc = team_option_str(ctx->th, option, buf, sizeof(buf));
		teamd_log_dbgx(ctx, 2, "%s %s", buf, trunc ? "<trunc>" : "");
	}
	teamd_log_dbgx(ctx, 2, "</changed_option_list>");
}

static void debug_log_ifinfo_list(struct teamd_context *ctx)
{
	struct team_ifinfo *ifinfo;
	char buf[120];
	bool trunc;

	teamd_log_dbg(ctx, "<ifinfo_list>");
	team_for_each_ifinfo(ifinfo, ctx->th) {
		trunc = team_ifinfo_str(ifinfo, buf, sizeof(buf));
		teamd_log_dbg(ctx, "%s %s", buf, trunc ? "<trunc>" : "");
	}
	teamd_log_dbg(ctx, "</ifinfo_list>");
}

static int debug_change_handler_func(struct team_handle *th, void *priv,
				     team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = priv;

	if (type_mask & TEAM_PORT_CHANGE)
		debug_log_port_list(ctx);
	if (type_mask & TEAM_OPTION_CHANGE)
		debug_log_option_list(ctx);
	if (type_mask & TEAM_IFINFO_CHANGE)
		debug_log_ifinfo_list(ctx);
	return 0;
}

static const struct team_change_handler debug_change_handler = {
	.func = debug_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE | TEAM_IFINFO_CHANGE,
};

static int teamd_register_debug_handler(struct teamd_context *ctx)
{
	return team_change_handler_register_head(ctx->th,
						 &debug_change_handler, ctx);
}

static int teamd_register_default_handlers(struct teamd_context *ctx)
{
	if (!ctx->debug)
		return 0;
	return teamd_register_debug_handler(ctx);
}

static void teamd_unregister_debug_handler(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &debug_change_handler, ctx);
}

static void teamd_unregister_default_handlers(struct teamd_context *ctx)
{
	if (!ctx->debug)
		return;
	teamd_unregister_debug_handler(ctx);
}

int teamd_change_debug_level(struct teamd_context *ctx, unsigned int new_debug)
{
	int err = 0;

	if (!ctx->debug && new_debug) {
		daemon_set_verbosity(LOG_DEBUG);
		err = teamd_register_debug_handler(ctx);
	}
	if (ctx->debug && !new_debug) {
		daemon_set_verbosity(LOG_WARNING);
		teamd_unregister_debug_handler(ctx);
	}
	if (err)
		return err;
	ctx->debug = new_debug;
	return 0;
}

static int teamd_init(struct teamd_context *ctx)
{
	int err;

	ctx->th = team_alloc();
	if (!ctx->th) {
		teamd_log_err("Team alloc failed.");
		return -ENOMEM;
	}
	if (ctx->debug)
		team_set_log_priority(ctx->th, LOG_DEBUG);

	team_set_log_fn(ctx->th, libteam_log_daemon);

	ctx->ifindex = team_ifname2ifindex(ctx->th, ctx->team_devname);
	if (ctx->ifindex && ctx->take_over)
		goto skip_create;

	if (ctx->force_recreate)
		err = team_recreate(ctx->th, ctx->team_devname);
	else
		err = team_create(ctx->th, ctx->team_devname);
	if (err) {
		teamd_log_err("Failed to create team device.");
		goto team_free;
	}

	ctx->ifindex = team_ifname2ifindex(ctx->th, ctx->team_devname);
	if (!ctx->ifindex) {
		teamd_log_err("Netdevice \"%s\" not found.", ctx->team_devname);
		err = -ENODEV;
		goto team_destroy;
	}
skip_create:

	err = team_init(ctx->th, ctx->ifindex);
	if (err) {
		teamd_log_err("Team init failed.");
		goto team_destroy;
	}

	ctx->ifinfo = team_get_ifinfo(ctx->th);
	ctx->hwaddr = team_get_ifinfo_hwaddr(ctx->ifinfo);
	ctx->hwaddr_len = team_get_ifinfo_hwaddr_len(ctx->ifinfo);

	err = teamd_set_hwaddr(ctx);
	if (err) {
		teamd_log_err("Hardware address set failed.");
		goto team_destroy;
	}

	err = teamd_run_loop_init(ctx);
	if (err) {
		teamd_log_err("Failed to init run loop.");
		goto team_destroy;
	}

	err = teamd_workq_init(ctx);
	if (err) {
		teamd_log_err("Failed to init workq.");
		goto run_loop_fini;
	}

	err = teamd_register_default_handlers(ctx);
	if (err) {
		teamd_log_err("Failed to register debug event handlers.");
		goto workq_fini;
	}

	err = teamd_events_init(ctx);
	if (err) {
		teamd_log_err("Failed to init events infrastructure.");
		goto team_unreg_debug_handlers;
	}

	err = teamd_option_watch_init(ctx);
	if (err) {
		teamd_log_err("Failed to init option watches.");
		goto events_fini;
	}

	err = teamd_ifinfo_watch_init(ctx);
	if (err) {
		teamd_log_err("Failed to init ifinfo watches.");
		goto option_watch_fini;
	}

	err = teamd_port_watch_init(ctx);
	if (err) {
		teamd_log_err("Failed to init port watch.");
		goto ifinfo_watch_fini;
	}

	err = teamd_state_init(ctx);
	if (err) {
		teamd_log_err("Failed to init state json infrastructure.");
		goto port_watch_fini;
	}

	err = teamd_per_port_init(ctx);
	if (err) {
		teamd_log_err("Failed to init per-port.");
		goto state_fini;
	}

	err = teamd_link_watch_init(ctx);
	if (err) {
		teamd_log_err("Failed to init link watch.");
		goto per_port_fini;
	}

	err = teamd_runner_init(ctx);
	if (err) {
		teamd_log_err("Failed to init runner.");
		goto link_watch_fini;
	}

	err = teamd_post_runner_init(ctx);
	if (err) {
		teamd_log_err("Failed to do post-runner initializations.");
		goto runner_fini;
	}

	err = teamd_state_basics_init(ctx);
	if (err) {
		teamd_log_err("Failed to init state json basics.");
		goto runner_fini;
	}

	err = teamd_phys_port_check_init(ctx);
	if (err) {
		teamd_log_err("Failed to init SR-IOV support.");
		goto state_basics_fini;
	}

	err = teamd_usock_init(ctx);
	if (err) {
		teamd_log_err("Failed to init unix domain socket.");
		goto phys_port_check_fini;
	}

	err = teamd_dbus_init(ctx);
	if (err) {
		teamd_log_err("Failed to init dbus.");
		goto usock_fini;
	}

	err = teamd_zmq_init(ctx);
	if (err) {
		teamd_log_err("Failed to init zmq.");
		goto dbus_fini;
	}

	ctx->pre_add_ports = true;
	err = team_refresh(ctx->th);
	if (err) {
		teamd_log_err("Team refresh failed.");
		goto zmq_fini;
	}

	err = teamd_add_ports(ctx);
	if (err) {
		teamd_log_err("Failed to add ports.");
		goto zmq_fini;
	}

	/*
	 * Expose name as the last thing so watchers like systemd
	 * knows we are here and all ready.
	 */
	err = teamd_dbus_expose_name(ctx);
	if (err) {
		teamd_log_err("Failed to expose dbus name.");
		goto zmq_fini;
	}

	return 0;
zmq_fini:
	teamd_zmq_fini(ctx);
dbus_fini:
	teamd_dbus_fini(ctx);
usock_fini:
	teamd_usock_fini(ctx);
phys_port_check_fini:
	teamd_phys_port_check_fini(ctx);
state_basics_fini:
	teamd_state_basics_fini(ctx);
runner_fini:
	teamd_runner_fini(ctx);
link_watch_fini:
	teamd_link_watch_fini(ctx);
per_port_fini:
	teamd_per_port_fini(ctx);
state_fini:
	teamd_state_fini(ctx);
port_watch_fini:
	teamd_port_watch_fini(ctx);
ifinfo_watch_fini:
	teamd_ifinfo_watch_fini(ctx);
option_watch_fini:
	teamd_option_watch_fini(ctx);
events_fini:
	teamd_events_fini(ctx);
team_unreg_debug_handlers:
	teamd_unregister_default_handlers(ctx);
workq_fini:
	teamd_workq_fini(ctx);
run_loop_fini:
	teamd_run_loop_fini(ctx);
team_destroy:
	if (!ctx->take_over)
		team_destroy(ctx->th);
team_free:
	team_free(ctx->th);
	return err;
}

static void teamd_fini(struct teamd_context *ctx)
{
	teamd_zmq_fini(ctx);
	teamd_dbus_fini(ctx);
	teamd_usock_fini(ctx);
	teamd_phys_port_check_fini(ctx);
	teamd_state_basics_fini(ctx);
	teamd_runner_fini(ctx);
	teamd_link_watch_fini(ctx);
	teamd_per_port_fini(ctx);
	teamd_state_fini(ctx);
	teamd_ifinfo_watch_fini(ctx);
	teamd_option_watch_fini(ctx);
	teamd_events_fini(ctx);
	teamd_unregister_default_handlers(ctx);
	teamd_workq_fini(ctx);
	teamd_run_loop_fini(ctx);
	if (!ctx->no_quit_destroy)
		team_destroy(ctx->th);
	team_free(ctx->th);
}

static int teamd_start(struct teamd_context *ctx, enum teamd_exit_code *p_ret)
{
	pid_t pid;
	int err = 0;

	if (getuid() == 0)
		teamd_log_warn("This program is not intended to be run as root.");

	if (daemon_reset_sigs(-1) < 0) {
		teamd_log_err("Failed to reset all signal handlers.");
		return -errno;
	}

	if (daemon_unblock_sigs(SIGPIPE, -1) < 0) {
		teamd_log_err("Failed to unblock all signals.");
		return -errno;
	}

	pid = daemon_pid_file_is_running();
	if (pid == 0)
		daemon_pid_file_remove();
	if (pid > 0) {
		teamd_log_err("Daemon already running on PID %u.", pid);
		return -EEXIST;
	}

	if (ctx->daemonize) {
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

	ctx->log_output = ctx->log_output ? : getenv("TEAM_LOG_OUTPUT");
	if (ctx->log_output) {
		if (strcmp(ctx->log_output, "stdout") == 0)
			daemon_log_use = DAEMON_LOG_STDOUT;
		else if (strcmp(ctx->log_output, "stderr") == 0)
			daemon_log_use = DAEMON_LOG_STDERR;
		else if (strcmp(ctx->log_output, "syslog") == 0)
			daemon_log_use = DAEMON_LOG_SYSLOG;
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

	err = teamd_init(ctx);
	if (err) {
		teamd_log_err("teamd_init() failed.");
		daemon_retval_send(-err);
		goto signal_done;
	}
	*p_ret = TEAMD_EXIT_RUNTIME_FAILURE;

	daemon_retval_send(0);

	teamd_log_info(PACKAGE_VERSION" successfully started.");

	err = teamd_run_loop_run(ctx);

	teamd_log_info("Exiting...");

	teamd_fini(ctx);

signal_done:
	daemon_signal_done();

pid_file_remove:
	daemon_pid_file_remove();

	return err;
}

static int teamd_generate_devname(struct teamd_context *ctx)
{
	char buf[IFNAMSIZ];
	int i = 0;
	uint32_t ifindex = 0; /* gcc needs this initialized */
	int ret;
	int err;

	do {
		ret = snprintf(buf, sizeof(buf),
			       TEAMD_DEFAULT_DEVNAME_PREFIX "%d", i++);
		if (ret >= sizeof(buf))
			return -EINVAL;
		err = ifname2ifindex(&ifindex, buf);
		if (err)
			return err;
	} while (ifindex);
	teamd_log_dbg(ctx, "Generated team device name \"%s\".", buf);

	ctx->team_devname = strdup(buf);
	if (!ctx->team_devname)
		return -ENOMEM;
	return 0;
}

static int teamd_get_devname(struct teamd_context *ctx, bool generate_enabled)
{
	int err;

	if (!ctx->team_devname) {
		const char *team_name;

		err = teamd_config_string_get(ctx, &team_name, "$.device");
		if (!err) {
			ctx->team_devname = strdup(team_name);
			if (!ctx->team_devname) {
				teamd_log_err("Failed allocate memory for device name.");
				return -ENOMEM;
			}
			goto skip_set;
		} else {
			teamd_log_dbg(ctx, "Failed to get team device name from config.");
			if (generate_enabled) {
				err = teamd_generate_devname(ctx);
				if (err) {
					teamd_log_err("Failed to generate team device name.");
					return err;
				}
			} else {
				teamd_log_err("Team device name not specified.");
				return -EINVAL;
			}
		}
	}
	err = teamd_config_string_set(ctx, ctx->team_devname, "$.device");
	if (err) {
		teamd_log_err("Failed to set team device name in config.");
		return err;
	}

skip_set:
	teamd_log_dbg(ctx, "Using team device \"%s\".", ctx->team_devname);

	err = asprintf(&ctx->ident, "%s_%s", ctx->argv0, ctx->team_devname);
	if (err == -1) {
		teamd_log_err("Failed allocate memory for identification string.");
		return -ENOMEM;
	}
	return 0;
}

static int teamd_set_default_pid_file(struct teamd_context *ctx)
{
	int err;

	/* Generate PID filename only if it was not set on command line */
	if (ctx->pid_file)
		return 0;

	err = asprintf(&ctx->pid_file, TEAMD_RUN_DIR"%s.pid", ctx->team_devname);
	if (err == -1) {
		teamd_log_err("Failed allocate memory for PID file string.");
		return -ENOMEM;
	}
	return 0;
}

static void teamd_init_debug_level(struct teamd_context *ctx)
{
	int err;
	int tmp;

	err = teamd_config_int_get(ctx, &tmp, "$.debug_level");
	if (err || tmp <= ctx->debug)
		return;
	ctx->debug = tmp;
	daemon_set_verbosity(LOG_DEBUG);
}

static int teamd_context_init(struct teamd_context **pctx)
{
	struct teamd_context *ctx;

	ctx = myzalloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	*pctx = ctx;
	__g_pid_file = &ctx->pid_file;

	/* Enable usock by default */
	ctx->usock.enabled = true;
	return 0;
}

static void teamd_context_fini(struct teamd_context *ctx)
{
	free(ctx->ident);
	free(ctx->team_devname);
	free(ctx->config_text);
	free(ctx->config_file);
	free(ctx->pid_file);
	free(ctx);
}


#ifdef HAVE_LIBCAP
#include <sys/prctl.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#ifndef TEAMD_USER
#define TEAMD_USER "root"
#endif
#ifndef TEAMD_GROUP
#define TEAMD_GROUP "root"
#endif

static int teamd_drop_privileges()
{
	cap_value_t cv[] = {CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW};
	cap_t my_caps;
	struct passwd *pw = NULL;
	struct group *grpent = NULL;

	if ((pw = getpwnam(TEAMD_USER)) == NULL) {
		fprintf(stderr, "Error reading user %s entry (%m)\n", TEAMD_USER);
		goto error;
	}

	if (pw->pw_uid == 0)
		return 0;

	if ((grpent = getgrnam(TEAMD_GROUP)) == NULL) {
		fprintf(stderr, "Error reading group %s entry (%m)\n", TEAMD_GROUP);
		goto error;
	}

	if (pw->pw_gid != grpent->gr_gid) {
		fprintf(stderr, "%s GID (%u) does not match %s GID (%u)\n",
			TEAMD_USER, pw->pw_gid, TEAMD_GROUP, grpent->gr_gid);
		goto error;
	}

	if (chown(TEAMD_RUN_DIR, pw->pw_uid, pw->pw_gid) < 0) {
		fprintf(stderr, "Unable to change ownership of %s to %s/%s (%m)\n",
			TEAMD_RUN_DIR, TEAMD_USER, TEAMD_GROUP);
		goto error;
	}

	if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0)
		goto error;

	if (setgid(pw->pw_gid) < 0) {
		fprintf(stderr, "Unable to set process GID to %u (%m)\n", pw->pw_gid);
		goto error;
	}

	if (initgroups(TEAMD_USER, pw->pw_gid) < 0) {
		fprintf(stderr, "Unable to initialize the group access list for %s user with GID %u (%m)\n",
			TEAMD_USER, pw->pw_gid);
		goto error;
	}
	if (setuid(pw->pw_uid) < 0) {
		fprintf(stderr, "Unable to set UID to %u (%m)\n", pw->pw_uid);
		goto error;
	}

	if ((my_caps = cap_init()) == NULL)
		goto error;
	if (cap_set_flag(my_caps, CAP_EFFECTIVE, ARRAY_SIZE(cv), cv, CAP_SET) < 0)
		goto error;
	if (cap_set_flag(my_caps, CAP_PERMITTED, ARRAY_SIZE(cv), cv, CAP_SET) < 0)
		goto error;
	if (cap_set_proc(my_caps) < 0)
		goto error;
	cap_free(my_caps);

	return 0;
error:
	fprintf(stderr, "Failed to drop privileges\n");
	return -EINVAL;
}

#else

static int teamd_drop_privileges()
{
	return 0;
}

#endif

static int teamd_get_link_watch_policy(struct teamd_context *ctx)
{
	int err;
	const char *link_watch_policy;

	err = teamd_config_string_get(ctx, &link_watch_policy, "$.link_watch_policy");
	if (!err) {
		if (!strcmp(link_watch_policy, "all")) {
			ctx->evaluate_all_watchers = true;
		} else if (!strcmp(link_watch_policy, "any")) {
			ctx->evaluate_all_watchers = false;
		} else {
			teamd_log_err("Unrecognized value for link_watch_policy.");
			teamd_log_err("Only \"any\" or \"all\" are allowed but \"%s\" found in config.", link_watch_policy);
			return -EINVAL;
		}
	} else {
		teamd_log_dbg(ctx, "No link_watch_policy specified in config, using default value \"any\".");
	}
	return 0;
}

int main(int argc, char **argv)
{
	enum teamd_exit_code ret = TEAMD_EXIT_FAILURE;
	int err;
	struct teamd_context *ctx;

	err = teamd_make_rundir();
	if (err)
		return ret;

	err = teamd_drop_privileges();
	if (err)
		return ret;

	err = teamd_context_init(&ctx);
	if (err) {
		fprintf(stderr, "Failed to init daemon context\n");
		return ret;
	}

	err = parse_command_line(ctx, argc, argv);
	if (err)
		goto context_fini;

	ctx->argv0 = daemon_ident_from_argv0(argv[0]);

	switch (ctx->cmd) {
	case DAEMON_CMD_HELP:
		print_help(ctx);
		ret = TEAMD_EXIT_SUCCESS;
		goto context_fini;
	case DAEMON_CMD_VERSION:
		printf("%s "PACKAGE_VERSION"\n", ctx->argv0);
		ret = TEAMD_EXIT_SUCCESS;
		goto context_fini;
	case DAEMON_CMD_KILL:
	case DAEMON_CMD_CHECK:
	case DAEMON_CMD_RUN:
		break;
	}

	if (ctx->debug)
		daemon_set_verbosity(LOG_DEBUG);

	daemon_log_ident = ctx->argv0;

	err = teamd_config_load(ctx);
	if (err) {
		teamd_log_err("Failed to load config.");
		goto context_fini;
	}

	teamd_init_debug_level(ctx);

	err = teamd_get_devname(ctx, ctx->cmd == DAEMON_CMD_RUN);
	if (err)
		goto config_free;

	err = teamd_get_link_watch_policy(ctx);
	if (err)
		goto config_free;

	err = teamd_set_default_pid_file(ctx);
	if (err)
		goto config_free;

	daemon_log_ident = ctx->ident;
	daemon_pid_file_proc = teamd_pid_file_proc;

	teamd_log_dbg(ctx, "Using PID file \"%s\"", daemon_pid_file_proc());
	if (ctx->config_file)
		teamd_log_dbg(ctx, "Using config file \"%s\"", ctx->config_file);

	switch (ctx->cmd) {
	case DAEMON_CMD_HELP:
	case DAEMON_CMD_VERSION:
		break;
	case DAEMON_CMD_KILL:
		if (daemon_pid_file_is_running() > 0) {
			err = daemon_pid_file_kill_wait(SIGTERM, 30);
			if (err)
				teamd_log_warn("Failed to kill daemon: %s",
					       strerror(errno));
			else
				ret = TEAMD_EXIT_SUCCESS;
		} else {
			teamd_log_warn("Daemon not running");
		}
		break;
	case DAEMON_CMD_CHECK:
		ret = (daemon_pid_file_is_running() > 0) ? TEAMD_EXIT_SUCCESS :
							   TEAMD_EXIT_FAILURE;
		break;
	case DAEMON_CMD_RUN:
		err = teamd_start(ctx, &ret);
		if (err)
			teamd_log_err("Failed: %s", strerror(-err));
		else
			ret = TEAMD_EXIT_SUCCESS;
		break;
	}

config_free:
	teamd_config_free(ctx);
context_fini:
	teamd_context_fini(ctx);
	return ret;
}
