/*
 *   teamd.c - Network team device daemon
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
#include <linux/netdevice.h>
#include <sys/syslog.h>
#include <sys/timerfd.h>
#include <libdaemon/dfork.h>
#include <libdaemon/dsignal.h>
#include <libdaemon/dlog.h>
#include <libdaemon/dpid.h>
#include <jansson.h>
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

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
            "    -V --version             Show version\n"
            "    -f --config-file=FILE    Load the specified configuration file\n"
            "    -c --config=TEXT         Use given config string (This causes configuration\n"
	    "                             file will be ignored)\n"
            "    -p --pid-file=FILE       Use the specified PID file\n"
            "    -g --debug               Increase verbosity\n"
            "    -r --force-recreate      Force team device recreation in case it\n"
            "                             already exists\n"
            "    -t --team-dev=DEVNAME    Use the specified team device\n"
            "    -n --no-ports            Start without ports\n"
            "    -D --dbus-enable         Enable D-Bus interface\n"
            "    -U --usock-enable        Enable UNIX domain socket interface\n",
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
		{ "force-recreate",	no_argument,		NULL, 'r' },
		{ "team-dev",		required_argument,	NULL, 't' },
		{ "no-ports",		no_argument,		NULL, 'n' },
		{ "dbus-enable",	no_argument,		NULL, 'D' },
		{ "usock-enable",	no_argument,		NULL, 'U' },
		{ NULL, 0, NULL, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hdkevf:c:p:grt:nDU",
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
		case 'r':
			ctx->force_recreate = true;
			break;
		case 't':
			free(ctx->team_devname);
			ctx->team_devname = strdup(optarg);
			break;
		case 'n':
			ctx->init_no_ports = true;
			break;
		case 'D':
			ctx->dbus.enabled = true;
			break;
		case 'U':
			ctx->usock.enabled = true;
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

static const char *pid_file_proc(void) {
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

static int teamd_run_loop_do_callbacks(struct list_item *lcb_list, fd_set *fds,
					struct teamd_context *ctx)
{
	struct teamd_loop_callback *lcb;
	int i;
	int events;
	int err;

	list_for_each_node_entry(lcb, lcb_list, list) {
		for (i = 0; i < 3; i++) {
			if (lcb->fd_event& (1 << i)) {
				events = 0;
				if (FD_ISSET(lcb->fd, &fds[i]))
					events |= (1 << i);
				if (events) {
					if (lcb->is_period) {
						err = handle_period_fd(lcb->fd);
						if (err)
							return err;
					}
					err = lcb->func(ctx, events, lcb->priv);
					if (err)
						return err;
				}
			}
		}
	}
	return 0;
}

static int teamd_flush_ports(struct teamd_context *ctx)
{
	struct teamd_port *tdport;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		err = teamd_port_remove(ctx, tdport->ifname);
		if (err)
			return err;
	}
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
						continue;
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

static void teamd_run_loop_quit(struct teamd_context *ctx, int err)
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

int teamd_loop_callback_fd_add(struct teamd_context *ctx,
			       const char *cb_name, void *priv,
			       teamd_loop_callback_func_t func,
			       int fd, int fd_event)
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
	list_add(&ctx->run_loop.callback_list, &lcb->list);
	return 0;

lcb_free:
	free(lcb);
	return err;
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
	int fd = fd;

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
	bool found = false;

	for_each_lcb_multi_match(lcb, ctx, cb_name, priv) {
		list_del(&lcb->list);
		if (lcb->is_period)
			close(lcb->fd);
		free(lcb);
		free(lcb->name);
		found = true;
	}
	if (found)
		teamd_run_loop_restart(ctx);
	else
		teamd_log_dbg("Callback named \"%s\" not found.", cb_name);
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
	const struct team_eventfd *eventfd = priv;

	return team_call_eventfd_handler(ctx->th, eventfd);
}

#define DAEMON_CB_NAME "daemon"
#define LIBTEAM_EVENTS_CB_NAME "libteam_events"

static int teamd_run_loop_init(struct teamd_context *ctx)
{
	int fds[2];
	const struct team_eventfd *eventfd;
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

	team_for_each_event_fd(eventfd, ctx->th) {
		int fd = team_get_eventfd_fd(ctx->th, eventfd);
		err = teamd_loop_callback_fd_add(ctx, LIBTEAM_EVENTS_CB_NAME,
						 (void *) eventfd,
						 callback_libteam_event,
						 fd, TEAMD_LOOP_FD_EVENT_READ);
		if (err) {
			teamd_log_err("Failed to add libteam event loop callback");
			goto unroll_libteam_events_callbacks;
		}
	}

	teamd_loop_callback_enable(ctx, DAEMON_CB_NAME, ctx);
	teamd_loop_callback_enable(ctx, LIBTEAM_EVENTS_CB_NAME, NULL);

	return 0;

unroll_libteam_events_callbacks:
	teamd_loop_callback_del(ctx, LIBTEAM_EVENTS_CB_NAME, NULL);
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

#define TEAMD_IMPLICIT_CONFIG "{\"device\": \"team0\", \"runner\": {\"name\": \"roundrobin\"}}"

static int config_load(struct teamd_context *ctx)
{
	json_error_t jerror;
	size_t jflags = JSON_REJECT_DUPLICATES;

	if (!ctx->config_text && !ctx->config_file) {
		ctx->config_text = strdup(TEAMD_IMPLICIT_CONFIG);
		if (!ctx->config_text)
			return -ENOMEM;
		teamd_log_warn("No config passed, using implicit one.");
	}
	if (ctx->config_text) {
		if (ctx->config_file)
			teamd_log_warn("Command line config string is present, ignoring given config file.");
		ctx->config_json = json_loads(ctx->config_text, jflags,
					      &jerror);
	} else if (ctx->config_file) {
		ctx->config_json = json_load_file(ctx->config_file, jflags,
						  &jerror);
	}
	if (!ctx->config_json) {
		teamd_log_err("Failed to parse config: %s on line %d, column %d",
			      jerror.text, jerror.line, jerror.column);
		return -EIO;
	}

	return 0;
}

static void config_free(struct teamd_context *ctx)
{
	json_decref(ctx->config_json);
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

static int teamd_check_change_hwaddr(struct teamd_context *ctx)
{
	int err;
	const char *hwaddr_str;
	char *hwaddr;
	unsigned int hwaddr_len;

	err = json_unpack(ctx->config_json, "{s:s}", "hwaddr", &hwaddr_str);
	if (err)
		return 0; /* addr is not defined in config, no change needed */

	teamd_log_dbg("Hwaddr string: \"%s\".", hwaddr_str);
	err = parse_hwaddr(hwaddr_str, &hwaddr, &hwaddr_len);
	if (err) {
		teamd_log_err("Failed to parse hardware address.");
		return err;
	}

	if (hwaddr_len != ctx->hwaddr_len) {
		teamd_log_err("Passed hardware address has different length (%d) than team device has (%d).",
			      hwaddr_len, ctx->hwaddr_len);
		return -EINVAL;
	}
	err = team_hwaddr_set(ctx->th, ctx->ifindex, hwaddr, hwaddr_len);
	free(hwaddr);
	return err;
}

static int get_port_obj(json_t **pport_obj, json_t *config_json,
			const char *port_name)
{
	int err;
	json_t *ports_obj;
	json_t *port_obj;

	err = json_unpack(config_json, "{s:o}", "ports", &ports_obj);
	if (err) {
		ports_obj = json_object();
		if (!ports_obj)
			return -ENOMEM;
		err = json_object_set(config_json, "ports", ports_obj);
		if (err) {
			json_decref(ports_obj);
			return -ENOMEM;
		}
	}
	err = json_unpack(ports_obj, "{s:o}", port_name, &port_obj);
	if (err) {
		port_obj = json_object();
		if (!port_obj)
			return -ENOMEM;
		err = json_object_set(ports_obj, port_name, port_obj);
		if (err) {
			json_decref(port_obj);
			return -ENOMEM;
		}
	}
	if (pport_obj)
		*pport_obj = port_obj;
	return 0;
}

int teamd_get_actual_config(struct teamd_context *ctx, json_t **pactual_json)
{
	json_t *actual_json;
	struct teamd_port *tdport;
	json_t *ports_obj;
	void *iter;
	int err;

	actual_json = json_deep_copy(ctx->config_json);
	if (!actual_json)
		return -ENOMEM;

	/*
	 * Create json objects for all present ports
	 */
	teamd_for_each_tdport(tdport, ctx) {
		err = get_port_obj(NULL, actual_json, tdport->ifname);
		if (err)
			goto errout;
	}

	/*
	 * Get rid of json object of ports which are not present
	 */
	err = json_unpack(actual_json, "{s:o}", "ports", &ports_obj);
	if (err) {
		err = -EINVAL;
		goto errout;
	}
	iter = json_object_iter(ports_obj);
	while (iter) {
		const char *port_name = json_object_iter_key(iter);

		iter = json_object_iter_next(ports_obj, iter);
		if (!teamd_get_port_by_ifname(ctx, (char *) port_name))
			json_object_del(ports_obj, port_name);
	}

	*pactual_json = actual_json;
	return 0;

errout:
	json_decref(actual_json);
	return err;
}

int teamd_update_port_config(struct teamd_context *ctx, const char *port_name,
			     const char *json_port_cfg_str)
{
	int err;
	json_t *port_obj;
	json_t *port_new_obj;
	json_error_t jerror;

	port_new_obj = json_loads(json_port_cfg_str, JSON_REJECT_DUPLICATES,
				  &jerror);
	if (!port_new_obj) {
		teamd_log_err("%s: Failed to parse port config string: "
			      "%s on line %d, column %d", port_name,
			      jerror.text, jerror.line, jerror.column);
		return -EIO;
	}
	err = get_port_obj(&port_obj, ctx->config_json, port_name);
	if (err) {
		teamd_log_err("%s: Failed to obtain port config object",
			      port_name);
		goto new_port_decref;
	}

	/* replace existing object content */
	json_object_clear(port_obj);
	err = json_object_update(port_obj, port_new_obj);
	if (err)
		teamd_log_err("%s: Failed to update existing config "
			      "port object", port_name);
new_port_decref:
	json_decref(port_new_obj);
	return err;
}

int teamd_port_add(struct teamd_context *ctx, const char *port_name)
{
	int err;
	uint32_t ifindex;

	ifindex = team_ifname2ifindex(ctx->th, port_name);
	teamd_log_dbg("%s: Adding port (found ifindex \"%d\").",
		      port_name, ifindex);
	err = team_port_add(ctx->th, ifindex);
	if (err)
		teamd_log_err("%s: Failed to add port.", port_name);
	return err;
}

int teamd_port_remove(struct teamd_context *ctx, const char *port_name)
{
	int err;
	uint32_t ifindex;

	ifindex = team_ifname2ifindex(ctx->th, port_name);
	teamd_log_dbg("%s: Removing port (found ifindex \"%d\").",
		      port_name, ifindex);
	err = team_port_remove(ctx->th, ifindex);
	if (err)
		teamd_log_err("%s: Failed to remove port.", port_name);
	return err;
}

static int teamd_add_ports(struct teamd_context *ctx)
{
	int err;
	json_t *ports_obj;
	void *iter;

	if (ctx->init_no_ports)
		return 0;

	err = json_unpack(ctx->config_json, "{s:o}", "ports", &ports_obj);
	if (err) {
		teamd_log_dbg("No ports found in config.");
		return 0;
	}
	for (iter = json_object_iter(ports_obj); iter;
	     iter = json_object_iter_next(ports_obj, iter)) {
		const char *port_name = json_object_iter_key(iter);

		err = teamd_port_add(ctx, port_name);
		if (err)
			return err;
	}
	return 0;
}

static int teamd_event_watch_port_added(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	int err;
	json_t *port_obj;
	int tmp;

	err = json_unpack(ctx->config_json, "{s:{s:o}}",
			  "ports", tdport->ifname, &port_obj);
	if (err)
		return 0; /* no config found */

	err = json_unpack(port_obj, "{s:i}", "queue_id", &tmp);
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
	err = json_unpack(port_obj, "{s:i}", "prio", &tmp);
	if (!err)
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

	err = json_unpack(ctx->config_json, "{s:{s:s}}", "runner", "name",
							 &runner_name);
	if (err) {
		teamd_log_err("Failed to get team runner name from config.");
		return -EINVAL;
	}
	teamd_log_dbg("Using team runner \"%s\".", runner_name);
	ctx->runner = teamd_find_runner(runner_name);
	if (!ctx->runner) {
		teamd_log_err("No runner named \"%s\" available.", runner_name);
		return -EINVAL;
	}

	if (ctx->runner->team_mode_name) {
		err = team_set_mode_name(ctx->th, ctx->runner->team_mode_name);
		if (err) {
			teamd_log_err("Failed to set team mode \"%s\".",
				      ctx->runner->team_mode_name);
			return err;
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

	if (ctx->runner->state_json_ops) {
		err = teamd_state_json_register(ctx,
						ctx->runner->state_json_ops,
						ctx->runner_priv);
		if (err)
			goto free_runner_priv;
	}

	if (ctx->runner->init) {
		err = ctx->runner->init(ctx, ctx->runner_priv);
		if (err)
			goto runner_state_unreg;
	}
	return 0;

runner_state_unreg:
	if (ctx->runner->state_json_ops)
		teamd_state_json_unregister(ctx, ctx->runner->state_json_ops,
					    ctx->runner_priv);
free_runner_priv:
	free(ctx->runner_priv);
	return err;
}

static void teamd_runner_fini(struct teamd_context *ctx)
{
	if (ctx->runner->fini)
		ctx->runner->fini(ctx, ctx->runner_priv);
	if (ctx->runner->state_json_ops)
		teamd_state_json_unregister(ctx, ctx->runner->state_json_ops,
					    ctx->runner_priv);
	free(ctx->runner_priv);
	ctx->runner = NULL;
}

static void debug_log_port_list(struct teamd_context *ctx)
{
	struct team_port *port;
	char buf[120];
	bool trunc;

	teamd_log_dbg("<port_list>");
	team_for_each_port(port, ctx->th) {
		trunc = team_port_str(port, buf, sizeof(buf));
		teamd_log_dbg("%s %s", buf, trunc ? "<trunc>" : "");
	}
	teamd_log_dbg("</port_list>");
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

	teamd_log_dbg("<ifinfo_list>");
	team_for_each_ifinfo(ifinfo, ctx->th) {
		trunc = team_ifinfo_str(ifinfo, buf, sizeof(buf));
		teamd_log_dbg("%s %s", buf, trunc ? "<trunc>" : "");
	}
	teamd_log_dbg("</ifinfo_list>");
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

static int teamd_register_default_handlers(struct teamd_context *ctx)
{
	if (!ctx->debug)
		return 0;
	return team_change_handler_register(ctx->th,
					    &debug_change_handler, ctx);
}

static void teamd_unregister_default_handlers(struct teamd_context *ctx)
{
	if (!ctx->debug)
		return;
	team_change_handler_unregister(ctx->th, &debug_change_handler, ctx);
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

	err = team_init(ctx->th, ctx->ifindex);
	if (err) {
		teamd_log_err("Team init failed.");
		goto team_destroy;
	}

	ctx->ifinfo = team_get_ifinfo(ctx->th);
	ctx->hwaddr = team_get_ifinfo_hwaddr(ctx->ifinfo);
	ctx->hwaddr_len = team_get_ifinfo_hwaddr_len(ctx->ifinfo);

	err = teamd_check_change_hwaddr(ctx);
	if (err) {
		teamd_log_err("Hardware address change failed.");
		goto team_destroy;
	}

	err = teamd_run_loop_init(ctx);
	if (err) {
		teamd_log_err("Failed to init run loop.");
		goto team_destroy;
	}

	err = teamd_register_default_handlers(ctx);
	if (err) {
		teamd_log_err("Failed to register debug event handlers.");
		goto run_loop_fini;
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

	err = teamd_state_json_init(ctx);
	if (err) {
		teamd_log_err("Failed to init state json infrastructure.");
		goto port_watch_fini;
	}

	err = teamd_per_port_init(ctx);
	if (err) {
		teamd_log_err("Failed to init per-port.");
		goto state_json_fini;
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

	err = teamd_state_json_basics_init(ctx);
	if (err) {
		teamd_log_err("Failed to init state json basics.");
		goto runner_fini;
	}

	err = teamd_usock_init(ctx);
	if (err) {
		teamd_log_err("Failed to init unix domain socket.");
		goto state_json_basics_fini;
	}

	err = teamd_dbus_init(ctx);
	if (err) {
		teamd_log_err("Failed to init dbus.");
		goto usock_fini;
	}

	err = teamd_add_ports(ctx);
	if (err) {
		teamd_log_err("Failed to add ports.");
		goto dbus_fini;
	}

	/*
	 * Expose name as the last thing so watchers like systemd
	 * knows we are here and all ready.
	 */
	err = teamd_dbus_expose_name(ctx);
	if (err) {
		teamd_log_err("Failed to expose dbus name.");
		goto dbus_fini;
	}

	return 0;

dbus_fini:
	teamd_dbus_fini(ctx);
usock_fini:
	teamd_usock_fini(ctx);
state_json_basics_fini:
	teamd_state_json_basics_fini(ctx);
runner_fini:
	teamd_runner_fini(ctx);
link_watch_fini:
	teamd_link_watch_fini(ctx);
per_port_fini:
	teamd_per_port_fini(ctx);
state_json_fini:
	teamd_state_json_fini(ctx);
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
run_loop_fini:
	teamd_run_loop_fini(ctx);
team_destroy:
	team_destroy(ctx->th);
team_free:
	team_free(ctx->th);
	return err;
}

static void teamd_fini(struct teamd_context *ctx)
{
	teamd_dbus_fini(ctx);
	teamd_usock_fini(ctx);
	teamd_runner_fini(ctx);
	teamd_link_watch_fini(ctx);
	teamd_per_port_fini(ctx);
	teamd_state_json_fini(ctx);
	teamd_ifinfo_watch_fini(ctx);
	teamd_option_watch_fini(ctx);
	teamd_events_fini(ctx);
	teamd_unregister_default_handlers(ctx);
	teamd_run_loop_fini(ctx);
	team_destroy(ctx->th);
	team_free(ctx->th);
}

static int teamd_start(struct teamd_context *ctx)
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

	daemon_retval_send(0);

	teamd_log_info(PACKAGE_VERSION" sucessfully started.");

	err = teamd_run_loop_run(ctx);

	teamd_log_info("Exiting...");

	teamd_fini(ctx);

signal_done:
	daemon_signal_done();

pid_file_remove:
	daemon_pid_file_remove();

	return err;
}

static int teamd_get_devname(struct teamd_context *ctx)
{
	int err;

	if (!ctx->team_devname) {
		const char *team_name;

		err = json_unpack(ctx->config_json, "{s:s}", "device", &team_name);
		if (err) {
			teamd_log_err("Failed to get team device name.");
			return -EINVAL;
		}
		ctx->team_devname = strdup(team_name);
		if (!ctx->team_devname) {
			teamd_log_err("Failed allocate memory for device name.");
			return -ENOMEM;
		}
	}
	teamd_log_dbg("Using team device \"%s\".", ctx->team_devname);

	err = asprintf(&ctx->ident, "%s_%s", ctx->argv0, ctx->team_devname);
	if (err == -1) {
		teamd_log_err("Failed allocate memory for identification string.");
		return -ENOMEM;
	}
	return 0;
}

static int teamd_context_init(struct teamd_context **pctx)
{
	struct teamd_context *ctx;

	ctx = myzalloc(sizeof(*ctx));
	if (!ctx)
		return -ENOMEM;
	*pctx = ctx;
	__g_pid_file = &ctx->pid_file;
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

int main(int argc, char **argv)
{
	int ret = EXIT_FAILURE;
	int err;
	struct teamd_context *ctx;

	err = teamd_context_init(&ctx);
	if (err) {
		fprintf(stderr, "Failed to init daemon context\n");
		return ret;
	}

	err = parse_command_line(ctx, argc, argv);
	if (err)
		goto context_fini;

	if (ctx->debug)
		daemon_set_verbosity(LOG_DEBUG);

	ctx->argv0 = daemon_ident_from_argv0(argv[0]);
	daemon_log_ident = ctx->argv0;

	err = config_load(ctx);
	if (err) {
		teamd_log_err("Failed to load config.");
		goto context_fini;
	}
	err = teamd_get_devname(ctx);
	if (err)
		goto config_free;

	daemon_log_ident = ctx->ident;
	daemon_pid_file_ident = ctx->ident;

	if (ctx->pid_file)
		daemon_pid_file_proc = pid_file_proc;

	teamd_log_dbg("Using PID file \"%s\"", daemon_pid_file_proc());
	if (ctx->config_file)
		teamd_log_dbg("Using config file \"%s\"", ctx->config_file);

	switch (ctx->cmd) {
	case DAEMON_CMD_HELP:
		print_help(ctx);
		ret = EXIT_SUCCESS;
		break;
	case DAEMON_CMD_VERSION:
		printf("%s "PACKAGE_VERSION"\n", ctx->argv0);
		ret = 0;
		break;
	case DAEMON_CMD_KILL:
		err = daemon_pid_file_kill_wait(SIGTERM, 5);
		if (err)
			teamd_log_warn("Failed to kill daemon: %s", strerror(errno));
		else
			ret = EXIT_SUCCESS;
		break;
	case DAEMON_CMD_CHECK:
		ret = (daemon_pid_file_is_running() >= 0) ? 0 : 1;
		break;
	case DAEMON_CMD_RUN:
		err = teamd_start(ctx);
		if (err)
			teamd_log_err("Failed: %s", strerror(-err));
		else
			ret = EXIT_SUCCESS;
		break;
	}

config_free:
	config_free(ctx);
context_fini:
	teamd_context_fini(ctx);
	return ret;
}
