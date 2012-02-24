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

/* For purpose of immediate use, e.g. print */
char *dev_name(const struct teamd_context *ctx, uint32_t ifindex)
{
	static char ifname[IFNAMSIZ];

	return team_ifindex2ifname(ctx->th, ifindex, ifname, sizeof(ifname));
}

char *dev_name_dup(const struct teamd_context *ctx, uint32_t ifindex)
{
	char *ifname = dev_name(ctx, ifindex);

	if (!ifname)
		return NULL;
	return strdup(ifname);
}

static const struct teamd_runner *teamd_runner_list[] = {
	&teamd_runner_dummy,
	&teamd_runner_roundrobin,
	&teamd_runner_activebackup,
};

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
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
            "    -D --dbus-enable         Enable D-Bus interface\n",
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
		{ "dbus-enable",	no_argument,		NULL, 'D' },
		{ NULL, 0, NULL, 0 }
	};

	while ((opt = getopt_long(argc, argv, "hdkevf:c:p:grt:D",
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
			if (!ctx->config_file)
				fprintf(stderr, "Failed to get absolute path of \"%s\": %s\n",
					optarg, strerror(errno));
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
			ctx->debug = true;
			break;
		case 'r':
			ctx->force_recreate = true;
			break;
		case 't':
			free(ctx->team_devname);
			ctx->team_devname = strdup(optarg);
			break;
		case 'D':
			ctx->dbus.enabled = true;
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

static void handle_period_fd(int fd)
{
	ssize_t ret;
	uint64_t exp;

	ret = read(fd, &exp, sizeof(uint64_t));
	if (ret == -1) {
		if (errno == EINTR || errno == EAGAIN)
			return;
		teamd_log_err("read() failed.");
		return;
	}
	if (ret != sizeof(uint64_t)) {
		teamd_log_err("read() returned unexpected number of bytes.");
		return;
	}
	if (exp > 1)
		teamd_log_warn("some periodic function calls missed (%" PRIu64 ")",
			       exp - 1);
}

struct teamd_loop_callback {
	struct list_item list;
	char *name;
	teamd_loop_callback_func_t func;
	void *func_priv;
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

static void teamd_run_loop_do_callbacks(struct list_item *lcb_list, fd_set *fds,
					struct teamd_context *ctx)
{
	struct teamd_loop_callback *lcb;
	int i;
	int events;

	list_for_each_node_entry(lcb, lcb_list, list) {
		for (i = 0; i < 3; i++) {
			if (lcb->fd_event& (1 << i)) {
				events = 0;
				if (FD_ISSET(lcb->fd, &fds[i]))
					events |= (1 << i);
				if (events) {
					if (lcb->is_period)
						handle_period_fd(lcb->fd);
					lcb->func(ctx, events, lcb->func_priv);
				}
			}
		}
	}
}

static int teamd_run_loop_run(struct teamd_context *ctx)
{
	int err;
	int ctrl_fd = ctx->run_loop.ctrl_pipe_r;
	fd_set fds[3];
	int fdmax;
	char ctrl_byte;
	int i;

	while (true) {
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
					return ctx->run_loop.err;
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

		teamd_run_loop_do_callbacks(&ctx->run_loop.callback_list,
					    fds, ctx);
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

static int get_timerfd(int *pfd, time_t i_sec, long i_nsec,
		       time_t v_sec, long v_nsec)
{
	int fd;
	struct itimerspec its;

	its.it_interval.tv_sec = i_sec;
	its.it_interval.tv_nsec = i_nsec;
	its.it_value.tv_sec = v_sec;
	its.it_value.tv_nsec = v_nsec;

	fd = timerfd_create(CLOCK_MONOTONIC, 0);
	if (fd < 0) {
		teamd_log_err("Failed to create timerfd.");
		return -errno;
	}
	*pfd = fd;
	if (timerfd_settime(fd, 0, &its, NULL) < 0) {
		teamd_log_err("Failed to set timerfd.");
		close(fd);
		return -errno;
	}
	return 0;
}

static struct teamd_loop_callback *get_lcb(struct teamd_context *ctx,
					   const char *cb_name)
{
	struct teamd_loop_callback *lcb;

	list_for_each_node_entry(lcb, &ctx->run_loop.callback_list, list)
		if (!strcmp(lcb->name, cb_name))
			return lcb;
	return NULL;
}

int teamd_loop_callback_fd_add(struct teamd_context *ctx,
			       const char *cb_name,
			       int fd, int fd_event,
			       teamd_loop_callback_func_t func,
			       void *func_priv)
{
	int err;
	struct teamd_loop_callback *lcb;

	if (get_lcb(ctx, cb_name)) {
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
	lcb->fd = fd;
	lcb->fd_event = fd_event & TEAMD_LOOP_FD_EVENT_MASK;
	lcb->func = func;
	lcb->func_priv = func_priv;
	list_add(&ctx->run_loop.callback_list, &lcb->list);
	return 0;

lcb_free:
	free(lcb);
	return err;
}

int teamd_loop_callback_timer_add(struct teamd_context *ctx,
				  const char *cb_name,
				  time_t i_sec, long i_nsec,
				  time_t v_sec, long v_nsec,
				  teamd_loop_callback_func_t func,
				  void *func_priv)
{
	int err;
	int fd = fd;

	err = get_timerfd(&fd, i_sec, i_nsec, v_sec, v_nsec);
	if (err)
		return err;
	err = teamd_loop_callback_fd_add(ctx, cb_name, fd,
					 TEAMD_LOOP_FD_EVENT_READ,
					 func, func_priv);
	if (err) {
		close(fd);
		return err;
	}
	get_lcb(ctx, cb_name)->is_period = true;
	return 0;
}

void teamd_loop_callback_del(struct teamd_context *ctx, const char *cb_name)
{
	struct teamd_loop_callback *lcb;

	lcb = get_lcb(ctx, cb_name);
	if (!lcb) {
		teamd_log_dbg("Callback named \"%s\" not found.", cb_name);
		return;
	}
	list_del(&lcb->list);
	teamd_run_loop_restart(ctx);
	if (lcb->is_period)
		close(lcb->fd);
	free(lcb);
	free(lcb->name);
}

int teamd_loop_callback_enable(struct teamd_context *ctx, const char *cb_name)
{
	struct teamd_loop_callback *lcb;

	lcb = get_lcb(ctx, cb_name);
	if (!lcb)
		return -ENOENT;
	lcb->enabled = true;
	teamd_run_loop_restart(ctx);
	return 0;
}

int teamd_loop_callback_disable(struct teamd_context *ctx, const char *cb_name)
{
	struct teamd_loop_callback *lcb;

	lcb = get_lcb(ctx, cb_name);
	if (!lcb)
		return -ENOENT;
	lcb->enabled = false;
	teamd_run_loop_restart(ctx);
	return 0;
}

bool teamd_loop_callback_is_enabled(struct teamd_context *ctx, const char *cb_name)
{
	struct teamd_loop_callback *lcb;

	lcb = get_lcb(ctx, cb_name);
	if (!lcb) {
		teamd_log_dbg("Callback named \"%s\" not found.", cb_name);
		return false;
	}
	return lcb->enabled;
}

static void callback_daemon_signal(struct teamd_context *ctx, int events,
				   void *func_priv)
{
	int sig;

	/* Get signal */
	if ((sig = daemon_signal_next()) <= 0) {
		teamd_log_err("daemon_signal_next() failed.");
		teamd_run_loop_quit(ctx, -errno);
		return;
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
}

static void callback_libteam_event(struct teamd_context *ctx, int events,
				   void *func_priv)
{
	team_process_event(ctx->th);
}

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

	err = teamd_loop_callback_fd_add(ctx, "daemon",
					 daemon_signal_fd(),
					 TEAMD_LOOP_FD_EVENT_READ,
					 callback_daemon_signal, NULL);
	if (err) {
		teamd_log_err("Failed to add daemon loop callback");
		goto close_pipe;
	}

	err = teamd_loop_callback_fd_add(ctx, "libteam_events",
					 team_get_event_fd(ctx->th),
					 TEAMD_LOOP_FD_EVENT_READ,
					 callback_libteam_event, NULL);
	if (err) {
		teamd_log_err("Failed to add libteam event loop callback");
		goto del_daemon_cb;
	}

	teamd_loop_callback_enable(ctx, "daemon");
	teamd_loop_callback_enable(ctx, "libteam_events");

	return 0;

del_daemon_cb:
	teamd_loop_callback_del(ctx, "daemon");
close_pipe:
	close(ctx->run_loop.ctrl_pipe_r);
	close(ctx->run_loop.ctrl_pipe_w);
	return err;
}

static void teamd_run_loop_fini(struct teamd_context *ctx)
{
	teamd_loop_callback_del(ctx, "libteam_events");
	teamd_loop_callback_del(ctx, "daemon");
	close(ctx->run_loop.ctrl_pipe_r);
	close(ctx->run_loop.ctrl_pipe_w);
}

static int config_load(struct teamd_context *ctx)
{
	json_error_t jerror;
	size_t jflags = JSON_REJECT_DUPLICATES;

	if (ctx->config_text) {
		if (ctx->config_file)
			teamd_log_warn("Command line config string is present, ignoring given config file.");
		ctx->config_json = json_loads(ctx->config_text, jflags,
					      &jerror);
	} else if (ctx->config_file) {
		ctx->config_json = json_load_file(ctx->config_file, jflags,
						  &jerror);
	} else {
		teamd_log_err("Either config file or command line config string must be present.");
		return -ENOENT;
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

static int get_port_obj(json_t **pport_obj, struct teamd_context *ctx,
			const char *port_name)
{
	int err;
	json_t *ports_obj;
	json_t *port_obj;

	err = json_unpack(ctx->config_json, "{s:o}", "ports", &ports_obj);
	if (err) {
		ports_obj = json_object();
		if (!ports_obj)
			return -ENOMEM;
		err = json_object_set(ctx->config_json, "ports", ports_obj);
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
	*pport_obj = port_obj;
	return 0;
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
		teamd_log_err("Failed to parse port config string: %s on line %d, column %d",
			      jerror.text, jerror.line, jerror.column);
		return -EIO;
	}
	err = get_port_obj(&port_obj, ctx, port_name);
	if (err) {
		teamd_log_err("Failed to obtain port config object");
		goto new_port_decref;
	}

	/* replace existing object content */
	json_object_clear(port_obj);
	err = json_object_update(port_obj, port_new_obj);
	if (err)
		teamd_log_err("Failed to update existing config port object");
new_port_decref:
	json_decref(port_new_obj);
	return err;
}

static int teamd_add_ports(struct teamd_context *ctx)
{
	int err;
	json_t *ports_obj;
	void *iter;

	err = json_unpack(ctx->config_json, "{s:o}", "ports", &ports_obj);
	if (err) {
		teamd_log_dbg("No ports found in config.");
		return 0;
	}
	for (iter = json_object_iter(ports_obj); iter;
	     iter = json_object_iter_next(ports_obj, iter)) {
		const char *port_name = json_object_iter_key(iter);
		uint32_t ifindex;

		ifindex = team_ifname2ifindex(ctx->th, port_name);
		teamd_log_dbg("Adding port \"%s\" (found ifindex \"%d\").",
			      port_name, ifindex);
		err = team_port_add(ctx->th, ifindex);
		if (err) {
			teamd_log_err("Failed to add port \"%s\".", port_name);
			return err;
		}
	}
	return 0;
}

static int teamd_runner_init(struct teamd_context *ctx)
{
	int err;
	const char *runner_name;

	err = json_unpack(ctx->config_json, "{s:s}", "runner", &runner_name);
	if (err) {
		teamd_log_err("Failed to get team runner name from config.");
		return err;
	}
	teamd_log_dbg("Using team runner \"%s\".", runner_name);
	ctx->runner = teamd_find_runner(runner_name);
	if (!ctx->runner) {
		teamd_log_err("No runner named \"%s\" available.", runner_name);
		return -ENOENT;
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

	if (ctx->runner->init) {
		err = ctx->runner->init(ctx);
		if (err) {
			free(ctx->runner_priv);
			return err;
		}
	}
	return 0;
}

static void teamd_runner_fini(struct teamd_context *ctx)
{
	if (ctx->runner->fini)
		ctx->runner->fini(ctx);
	free(ctx->runner_priv);
}

struct port_priv_item {
	struct list_item list;
	uint32_t ifindex;
	bool to_be_removed;
	long priv[0];
};

static struct port_priv_item *get_ppitem(struct teamd_context *ctx,
					 uint32_t ifindex)
{
	struct port_priv_item *ppitem;
	size_t alloc_size;

	list_for_each_node_entry(ppitem, &ctx->runner_port_priv_list, list) {
		if (ppitem->ifindex == ifindex)
			return ppitem;
	}

	alloc_size = sizeof(*ppitem) + ctx->runner->port_priv_size;
	ppitem = myzalloc(alloc_size);
	if (!ppitem) {
		teamd_log_err("Failed to alloc port priv (ifindex %d).",
			       ifindex);
		return NULL;
	}
	ppitem->ifindex = ifindex;
	list_add(&ctx->runner_port_priv_list, &ppitem->list);
	return ppitem;
}

void *teamd_get_runner_port_priv(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	ppitem = get_ppitem(ctx, ifindex);
	if (!ppitem)
		return NULL;
	return &ppitem->priv;
}

static void check_ppitems_to_be_removed(struct teamd_context *ctx, bool killall)
{
	struct port_priv_item *ppitem, *tmp;

	list_for_each_node_entry_safe(ppitem, tmp,
				      &ctx->runner_port_priv_list, list) {
		if (killall || ppitem->to_be_removed) {
			list_del(&ppitem->list);
			free(ppitem);
		}
	}
}

static void teamd_free_port_privs(struct teamd_context *ctx)
{
	check_ppitems_to_be_removed(ctx, true);
}

static void port_priv_change_handler_func(struct team_handle *th, void *arg,
					  team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_port *port;
	struct port_priv_item *ppitem;

	check_ppitems_to_be_removed(ctx, false);

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		ppitem = get_ppitem(ctx, ifindex);
		if (!ppitem)
			continue;
		if (team_is_port_removed(port))
			ppitem->to_be_removed = true;
	}
}

static struct team_change_handler port_priv_change_handler = {
	.func = port_priv_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE,
};

static void debug_log_port_list(struct teamd_context *ctx)
{
	struct team_port *port;

	teamd_log_dbg("<port_list>");
	team_for_each_port(port, ctx->th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		teamd_log_dbg("%d: %s: %s %u %s%s%s", ifindex,
			      dev_name(ctx, ifindex),
			      team_is_port_link_up(port) ? "up": "down",
			      team_get_port_speed(port),
			      team_get_port_duplex(port) ? "fullduplex" : "halfduplex",
			      team_is_port_changed(port) ? " changed" : "",
			      team_is_port_removed(port) ? " removed" : "");
	}
	teamd_log_dbg("</port_list>");
}

static void debug_log_option_list(struct teamd_context *ctx)
{
	struct team_option *option;

	teamd_log_dbg("<option_list>");
	team_for_each_option(option, ctx->th) {
		char *name = team_get_option_name(option);
		bool changed = team_is_option_changed(option);

		switch (team_get_option_type(option)) {
		case TEAM_OPTION_TYPE_U32:
			teamd_log_dbg("%s: \"%d\" <int>%s", name,
				      team_get_option_value_u32(option),
				      changed ? " changed" : "");
			break;
		case TEAM_OPTION_TYPE_STRING:
			teamd_log_dbg("%s: \"%s\" <str>%s", name,
				      team_get_option_value_string(option),
				      changed ? " changed" : "");
			break;
		default:
			teamd_log_dbg("%s: <unknown>%s", name,
				      changed ? " changed" : "");
		}
	}
	teamd_log_dbg("</option_list>");
}

static void debug_change_handler_func(struct team_handle *th, void *arg,
				      team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);

	if (type_mask & TEAM_PORT_CHANGE)
		debug_log_port_list(ctx);
	if (type_mask & TEAM_OPTION_CHANGE)
		debug_log_option_list(ctx);
}

static struct team_change_handler debug_change_handler = {
	.func = debug_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE,
};

static int teamd_register_default_handlers(struct teamd_context *ctx)
{
	int err;

	err = team_change_handler_register(ctx->th, &port_priv_change_handler);
	if (err)
		return err;

	if (!ctx->debug)
		return 0;
	err = team_change_handler_register(ctx->th, &debug_change_handler);
	if (err)
		goto unreg_port_priv_handler;
	return 0;

unreg_port_priv_handler:
	team_change_handler_unregister(ctx->th, &port_priv_change_handler);

	return err;
}

static void teamd_unregister_default_handlers(struct teamd_context *ctx)
{
	if (ctx->debug)
		team_change_handler_unregister(ctx->th, &debug_change_handler);
	team_change_handler_unregister(ctx->th, &port_priv_change_handler);
}

static int teamd_init(struct teamd_context *ctx)
{
	int err;
	const char *team_name;

	list_init(&ctx->runner_port_priv_list);
	err = config_load(ctx);
	if (err) {
		teamd_log_err("Failed to load config.");
		return err;
	}

	if (!ctx->team_devname) {
		err = json_unpack(ctx->config_json, "{s:s}", "device", &team_name);
		if (err) {
			teamd_log_err("Failed to get team device name.");
			err = -EINVAL;
			goto config_free;
		}
		ctx->team_devname = strdup(team_name);
		if (!ctx->team_devname) {
			teamd_log_err("Failed allocate memory for device name.");
			err = -ENOMEM;
			goto config_free;
		}
	} else {
		team_name = ctx->team_devname;
	}
	teamd_log_dbg("Using team device \"%s\".", team_name);

	ctx->th = team_alloc();
	if (!ctx->th) {
		teamd_log_err("Team alloc failed.");
		err = -ENOMEM;
		goto config_free;
	}
	if (ctx->debug)
		team_set_log_priority(ctx->th, LOG_DEBUG);

	team_set_log_fn(ctx->th, libteam_log_daemon);

	if (ctx->force_recreate)
		err = team_recreate(ctx->th, team_name);
	else
		err = team_create(ctx->th, team_name);
	if (err) {
		teamd_log_err("Failed to create team device.");
		goto team_free;
	}

	ctx->ifindex = team_ifname2ifindex(ctx->th, team_name);
	if (!ctx->ifindex) {
		teamd_log_err("Netdevice \"%s\" not found.", team_name);
		err = -ENOENT;
		goto team_destroy;
	}

	err = team_init(ctx->th, ctx->ifindex);
	if (err) {
		teamd_log_err("Team init failed.");
		goto team_destroy;
	}

	team_set_user_priv(ctx->th, ctx);

	ctx->hwaddr_len = team_hwaddr_len_get(ctx->th, ctx->ifindex);
	if (ctx->hwaddr_len < 0) {
		teamd_log_err("Failed to get hardware address length.");
		err = ctx->hwaddr_len;
		goto team_destroy;
	}

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

	err = teamd_runner_init(ctx);
	if (err) {
		teamd_log_err("Failed to init runner.");
		goto team_unreg_debug_handlers;
	}

	err = teamd_dbus_init(ctx);
	if (err) {
		teamd_log_err("Failed to init dbus.");
		goto runner_fini;
	}

	err = teamd_add_ports(ctx);
	if (err) {
		teamd_log_err("Failed to add ports.");
		goto dbus_fini;
	}

	return 0;

dbus_fini:
	teamd_dbus_fini(ctx);
runner_fini:
	teamd_runner_fini(ctx);
team_unreg_debug_handlers:
	teamd_unregister_default_handlers(ctx);
run_loop_fini:
	teamd_run_loop_fini(ctx);
team_destroy:
	team_destroy(ctx->th);
team_free:
	team_free(ctx->th);
config_free:
	config_free(ctx);
	teamd_free_port_privs(ctx);
	return err;
}

static void teamd_fini(struct teamd_context *ctx)
{
	teamd_dbus_fini(ctx);
	teamd_runner_fini(ctx);
	teamd_unregister_default_handlers(ctx);
	teamd_run_loop_fini(ctx);
	team_destroy(ctx->th);
	team_free(ctx->th);
	config_free(ctx);
	teamd_free_port_privs(ctx);
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
		goto finish;

	if (ctx->debug)
		daemon_set_verbosity(LOG_DEBUG);

	ctx->argv0 = daemon_ident_from_argv0(argv[0]);
	daemon_log_ident = ctx->argv0;
	daemon_pid_file_ident = ctx->argv0;

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
			teamd_log_err("Failed to start daemon: %s", strerror(-err));
		else
			ret = EXIT_SUCCESS;
		break;
	}

finish:

	teamd_context_fini(ctx);
	return ret;
}
