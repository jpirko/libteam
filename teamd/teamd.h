/*
 *   teamd.h - Network team device daemon
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

#ifndef _TEAMD_H_
#define _TEAMD_H_

#include <stdbool.h>
#include <stdint.h>
#include <libdaemon/dlog.h>
#include <sys/types.h>
#include <sys/time.h>
#include <jansson.h>
#include <team.h>
#include <private/list.h>
#include <dbus/dbus.h>

#define teamd_log_err(args...) daemon_log(LOG_ERR, ##args)
#define teamd_log_warn(args...) daemon_log(LOG_WARNING, ##args)
#define teamd_log_info(args...) daemon_log(LOG_INFO, ##args)
#define teamd_log_dbg(args...) daemon_log(LOG_DEBUG, ##args)

enum teamd_command {
	DAEMON_CMD_RUN,
	DAEMON_CMD_KILL,
	DAEMON_CMD_VERSION,
	DAEMON_CMD_HELP,
	DAEMON_CMD_CHECK
};

struct teamd_runner;
struct teamd_link_watch;
struct teamd_context;

typedef void (*teamd_link_watch_handler_t)(struct teamd_context *ctx);

struct teamd_context {
	enum teamd_command		cmd;
	bool				daemonize;
	bool				debug;
	bool				force_recreate;
	char *				config_file;
	char *				config_text;
	json_t *			config_json;
	char *				pid_file;
	char *				team_devname;
	char *				argv0;
	struct team_handle *		th;
	const struct teamd_runner *	runner;
	void *				runner_priv;
	const struct teamd_link_watch *	link_watch;
	void *				link_watch_priv;
	teamd_link_watch_handler_t	link_watch_handler;
	struct list_item		port_priv_list;
	uint32_t			ifindex;
	uint32_t			hwaddr_len;
	struct {
		struct list_item		callback_list;
		int				ctrl_pipe_r;
		int				ctrl_pipe_w;
		int				err;
	} run_loop;
	struct {
		bool			enabled;
		DBusConnection *	con;
	} dbus;
};

struct teamd_port {
	uint32_t ifindex;
};

struct teamd_runner {
	const char *name;
	const char *team_mode_name;
	size_t priv_size;
	int (*init)(struct teamd_context *ctx);
	void (*fini)(struct teamd_context *ctx);
	int (*port_added)(struct teamd_context *ctx, uint32_t ifindex, void *runner_port_priv);
	void (*port_removed)(struct teamd_context *ctx, uint32_t ifindex, void *runner_port_priv);
	size_t port_priv_size;
};

struct teamd_link_watch {
	const char *name;
	size_t priv_size;
	int (*init)(struct teamd_context *ctx);
	void (*fini)(struct teamd_context *ctx);
	int (*port_added)(struct teamd_context *ctx, uint32_t ifindex, void *link_watch_port_priv);
	void (*port_removed)(struct teamd_context *ctx, uint32_t ifindex, void *link_watch_port_priv);
	bool (*is_port_up)(struct teamd_context *ctx, uint32_t ifindex);
	size_t port_priv_size;
};

int teamd_update_port_config(struct teamd_context *ctx, const char *port_name,
			     const char *json_port_cfg_str);

/* Main loop callbacks */
#define TEAMD_LOOP_FD_EVENT_READ	(1 << 0)
#define TEAMD_LOOP_FD_EVENT_WRITE	(1 << 1)
#define TEAMD_LOOP_FD_EVENT_EXCEPTION	(1 << 2)
#define TEAMD_LOOP_FD_EVENT_MASK	(TEAMD_LOOP_FD_EVENT_READ | \
					 TEAMD_LOOP_FD_EVENT_WRITE | \
					 TEAMD_LOOP_FD_EVENT_EXCEPTION)

typedef void (*teamd_loop_callback_func_t)(struct teamd_context *ctx,
					   int events, void *func_priv);

int teamd_loop_callback_fd_add(struct teamd_context *ctx,
			       const char *cb_name,
			       int fd, int fd_event,
			       teamd_loop_callback_func_t func,
			       void *func_priv);
int teamd_loop_callback_timer_add(struct teamd_context *ctx,
				  const char *cb_name,
				  time_t i_sec, long i_nsec,
				  time_t v_sec, long v_nsec,
				  teamd_loop_callback_func_t func,
				  void *func_priv);
void teamd_loop_callback_del(struct teamd_context *ctx, const char *cb_name);
int teamd_loop_callback_enable(struct teamd_context *ctx, const char *cb_name);
int teamd_loop_callback_disable(struct teamd_context *ctx, const char *cb_name);
bool teamd_loop_callback_is_enabled(struct teamd_context *ctx, const char *cb_name);
void teamd_run_loop_restart(struct teamd_context *ctx);

/* Runner structures */
const struct teamd_runner teamd_runner_dummy;
const struct teamd_runner teamd_runner_roundrobin;
const struct teamd_runner teamd_runner_activebackup;

/* Link-watch structures */
const struct teamd_link_watch teamd_link_watch_ethtool;

static inline void teamd_link_watch_set_handler(struct teamd_context *ctx,
						teamd_link_watch_handler_t handler)
{
	ctx->link_watch_handler = handler;
}

static inline bool teamd_link_watch_port_up(struct teamd_context *ctx,
					    uint32_t ifindex)
{
	if (ctx->link_watch && ctx->link_watch->is_port_up)
		return ctx->link_watch->is_port_up(ctx, ifindex);
	return true;
}

int teamd_per_port_init(struct teamd_context *ctx);
void teamd_per_port_fini(struct teamd_context *ctx);

void *teamd_get_runner_port_priv(struct teamd_context *ctx, uint32_t ifindex);
void *teamd_get_link_watch_port_priv(struct teamd_context *ctx,
				     uint32_t ifindex);
int teamd_dbus_init(struct teamd_context *ctx);
void teamd_dbus_fini(struct teamd_context *ctx);

/* Various helpers */
char *dev_name(const struct teamd_context *ctx, uint32_t ifindex);
char *dev_name_dup(const struct teamd_context *ctx, uint32_t ifindex);

#endif /* _TEAMD_H_ */
