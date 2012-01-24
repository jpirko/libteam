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
#include <libdaemon/dlog.h>
#include <sys/types.h>
#include <json/json.h>
#include <team.h>

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

struct teamd_context {
	enum teamd_command	cmd;
	bool			daemonize;
	bool			debug;
	bool			force_recreate;
	char *			config_file;
	char *			config_text;
	json_object *		config_jso;
	char *			pid_file;
	char *			argv0;
	struct team_handle *	th;
	const struct teamd_runner *	runner;
	void *			runner_priv;
	uint32_t		ifindex;
	uint32_t		hwaddr_len;
	struct team_change_handler	debug_change_handler;
};

struct teamd_runner {
	const char *name;
	const char *team_mode_name;
	size_t priv_size;
	int (*init)(struct teamd_context *ctx);
	void (*fini)(struct teamd_context *ctx);
};

#define teamd_for_each_port(i, cur, ctx)	\
	for (i = 0; teamd_cfg_get_str(ctx, &cur, "['ports'][%d]", i) == 0; i++)

/* Runner structures */
const struct teamd_runner teamd_runner_dummy;
const struct teamd_runner teamd_runner_roundrobin;
const struct teamd_runner teamd_runner_activebackup;

/* Various helpers */
char *dev_name(const struct teamd_context *ctx, uint32_t ifindex);
char *dev_name_dup(const struct teamd_context *ctx, uint32_t ifindex);

#endif /* _TEAMD_H_ */
