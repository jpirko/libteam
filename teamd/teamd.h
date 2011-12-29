/*
 * teamd.h - Network team device daemon
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#ifndef _TEAMD_H_
#define _TEAMD_H_

#include <stdbool.h>
#include <libdaemon/dlog.h>
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
};

#endif /* _TEAMD_H_ */
