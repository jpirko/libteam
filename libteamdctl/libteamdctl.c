/*
 *   libteamdctl.c - Teamd daemon control library
 *   Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <private/misc.h>
#include <teamdctl.h>
#include "teamdctl_private.h"

/**
 * SECTION: logging
 * @short_description: libteamdctl logging facility
 */
void teamdctl_log(struct teamdctl *tdc, int priority,
		  const char *file, int line, const char *fn,
		  const char *format, ...)
{
	va_list args;

	va_start(args, format);
	tdc->log_fn(tdc, priority, file, line, fn, format, args);
	va_end(args);
}

static void log_stderr(struct teamdctl *tdc, int priority,
		       const char *file, int line, const char *fn,
		       const char *format, va_list args)
{
	fprintf(stderr, "libteamdctl: %s: ", fn);
	vfprintf(stderr, format, args);
	fprintf(stderr, "\n");
}

static int log_priority(const char *priority)
{
	char *endptr;
	int prio;

	prio = strtol(priority, &endptr, 10);
	if (endptr[0] == '\0' || isspace(endptr[0]))
		return prio;
	if (strncmp(priority, "err", 3) == 0)
		return LOG_ERR;
	if (strncmp(priority, "info", 4) == 0)
		return LOG_INFO;
	if (strncmp(priority, "debug", 5) == 0)
		return LOG_DEBUG;
	return 0;
}

/**
 * SECTION: Context functions
 * @short_description: Core context functions
 */

/**
 * teamdctl_alloc:
 *
 * Allocates library context and does initial setup.
 *
 * Returns: new libteam library context
 **/
TEAMDCTL_EXPORT
struct teamdctl *teamdctl_alloc(void)
{
	struct teamdctl *tdc;
	const char *env;

	tdc = myzalloc(sizeof(*tdc));
	if (!tdc)
		return NULL;

	tdc->log_fn = log_stderr;
	tdc->log_priority = LOG_ERR;
	/* environment overwrites config */
	env = getenv("TEAMDCTL_LOG");
	if (env != NULL)
		teamdctl_set_log_priority(tdc, log_priority(env));

	dbg(tdc, "teamdctl %p created.", tdc);
	dbg(tdc, "log_priority=%d", tdc->log_priority);
	return tdc;
}

/**
 * teamdctl_free:
 * @tdc: libteam library context
 *
 * Do library context cleanup.
 *
 **/
TEAMDCTL_EXPORT
void teamdctl_free(struct teamdctl *tdc)
{
	free(tdc);
}

/**
 * teamdctl_set_log_fn:
 * @tdc: libteamdctl library context
 * @log_fn: function to be called for logging messages
 *
 * The built-in logging writes to stderr. It can be
 * overridden by a custom function, to plug log messages
 * into the user's logging functionality.
 *
 **/
TEAMDCTL_EXPORT
void teamdctl_set_log_fn(struct teamdctl *tdc,
			 void (*log_fn)(struct teamdctl *tdc, int priority,
					const char *file, int line,
					const char *fn, const char *format,
					va_list args))
{
	tdc->log_fn = log_fn;
	dbg(tdc, "Custom logging function %p registered.", log_fn);
}

/**
 * teamdctl_get_log_priority:
 * @tdc: libteamdctl library context
 *
 * Returns: the current logging priority
 **/
TEAMDCTL_EXPORT
int teamdctl_get_log_priority(struct teamdctl *tdc)
{
	return tdc->log_priority;
}

/**
 * teamdctl_set_log_priority:
 * @tdc: libteamdctl library context
 * @priority: the new logging priority
 *
 * Set the current logging priority. The value controls which messages
 * are logged.
 **/
TEAMDCTL_EXPORT
void teamdctl_set_log_priority(struct teamdctl *tdc, int priority)
{
	tdc->log_priority = priority;
}

static const struct teamdctl_cli *teamdctl_cli_list[] = {
	&teamdctl_cli_usock,
	&teamdctl_cli_dbus,
};

#define TEAMDCTL_CLI_LIST_SIZE ARRAY_SIZE(teamdctl_cli_list)

static int cli_init(struct teamdctl *tdc, const char *team_name,
		    const struct teamdctl_cli *cli)
{
	int err;

	if (cli->priv_size) {
		tdc->cli.priv = myzalloc(cli->priv_size);
		if (!tdc->cli.priv)
			return -ENOMEM;
	}
	err = cli->init(tdc, team_name, tdc->cli.priv);
	if (err) {
		if (cli->priv_size)
			free(tdc->cli.priv);
		return err;
	}
	tdc->cli.cli = cli;
	return 0;
}

static void cli_fini(struct teamdctl *tdc)
{
	tdc->cli.cli->fini(tdc, tdc->cli.priv);
	free(tdc->cli.priv);
}

/**
 * teamdctl_connect:
 * @tdc: libteamdctl library context
 * @team_name: team device name
 * @cli_type: client type
 *
 * Connect to teamd instance controlling team driver instance with interface
 * name @team_name. Use client type @cli_type to connect. That can be either
 * "dbus" for connection over D-Bus, "usock" which will use unix domain socket
 * or NULL to select the type automatically.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_connect(struct teamdctl *tdc, const char *team_name,
		     const char *cli_type)
{
	int err = -EINVAL;
	int i;

	for (i = 0; i < TEAMDCTL_CLI_LIST_SIZE; i++) {
		const struct teamdctl_cli *cli = teamdctl_cli_list[i];

		if (cli_type && strcmp(cli_type, cli->name))
			continue;
		err = cli_init(tdc, team_name, cli);
		if (cli_type) {
			if (err) {
				err(tdc, "Failed to connect using CLI \"%s\".",
				    cli->name);
				return err;
			}
			return 0;
		} else if (err) {
			dbg(tdc, "Failed to connect using CLI \"%s\".",
			    cli->name);
		} else {
			dbg(tdc, "Connected using CLI \"%s\".", cli->name);
			return 0;
		}
	}
	if (!cli_type && i == TEAMDCTL_CLI_LIST_SIZE) {
		err(tdc, "Failed to connect using all CLIs.");
		return err;
	}
	return 0;
}

/**
 * teamdctl_disconnect:
 * @tdc: libteamdctl library context
 *
 * Disconnect from teamd instance.
 **/
TEAMDCTL_EXPORT
void teamdctl_disconnect(struct teamdctl *tdc)
{
	cli_fini(tdc);
}
