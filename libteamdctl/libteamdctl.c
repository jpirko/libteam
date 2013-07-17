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

#include "config.h"
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
	free(tdc->cached_reply.config);
	free(tdc->cached_reply.config_actual);
	free(tdc->cached_reply.state);
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

static int cli_method_call(struct teamdctl *tdc, const char *method_name,
			   char **p_reply, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = tdc->cli->method_call(tdc, method_name, p_reply,
				    tdc->cli_priv, fmt, ap);
	va_end(ap);
	return err;
}

static int cli_init(struct teamdctl *tdc, const char *team_name)
{
	int err;

	if (tdc->cli->priv_size) {
		tdc->cli_priv = myzalloc(tdc->cli->priv_size);
		if (!tdc->cli_priv)
			return -ENOMEM;
	}
	err = tdc->cli->init(tdc, team_name, tdc->cli_priv);
	if (err)
		goto free_priv;
	if (tdc->cli->test_method_call_required) {
		err = cli_method_call(tdc, "ConfigDump", NULL, "");
		if (err)
			goto free_priv;
	}
	return 0;
free_priv:
	if (tdc->cli->priv_size)
		free(tdc->cli_priv);
	return err;
}

static void cli_fini(struct teamdctl *tdc)
{
	tdc->cli->fini(tdc, tdc->cli_priv);
	free(tdc->cli_priv);
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
		     const char *addr, const char *cli_type)
{
	int err;
	int i;
	const struct teamdctl_cli *teamdctl_cli_list[] = {
		teamdctl_cli_usock_get(),
#ifdef ENABLE_DBUS
		teamdctl_cli_dbus_get(),
#endif
#ifdef ENABLE_ZMQ
		teamdctl_cli_zmq_get(),
#endif
	};
#define TEAMDCTL_CLI_LIST_SIZE ARRAY_SIZE(teamdctl_cli_list)

	if (tdc->cli)
		return -EBUSY;

	for (i = 0; i < TEAMDCTL_CLI_LIST_SIZE; i++) {
		const struct teamdctl_cli *cli = teamdctl_cli_list[i];
		int orig_log_prio = teamdctl_get_log_priority(tdc);

		if (cli_type && strcmp(cli_type, cli->name))
			continue;
		tdc->cli = cli;

		/* In case cli_type is not specified, we will try to connect
		 * using all avaivable clis. Once some of the cli connects,
		 * it will be selected. In that case, silence error messages
		 * that can appear during cli init by setting log priority to
		 * LOG_EMERG.
		 */
		if (!cli_type && orig_log_prio < LOG_DEBUG)
			teamdctl_set_log_priority(tdc, LOG_EMERG);

		tdc->addr = (char *) addr;

		err = cli_init(tdc, team_name);

		/* restore original log priority */
		teamdctl_set_log_priority(tdc, orig_log_prio);

		if (!err)
			break; /* usable cli found */

		if (cli_type) {
			err(tdc, "Failed to connect using CLI \"%s\".",
			    cli->name);
			goto err_out;
		}
	}
	if (i == TEAMDCTL_CLI_LIST_SIZE) {
		if (!cli_type)
			err(tdc, "Failed to connect using all CLIs.");
		else
			err(tdc, "Failed to connect using unknown CLI \"%s\".",
				 cli_type);
		err = -EINVAL;
		goto err_out;
	}

	dbg(tdc, "Connected using CLI \"%s\".", tdc->cli->name);

	err = teamdctl_refresh(tdc);
	if (err)
		goto err_out;
	return 0;
err_out:
	tdc->cli = NULL;
	return err;
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
	tdc->cli = NULL;
}

static void replace_str(char **p_str, char *new)
{
	if (*p_str)
		free(*p_str);
	*p_str = new;
}

TEAMDCTL_EXPORT
int teamdctl_refresh(struct teamdctl *tdc)
{
	char *reply;
	int err;

	err = cli_method_call(tdc, "ConfigDump", &reply, "");
	if (err)
		return err;
	replace_str(&tdc->cached_reply.config, reply);
	err = cli_method_call(tdc, "ConfigDumpActual", &reply, "");
	if (err)
		return err;
	replace_str(&tdc->cached_reply.config_actual, reply);
	err = cli_method_call(tdc, "StateDump", &reply, "");
	if (err)
		return err;
	replace_str(&tdc->cached_reply.state, reply);
	return 0;
}

/**
 * teamdctl_port_add:
 * @tdc: libteamdctl library context
 * @port_devname: port device name
 *
 * Adds specified port to team.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_add(struct teamdctl *tdc, const char *port_devname)
{
	return cli_method_call(tdc, "PortAdd", NULL, "s", port_devname);
}

/**
 * teamdctl_port_remove:
 * @tdc: libteamdctl library context
 * @port_devname: port device name
 *
 * Removes specified port from team.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_remove(struct teamdctl *tdc, const char *port_devname)
{
	return cli_method_call(tdc, "PortRemove", NULL, "s", port_devname);
}

/**
 * teamdctl_port_config_update_raw:
 * @tdc: libteamdctl library context
 * @port_devname: port device name
 * @port_config_raw: port config
 *
 * Update config for specified port.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_config_update_raw(struct teamdctl *tdc,
				    const char *port_devname,
				    const char *port_config_raw)
{
	return cli_method_call(tdc, "PortConfigUpdate", NULL,
			       "ss", port_devname, port_config_raw);
}

/**
 * teamdctl_config_get_raw:
 * @tdc: libteamdctl library context
 *
 * Gets raw config string.
 *
 * Returns: pointer to cached config string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_config_get_raw(struct teamdctl *tdc)
{
	return tdc->cached_reply.config;
}

/**
 * teamdctl_config_actual_get_raw:
 * @tdc: libteamdctl library context
 *
 * Gets raw actual config string.
 *
 * Returns: pointer to cached actual config string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_config_actual_get_raw(struct teamdctl *tdc)
{
	return tdc->cached_reply.config_actual;
}

/**
 * teamdctl_state_get_raw:
 * @tdc: libteamdctl library context
 *
 * Gets raw state string.
 *
 * Returns: pointer to cached state string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_state_get_raw(struct teamdctl *tdc)
{
	return tdc->cached_reply.state;
}

/**
 * teamdctl_state_item_value_get:
 * @tdc: libteamdctl library context
 * @item_path: path to item
 * @p_value: pointer where reply string will be stored
 *
 * Get state item value. Note that caller is responsible to free *p_value.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_state_item_value_get(struct teamdctl *tdc, const char *item_path,
				  char **p_value)
{
	return cli_method_call(tdc, "StateItemValueGet", p_value,
			       "s", item_path);
}
/**
 * teamdctl_state_item_value_set:
 * @tdc: libteamdctl library context
 * @item_path: path to item
 * @value: new value to be set
 *
 * Set state item value.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_state_item_value_set(struct teamdctl *tdc, const char *item_path,
				  const char *value)
{
	return cli_method_call(tdc, "StateItemValueSet", NULL,
			       "ss", item_path, value);
}
