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

/**
 * @defgroup libteamdctl Libteamdctl
 * Teamd daemon control library
 *
 * @{
 *
 * Header
 * ------
 * ~~~~{.c}
 * #include <teamdctl.h>
 * ~~~~
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <syslog.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <private/misc.h>
#include <private/list.h>
#include <teamdctl.h>

#include "config.h"
#include "teamdctl_private.h"

/**
 * SECTION: logging
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
 * SECTION: reply cache
 */

static void reply_cache_clean(struct teamdctl *tdc)
{
	struct teamdctl_reply_cache_item *rcitem;
	struct teamdctl_reply_cache_item *tmp;

	list_for_each_node_entry_safe(rcitem, tmp,
				      &tdc->reply_cache_list, list) {
		list_del(&rcitem->list);
		free(rcitem->reply);
		free(rcitem);
	}
}

static void replace_str(char **p_str, char *new)
{
	if (*p_str)
		free(*p_str);
	*p_str = new;
}

static struct teamdctl_reply_cache_item *find_rcitem(struct teamdctl *tdc,
						     const char *id)
{
	struct teamdctl_reply_cache_item *rcitem;

	list_for_each_node_entry(rcitem, &tdc->reply_cache_list, list) {
		if (!strcmp(rcitem->id, id))
			return rcitem;
	}
	return NULL;
}

static char *reply_cache_query(struct teamdctl *tdc, const char *id)
{
	struct teamdctl_reply_cache_item *rcitem;

	rcitem = find_rcitem(tdc, id);
	if (rcitem)
		return rcitem->reply;
	return NULL;
}

static char *reply_cache_update(struct teamdctl *tdc, const char *id,
				char *reply)
{
	struct teamdctl_reply_cache_item *rcitem;

	rcitem = find_rcitem(tdc, id);
	if (rcitem)
		goto skip_create;

	rcitem = myzalloc(sizeof(*rcitem) + strlen(id) + 1);
	if (!rcitem) {
		free(reply);
		return NULL;
	}
	strcpy(rcitem->id, id);
	list_add_tail(&tdc->reply_cache_list, &rcitem->list);

skip_create:
	replace_str(&rcitem->reply, reply);
	return reply;
}

/**
 * @details Allocates library context and does initial setup.
 *
 * @return New libteam library context.
 **/
TEAMDCTL_EXPORT
struct teamdctl *teamdctl_alloc(void)
{
	struct teamdctl *tdc;
	const char *env;

	tdc = myzalloc(sizeof(*tdc));
	if (!tdc)
		return NULL;

	list_init(&tdc->reply_cache_list);
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
 * @param tdc		libteam library context
 *
 * @details Do library context cleanup.
 **/
TEAMDCTL_EXPORT
void teamdctl_free(struct teamdctl *tdc)
{
	reply_cache_clean(tdc);
	free(tdc);
}

/**
 * @param tdc		libteamdctl library context
 * @param log_fn	function to be called for logging messages
 *
 * @details The built-in logging writes to stderr. It can be overridden
 *	    by a custom function, to plug log messages into the user's
 *	    logging functionality.
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
 * @param tdc		libteamdctl library context
 *
 * @return The current logging priority.
 **/
TEAMDCTL_EXPORT
int teamdctl_get_log_priority(struct teamdctl *tdc)
{
	return tdc->log_priority;
}

/**
 * @param tdc		libteamdctl library context
 * @param priority	the new logging priority
 *
 * @details Set the current logging priority. The value controls which messages
 *	    are logged.
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
 * @param tdc		libteamdctl library context
 * @param team_name	team device name
 * @param addr		address (for zeromq only)
 * @param cli_type	client type
 *
 * @details Connect to teamd instance controlling team driver instance
 *	    with interface name team_name. Use client type cli_type to connect.
 *	    That can be either "dbus" for connection over D-Bus, "usock" which
 *	    will use unix domain socket or NULL to select the type
 *	    automatically.
 *
 * @return Zero on success or negative number in case of an error.
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
 * @param tdc		libteamdctl library context
 *
 * @details Disconnect from teamd instance.
 **/
TEAMDCTL_EXPORT
void teamdctl_disconnect(struct teamdctl *tdc)
{
	cli_fini(tdc);
	tdc->cli = NULL;
}


static int cache_config(struct teamdctl *tdc, const char *id, char **p_reply)
{
	int err;
	char *reply;

	err = cli_method_call(tdc, id, &reply, "");
	if (err)
		return err;
	reply = reply_cache_update(tdc, id, reply);
	if (!reply)
		return -ENOMEM;
	if (p_reply)
		*p_reply = reply;
	return 0;
}

/**
 * @param tdc		libteamdctl library context
 *
 * @details Refresh cache.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_refresh(struct teamdctl *tdc)
{
	int err;

	err = cache_config(tdc, "ConfigDump", NULL);
	if (err)
		return err;
	err = cache_config(tdc, "ConfigDumpActual", NULL);
	if (err)
		return err;
	err = cache_config(tdc, "StateDump", NULL);
	if (err)
		return err;
	return 0;
}

/**
 * @param tdc		libteamdctl library context
 * @param port_devname	port device name
 *
 * @details Adds specified port to team.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_add(struct teamdctl *tdc, const char *port_devname)
{
	return cli_method_call(tdc, "PortAdd", NULL, "s", port_devname);
}

/**
 * @param tdc		libteamdctl library context
 * @param port_devname	port device name
 *
 * @details Removes specified port from team.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_remove(struct teamdctl *tdc, const char *port_devname)
{
	return cli_method_call(tdc, "PortRemove", NULL, "s", port_devname);
}

/**
 * @param tdc			libteamdctl library context
 * @param port_devname		port device name
 * @param port_config_raw	port config
 *
 * @details Update config for specified port.
 *
 * @return Zero on success or negative number in case of an error.
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
 * @param tdc		libteamdctl library context
 * @param port_devname	port device name
 * @param p_cfg		pointer to string which will be set
 *
 * @details Gets raw port config string.
 *	    Does direct method call avoiding possible stale data in the cache.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_port_config_get_raw_direct(struct teamdctl *tdc,
					const char *port_devname,
					char **p_cfg)
{
	int err;
	char *reply;
#define PC_ID_PREFIX "_portcnf_"
	char id[sizeof(PC_ID_PREFIX) + IFNAMSIZ + 1];

	if (strlen(port_devname) > IFNAMSIZ)
		return -EINVAL;
	err = cli_method_call(tdc, "PortConfigDump", &reply, "s", port_devname);
	if (err)
		return err;
	sprintf(id, "%s%s", PC_ID_PREFIX, port_devname);
	reply = reply_cache_update(tdc, id, reply);
	if (!reply)
		return -ENOMEM;
	if (p_cfg)
		*p_cfg = reply;
	return 0;
}

/**
 * @param tdc		libteamdctl library context
 *
 * @details Gets raw config string.
 *	    Using reply cache. Return value is never NULL.
 *	    To refresh the cache, use teamdctl_refresh function.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * Return Pointer to cached config string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_config_get_raw(struct teamdctl *tdc)
{
	return reply_cache_query(tdc, "ConfigDump");
}

/**
 * @param tdc		libteamdctl library context
 * @param p_cfg		pointer to string which will be set
 *
 * @details Gets raw config string.
 *	    Does direct method call avoiding possible stale data in the cache.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_config_get_raw_direct(struct teamdctl *tdc, char **p_cfg)
{
	return cache_config(tdc, "ConfigActual", p_cfg);
}

/**
 * @param tdc		libteamdctl library context
 *
 * @details Gets raw actual config string.
 *	    Using reply cache. Return value is never NULL.
 *	    To refresh the cache, use teamdctl_refresh function.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Pointer to cached actual config string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_config_actual_get_raw(struct teamdctl *tdc)
{
	return reply_cache_query(tdc, "ConfigDumpActual");
}

/**
 * @param tdc		libteamdctl library context
 * @param p_cfg		pointer to string which will be set
 *
 * @details Gets raw actual config string.
 *	    Does direct method call avoiding possible stale data in the cache.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_config_actual_get_raw_direct(struct teamdctl *tdc, char **p_cfg)
{
	return cache_config(tdc, "ConfigDumpActual", p_cfg);
}

/**
 * @param tdc		libteamdctl library context
 *
 * @details Gets raw state string.
 *	    Using reply cache. Return value is never NULL.
 *	    To refresh the cache, use teamdctl_refresh function.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Pointer to cached state string.
 **/
TEAMDCTL_EXPORT
char *teamdctl_state_get_raw(struct teamdctl *tdc)
{
	return reply_cache_query(tdc, "StateDump");
}

/**
 * @param tdc		libteamdctl library context
 * @param p_cfg		pointer to string which will be set
 *
 * @details Gets raw state string.
 *	    Does direct method call avoiding possible stale data in the cache.
 *	    Note: the obtained string should not be modified or freed by caller.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_state_get_raw_direct(struct teamdctl *tdc, char **p_cfg)
{
	return cache_config(tdc, "StateDump", p_cfg);
}

/**
 * @param tdc		libteamdctl library context
 * @param item_path	path to item
 * @param p_value	pointer where reply string will be stored
 *
 * @details Get state item value. Note that caller is responsible to
 *	    free *p_value.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_state_item_value_get(struct teamdctl *tdc, const char *item_path,
				  char **p_value)
{
	return cli_method_call(tdc, "StateItemValueGet", p_value,
			       "s", item_path);
}
/**
 * @param tdc		libteamdctl library context
 * @param item_path	path to item
 * @param value		new value to be set
 *
 * @details Set state item value.
 *
 * @return Zero on success or negative number in case of an error.
 **/
TEAMDCTL_EXPORT
int teamdctl_state_item_value_set(struct teamdctl *tdc, const char *item_path,
				  const char *value)
{
	return cli_method_call(tdc, "StateItemValueSet", NULL,
			       "ss", item_path, value);
}

/**
 * @}
 */
