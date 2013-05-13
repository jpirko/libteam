/*
 *   cli_dbus.c - Teamd daemon control library D-Bus client
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

#ifdef ENABLE_DBUS

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <teamdctl.h>
#include "teamdctl_private.h"
#include "../teamd/teamd_dbus_common.h"

struct cli_dbus_priv {
	DBusConnection *conn;
	char *service_name;
};

static int cli_dbus_check_error_msg(struct teamdctl *tdc, DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;
	const char *err_msg;

	err_msg = dbus_message_get_error_name(msg);
	if (!err_msg)
		return 0;
	err(tdc, "Error message received: \"%s\"", err_msg);

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == TRUE) {
		if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
			err(tdc, "Received argument is not string as expected.");
			return -EINVAL;
		}
		dbus_message_iter_get_basic(&args, &param);
		err(tdc, "Error message content: \"%s\"", param);
	}
	return -EINVAL;
}

static int cli_dbus_get_reply_str(struct teamdctl *tdc, char **p_reply,
				  DBusMessage *msg)
{
	DBusMessageIter args;
	dbus_bool_t dbres;
	char *param = NULL;

	dbres = dbus_message_iter_init(msg, &args);
	if (dbres == FALSE) {
		err(tdc, "Failed, no data received.");
		return -EINVAL;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		err(tdc, "Received argument is not string as expected.");
		return -EINVAL;
	}
	dbus_message_iter_get_basic(&args, &param);
	*p_reply = param;
	return 0;
}

static int cli_dbus_method_call(struct teamdctl *tdc, const char *method_name,
				char **p_reply, void *priv,
				const char *fmt, va_list ap)
{
	struct cli_dbus_priv *cli_dbus = priv;
	char *str;
	DBusMessage *msg;
	DBusMessageIter iter;
	dbus_bool_t dbres;
	DBusPendingCall *pending;
	char *reply;
	int err;

	dbg(tdc, "Calling method \"%s\"", method_name);
	msg = dbus_message_new_method_call(cli_dbus->service_name,
					   TEAMD_DBUS_PATH, TEAMD_DBUS_IFACE,
					   method_name);
	if (!msg) {
		err(tdc, "Failed to create message.");
		return -ENOMEM;
	}
	dbus_message_iter_init_append(msg, &iter);
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			str = va_arg(ap, char *);
			dbres = dbus_message_iter_append_basic(&iter,
							       DBUS_TYPE_STRING,
							       &str);
			if (dbres == FALSE) {
				err(tdc, "Failed to construct message.");
				err = -ENOMEM;
				goto free_msg;
			}
			break;
		default:
			err(tdc, "Unknown argument type requested.");
			err = -EINVAL;
			goto free_msg;
		}
	}

	dbres = dbus_connection_send_with_reply(cli_dbus->conn, msg,
						&pending, TEAMDCTL_REPLY_TIMEOUT);
	if (dbres == FALSE) {
		err(tdc, "Send with reply failed.");
		err = -ENOMEM;
		goto free_msg;
	}
	if (!pending) {
		err(tdc, "Pending call not created.");
		err = -ENOMEM;
		goto free_msg;
	}

	dbus_pending_call_block(pending);

	dbus_message_unref(msg);
	msg = dbus_pending_call_steal_reply(pending);
	dbus_pending_call_unref(pending);
	if (!msg) {
		err(tdc, "Failed to get reply.");
		err = -EINVAL;
		goto out;
	}

	err = cli_dbus_check_error_msg(tdc, msg);
	if (err)
		goto free_msg;

	if (p_reply) {
		err = cli_dbus_get_reply_str(tdc, &reply, msg);
		if (err)
			goto free_msg;

		reply = strdup(reply);
		if (!reply) {
			err = -ENOMEM;
			goto free_msg;
		}
		*p_reply = reply;
	}

free_msg:
	dbus_message_unref(msg);
out:
	return err;
}

static int cli_dbus_introspect(struct teamdctl *tdc,
			       struct cli_dbus_priv *cli_dbus)
{
	DBusMessage *msg;
	dbus_bool_t dbres;
	DBusPendingCall *pending;
	int err;

	msg = dbus_message_new_method_call(cli_dbus->service_name,
					   TEAMD_DBUS_PATH,
					   "org.freedesktop.DBus.Introspectable",
					   "Introspect");
	if (!msg) {
		err(tdc, "Failed to create message.");
		return -ENOMEM;
	}

	dbres = dbus_connection_send_with_reply(cli_dbus->conn, msg,
						&pending, -1);
	if (dbres == FALSE) {
		err(tdc, "Send with reply failed.");
		err = -ENOMEM;
		goto free_msg;
	}
	if (!pending) {
		err(tdc, "Pending call not created.");
		err = -ENOMEM;
		goto free_msg;
	}

	dbus_pending_call_block(pending);

	dbus_message_unref(msg);
	msg = dbus_pending_call_steal_reply(pending);
	dbus_pending_call_unref(pending);
	if (!msg) {
		err(tdc, "Failed to get reply.");
		err = -EINVAL;
		goto out;
	}

	err = cli_dbus_check_error_msg(tdc, msg);
	if (err)
		goto free_msg;

free_msg:
	dbus_message_unref(msg);
out:
	return err;

}

static int cli_dbus_init(struct teamdctl *tdc, const char *team_name, void *priv)
{
	struct cli_dbus_priv *cli_dbus = priv;
	DBusError error;
	int ret;
	int err;

	ret = asprintf(&cli_dbus->service_name, TEAMD_DBUS_SERVICE ".%s",
		       team_name);
	if (ret == -1)
		return -errno;

	dbus_error_init(&error);
	cli_dbus->conn = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!cli_dbus->conn) {
		err(tdc, "Could not acquire the system bus: %s - %s",
			 error.name, error.message);
		err = -EINVAL;
		goto free_service_name;
	}

	/* Now, try to introspect to see if it's possible to call methods */
	err = cli_dbus_introspect(tdc, cli_dbus);
	if (err) {
		err(tdc, "Failed to do introspection.");
		goto free_service_name;
	}
	goto free_error;

free_service_name:
	free(cli_dbus->service_name);
free_error:
	dbus_error_free(&error);
	return err;
}

void cli_dbus_fini(struct teamdctl *tdc, void *priv)
{
	struct cli_dbus_priv *cli_dbus = priv;

	free(cli_dbus->service_name);
	dbus_connection_unref(cli_dbus->conn);
}

static const struct teamdctl_cli cli_dbus = {
	.name = "dbus",
	.init = cli_dbus_init,
	.fini = cli_dbus_fini,
	.method_call = cli_dbus_method_call,
	.priv_size = sizeof(struct cli_dbus_priv),
};

const struct teamdctl_cli *teamdctl_cli_dbus_get(void)
{
	return &cli_dbus;
}

#endif /* ENABLE_DBUS */
