/*
 *   teamd_dbus.c - Teamd dbus api
 *   Copyright (C) 2012 Jiri Pirko <jpirko@redhat.com>
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

#include "config.h"

#ifdef ENABLE_DBUS

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_dbus.h"
#include "teamd_dbus_common.h"
#include "teamd_ctl.h"

static const char *introspection_xml =
	"<node name='" TEAMD_DBUS_PATH "'>"
	"  <interface name='" TEAMD_DBUS_IFACE "'>"
	"    <method name='PortConfigUpdate'>"
	"      <arg type='s' name='port_devname' direction='in'/>"
	"      <arg type='s' name='port_config' direction='in'/>"
	"    </method>"
	"    <method name='PortAdd'>"
	"      <arg type='s' name='port_devname' direction='in'/>"
	"    </method>"
	"    <method name='PortRemove'>"
	"      <arg type='s' name='port_devname' direction='in'/>"
	"    </method>"
	"    <method name='ConfigDump'>"
	"    </method>"
	"    <method name='ConfigDumpActual'>"
	"    </method>"
	"    <method name='StateDump'>"
	"    </method>"
	"    <method name='StateItemValueGet'>"
	"      <arg type='s' name='state_item_path' direction='in'/>"
	"    </method>"
	"    <method name='StateItemValueSet'>"
	"      <arg type='s' name='state_item_path' direction='in'/>"
	"      <arg type='s' name='value' direction='in'/>"
	"    </method>"
	"  </interface>"
	"</node>";

static DBusMessage *introspect(DBusMessage *message)
{
	DBusMessage *reply;

	reply = dbus_message_new_method_return(message);
	if (!reply)
		return NULL;
	dbus_message_append_args(reply, DBUS_TYPE_STRING, &introspection_xml,
				 DBUS_TYPE_INVALID);
	return reply;
}

struct dbus_ops_priv {
	DBusMessage *reply;
	DBusMessage *message;
};

static int dbus_op_get_args(void *ops_priv, const char *fmt, ...)
{
	va_list ap;
	struct dbus_ops_priv *dbus_ops_priv = ops_priv;
	DBusMessage *message = dbus_ops_priv->message;
	DBusMessageIter iter;
	int arg_type;
	char **pstr;

	dbus_message_iter_init(message, &iter);
	va_start(ap, fmt);
	while (*fmt) {
		arg_type = dbus_message_iter_get_arg_type(&iter);
		if (arg_type == DBUS_TYPE_INVALID) {
			teamd_log_err("Insufficient number of arguments in message.");
			return -EINVAL;
		}
		switch (*fmt++) {
		case 's': /* string */
			if (arg_type != DBUS_TYPE_STRING) {
				teamd_log_err("Unexpected argument type found in message.");
				return -EINVAL;
			}
			pstr = va_arg(ap, char **);
			dbus_message_iter_get_basic(&iter, pstr);
			break;
		default:
			teamd_log_err("Unknown argument type requested");
			return -EINVAL;
		}
		dbus_message_iter_next(&iter);
	}
	va_end(ap);
	return 0;
}

static int dbus_op_reply_err(void *ops_priv, const char *err_code,
			     const char *err_msg)
{
	struct dbus_ops_priv *dbus_ops_priv = ops_priv;
	int err;
	char *err_code_buf;

	err = asprintf(&err_code_buf, TEAMD_DBUS_IFACE "%s", err_code);
	if (err == -1)
		return -errno;
	dbus_ops_priv->reply = dbus_message_new_error(dbus_ops_priv->message,
						      err_code_buf,
						      err_msg);
	free(err_code_buf);
	return 0;
}

static int dbus_op_reply_succ(void *ops_priv, const char *msg)
{
	struct dbus_ops_priv *dbus_ops_priv = ops_priv;
	DBusMessage *reply;

	if (!msg)
		return 0;
	reply = dbus_message_new_method_return(dbus_ops_priv->message);
	if (reply)
		dbus_message_append_args(reply, DBUS_TYPE_STRING, &msg,
					 DBUS_TYPE_INVALID);
	dbus_ops_priv->reply = reply;
	return 0;
}

static const struct teamd_ctl_method_ops teamd_dbus_ctl_method_ops = {
	.get_args = dbus_op_get_args,
	.reply_err = dbus_op_reply_err,
	.reply_succ = dbus_op_reply_succ,
};

static DBusHandlerResult message_handler(DBusConnection *con,
					 DBusMessage *message,
					 void *user_data)
{
	const char *method;
	const char *path;
	const char *msg_interface;
	DBusMessage *reply = NULL;
	struct teamd_context *ctx = user_data;

	method = dbus_message_get_member(message);
	path = dbus_message_get_path(message);
	msg_interface = dbus_message_get_interface(message);
	if (!method || !path || !msg_interface)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	teamd_log_dbg("dbus: %s.%s (%s)", msg_interface, method, path);

	if (!strcmp(method, "Introspect") &&
	    !strcmp(msg_interface, "org.freedesktop.DBus.Introspectable")) {
		reply = introspect(message);
	}

	if (!strcmp(msg_interface, TEAMD_DBUS_IFACE) &&
	    teamd_ctl_method_exists(method)) {
		struct dbus_ops_priv dbus_ops_priv;

		dbus_ops_priv.reply = NULL;
		dbus_ops_priv.message = message;
		teamd_ctl_method_call(ctx, method, &teamd_dbus_ctl_method_ops,
				      &dbus_ops_priv);
		reply = dbus_ops_priv.reply;
	}

	if (!dbus_message_get_no_reply(message)) {
		if (!reply)
			reply = dbus_message_new_method_return(message);
		if (reply) {
			if (!dbus_connection_send(con, reply, NULL))
				teamd_log_err("dbus: Failed to send reply.");
			dbus_message_unref(reply);
		}
	}

	return DBUS_HANDLER_RESULT_HANDLED;
}

static const DBusObjectPathVTable vtable = {
	.message_function = message_handler,
};

static int teamd_dbus_iface_init(struct teamd_context *ctx)
{
	if (dbus_connection_register_object_path(ctx->dbus.con,
						 TEAMD_DBUS_PATH, &vtable,
						 ctx) == FALSE) {
		teamd_log_err("dbus: Could not set up message handler");
		return -EINVAL;
	}
	return 0;
}

static void teamd_dbus_iface_fini(struct teamd_context *ctx)
{
	dbus_connection_unregister_object_path(ctx->dbus.con,
					       TEAMD_DBUS_PATH);
}

static int teamd_dbus_con_init(struct teamd_context *ctx)
{
	DBusError error;
	int err = 0;

	dbus_error_init(&error);
	ctx->dbus.con = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!ctx->dbus.con) {
		teamd_log_err("dbus: Could not acquire the system bus: %s - %s",
			      error.name, error.message);
		err = -EINVAL;
		goto free_err;
	}
	dbus_connection_set_exit_on_disconnect(ctx->dbus.con, FALSE);
free_err:
	dbus_error_free(&error);
	return err;
}

static void teamd_dbus_con_fini(struct teamd_context *ctx)
{
	dbus_connection_unref(ctx->dbus.con);
}

static int callback_watch(struct teamd_context *ctx, int events, void *priv)
{
	DBusWatch *watch = priv;

	dbus_connection_ref(ctx->dbus.con);
	if (events & TEAMD_LOOP_FD_EVENT_READ)
		dbus_watch_handle(watch, DBUS_WATCH_READABLE);
	if (events & TEAMD_LOOP_FD_EVENT_WRITE)
		dbus_watch_handle(watch, DBUS_WATCH_WRITABLE);
	if (events & TEAMD_LOOP_FD_EVENT_EXCEPTION)
		dbus_watch_handle(watch, DBUS_WATCH_ERROR);
	dbus_connection_unref(ctx->dbus.con);
	return 0;
}

#define WATCH_CB_NAME "dbus_watch"

static dbus_bool_t add_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;
	unsigned int flags;
	int err;
	int fd;
	int fd_events;

	fd = dbus_watch_get_unix_fd(watch);
	flags = dbus_watch_get_flags(watch);
	fd_events = TEAMD_LOOP_FD_EVENT_EXCEPTION;
	if (flags & DBUS_WATCH_READABLE)
		fd_events |= TEAMD_LOOP_FD_EVENT_READ;
	if (flags & DBUS_WATCH_WRITABLE)
		fd_events |= TEAMD_LOOP_FD_EVENT_WRITE;

	err = teamd_loop_callback_fd_add(ctx, WATCH_CB_NAME, watch,
					 callback_watch, fd, fd_events);
	if (err)
		return FALSE;
	if (dbus_watch_get_enabled(watch))
		teamd_loop_callback_enable(ctx, WATCH_CB_NAME, watch);
	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;

	teamd_loop_callback_del(ctx, WATCH_CB_NAME, watch);
}

static void toggle_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;

	if (dbus_watch_get_enabled(watch))
		teamd_loop_callback_enable(ctx, WATCH_CB_NAME, watch);
	else
		teamd_loop_callback_disable(ctx, WATCH_CB_NAME, watch);
}

static int callback_timeout(struct teamd_context *ctx, int events, void *priv)
{
	DBusTimeout *timeout = priv;

	dbus_timeout_handle(timeout);
	return 0;
}

#define TIMEOUT_CB_NAME "dbus_timeout"

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;
	int err;
	struct timespec ts;

	ms_to_timespec(&ts, dbus_timeout_get_interval(timeout));
	err = teamd_loop_callback_timer_add_set(ctx, TIMEOUT_CB_NAME, timeout,
						callback_timeout, NULL, &ts);
	if (err)
		return FALSE;
	if (dbus_timeout_get_enabled(timeout))
		teamd_loop_callback_enable(ctx, TIMEOUT_CB_NAME, timeout);
	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;

	teamd_loop_callback_del(ctx, TIMEOUT_CB_NAME, timeout);
}

static void toggle_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;

	if (dbus_timeout_get_enabled(timeout))
		teamd_loop_callback_enable(ctx, TIMEOUT_CB_NAME, timeout);
	else
		teamd_loop_callback_disable(ctx, TIMEOUT_CB_NAME, timeout);
}

static void wakeup_main(void *priv)
{
	struct teamd_context *ctx = priv;

	teamd_run_loop_restart(ctx);
}

struct dispatch_priv {
	int fd_r;
	int fd_w;
	struct teamd_context *ctx;
};

static int callback_dispatch(struct teamd_context *ctx, int events, void *priv)
{
	struct dispatch_priv *dp = priv;
	char byte;
	int err;

	err = read(dp->fd_r, &byte, 1);
	if (err == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			teamd_log_err("dbus: dispatch, read() failed.");
			return -errno;
		}
	} else {
		while (dbus_connection_dispatch(ctx->dbus.con) ==
			DBUS_DISPATCH_DATA_REMAINS);
	}
	return 0;
}

static void wakeup_dispatch(struct dispatch_priv *dp)
{
	int err;

retry:
	err = write(dp->fd_w, "a", 1);
	if (err == -1 && errno == EINTR)
		goto retry;
}

static void dispatch_status(DBusConnection *conn, DBusDispatchStatus status,
			    void *priv) {
	struct dispatch_priv *dp = priv;

	if (status == DBUS_DISPATCH_COMPLETE)
		return;
	wakeup_dispatch(dp);
}

#define DISPATCH_CB_NAME "dbus_dispatch"

static int dispatch_init(struct dispatch_priv **pdp, struct teamd_context *ctx)
{
	struct dispatch_priv *dp;
	int fds[2];
	int err;

	dp = myzalloc(sizeof(*dp));
	if (!dp)
		return -ENOMEM;

	err = pipe(fds);
	if (err) {
		err = -errno;
		goto free_dp;
	}
	dp->fd_r = fds[0];
	dp->fd_w = fds[1];
	dp->ctx = ctx;

	err = teamd_loop_callback_fd_add(ctx, DISPATCH_CB_NAME, dp,
					 callback_dispatch,
					 dp->fd_r, TEAMD_LOOP_FD_EVENT_READ);
	teamd_loop_callback_enable(ctx, DISPATCH_CB_NAME, dp);
	if (err)
		goto close_pipe;
	*pdp = dp;
	return 0;
close_pipe:
	close(dp->fd_w);
	close(dp->fd_r);
free_dp:
	free(dp);
	return err;
}

static void dispatch_exit(void *priv)
{
	struct dispatch_priv *dp = priv;

	teamd_loop_callback_del(dp->ctx, DISPATCH_CB_NAME, dp);
	close(dp->fd_w);
	close(dp->fd_r);
	free(dp);
}

static int teamd_dbus_mainloop_init(struct teamd_context *ctx)
{
	struct dispatch_priv *dp = dp;
	int err;

	err = dispatch_init(&dp, ctx);
	if (err) {
		teamd_log_err("dbus: failed to init dispatch.");
		return err;
	}
	dbus_connection_set_dispatch_status_function(ctx->dbus.con,
						     dispatch_status,
						     dp, dispatch_exit);
	if (dbus_connection_set_watch_functions(ctx->dbus.con, add_watch,
						remove_watch, toggle_watch,
						ctx, NULL) == FALSE) {
		teamd_log_err("dbus: failed to init watch functions.");
		return -EINVAL;
	}
	if (dbus_connection_set_timeout_functions(ctx->dbus.con, add_timeout,
						  remove_timeout,
						  toggle_timeout,
						  ctx, NULL) == FALSE) {
		teamd_log_err("dbus: failed to init timeout functions.");
		return -EINVAL;
	}
	dbus_connection_set_wakeup_main_function(ctx->dbus.con, wakeup_main,
						 ctx, NULL);
	/* Do initial dispatch for early messages */
	wakeup_dispatch(dp);
	return 0;
}

int teamd_dbus_init(struct teamd_context *ctx)
{
	int err;
	char *id;

	if (!ctx->dbus.enabled)
		return 0;
	err = teamd_dbus_con_init(ctx);
	if (err)
		return err;
	err = teamd_dbus_iface_init(ctx);
	if (err)
		goto con_fini;
	err = teamd_dbus_mainloop_init(ctx);
	if (err)
		goto iface_fini;
	id = dbus_connection_get_server_id(ctx->dbus.con),
	teamd_log_dbg("dbus: connected to %s with name %s", id,
		      dbus_bus_get_unique_name(ctx->dbus.con));
	dbus_free(id);
	return 0;
iface_fini:
	teamd_dbus_iface_fini(ctx);
con_fini:
	teamd_dbus_con_fini(ctx);
	return err;
}

void teamd_dbus_fini(struct teamd_context *ctx)
{
	if (!ctx->dbus.enabled)
		return;
	teamd_dbus_iface_fini(ctx);
	teamd_dbus_con_fini(ctx);
}

int teamd_dbus_expose_name(struct teamd_context *ctx)
{
	DBusError error;
	int err;
	char *service_name;

	if (!ctx->dbus.enabled)
		return 0;

	err = asprintf(&service_name, TEAMD_DBUS_SERVICE ".%s",
		       ctx->team_devname);
	if (err == -1)
		return -errno;

	dbus_error_init(&error);
	err = dbus_bus_request_name(ctx->dbus.con, service_name, 0,
				    &error);
	if (err == DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		teamd_log_dbg("dbus: have name %s", service_name);
		err = 0;
	} else if (dbus_error_is_set(&error)) {
		teamd_log_err("dbus: Failed to acquire %s: %s: %s",
			      service_name, error.name, error.message);
		err = -EINVAL;
	} else {
		teamd_log_err("dbus: name %s already taken.", service_name);
		err = -EBUSY;
	}
	dbus_error_free(&error);
	free(service_name);
	return err;
}

#endif /* ENABLE_DBUS */
