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

#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <dbus/dbus.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

#define TEAMD_DBUS_SERVICE	"org.libteam.teamd"
#define TEAMD_DBUS_PATH		"/org/libteam/teamd"

static DBusHandlerResult message_handler(DBusConnection *con,
					 DBusMessage *message,
					 void *user_data)
{
	const char *method;
	const char *path;
	const char *msg_interface;

	method = dbus_message_get_member(message);
	path = dbus_message_get_path(message);
	msg_interface = dbus_message_get_interface(message);
	if (!method || !path || !msg_interface)
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
	teamd_log_dbg("dbus: %s.%s (%s)", msg_interface, method, path);

	return DBUS_HANDLER_RESULT_HANDLED;
}

static DBusObjectPathVTable vtable = {
	.message_function = message_handler,
};

int teamd_dbus_iface_init(struct teamd_context *ctx)
{
	DBusError error;
	int err;
	char *service_name;

	err = asprintf(&service_name, TEAMD_DBUS_SERVICE ".%s",
		       ctx->team_devname);
	if (err == -1)
		return -errno;

	if (dbus_connection_register_object_path(ctx->dbus.con,
						 TEAMD_DBUS_PATH, &vtable,
						 ctx) == FALSE) {
		teamd_log_err("dbus: Could not set up message handler");
		err = -EINVAL;
		goto out;
	}
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
	if (err)
		dbus_connection_unregister_object_path(ctx->dbus.con,
						       TEAMD_DBUS_PATH);
out:
	free(service_name);
	return err;
}

void teamd_dbus_iface_fini(struct teamd_context *ctx)
{
	dbus_connection_unregister_object_path(ctx->dbus.con,
					       TEAMD_DBUS_PATH);
}

int teamd_dbus_con_init(struct teamd_context *ctx)
{
	DBusError error;

	dbus_error_init(&error);
	ctx->dbus.con = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (!ctx->dbus.con) {
		teamd_log_err("dbus: Could not acquire the system bus: %s - %s",
			      error.name, error.message);
		return -EINVAL;
	}
	dbus_error_free(&error);
	dbus_connection_set_exit_on_disconnect(ctx->dbus.con, FALSE);
	return 0;
}

void teamd_dbus_con_fini(struct teamd_context *ctx)
{
	dbus_connection_unref(ctx->dbus.con);
}

static void callback_watch(struct teamd_context *ctx, int events,
			   void *func_priv)
{
	DBusWatch *watch = func_priv;

	dbus_connection_ref(ctx->dbus.con);
	if (events & TEAMD_LOOP_FD_EVENT_READ)
		dbus_watch_handle(watch, DBUS_WATCH_READABLE);
	if (events & TEAMD_LOOP_FD_EVENT_WRITE)
		dbus_watch_handle(watch, DBUS_WATCH_WRITABLE);
	if (events & TEAMD_LOOP_FD_EVENT_EXCEPTION)
		dbus_watch_handle(watch, DBUS_WATCH_ERROR);
	dbus_connection_unref(ctx->dbus.con);
}

static dbus_bool_t add_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;
	unsigned int flags;
	int err;
	char *cb_name;
	int fd;
	int fd_events;

	fd = dbus_watch_get_unix_fd(watch);
	flags = dbus_watch_get_flags(watch);
	fd_events = TEAMD_LOOP_FD_EVENT_EXCEPTION;
	if (flags & DBUS_WATCH_READABLE)
		fd_events |= TEAMD_LOOP_FD_EVENT_READ;
	if (flags & DBUS_WATCH_WRITABLE)
		fd_events |= TEAMD_LOOP_FD_EVENT_WRITE;

	err = asprintf(&cb_name, "dbus_watch_%p", watch);
	if (err == -1)
		return FALSE;

	dbus_watch_set_data(watch, cb_name, free);

	err = teamd_loop_callback_fd_add(ctx, cb_name, fd, fd_events,
					 callback_watch, watch);
	if (err)
		return FALSE;
	if (dbus_watch_get_enabled(watch))
		teamd_loop_callback_enable(ctx, cb_name);
	return TRUE;
}

static void remove_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;
	char *cb_name = dbus_watch_get_data(watch);

	teamd_loop_callback_del(ctx, cb_name);
	dbus_watch_set_data(watch, NULL, NULL);
}

static void toggle_watch(DBusWatch *watch, void *priv)
{
	struct teamd_context *ctx = priv;
	char *cb_name = dbus_watch_get_data(watch);

	if (dbus_watch_get_enabled(watch))
		teamd_loop_callback_enable(ctx, cb_name);
	else
		teamd_loop_callback_disable(ctx, cb_name);
}

static void convert_ms(time_t *sec, long *nsec, int ms)
{
	*sec = ms / 1000;
	*nsec = (ms % 1000) * 1000000;
}

static void callback_timeout(struct teamd_context *ctx, int events,
			     void *func_priv)
{
	DBusTimeout *timeout = func_priv;

	dbus_timeout_handle(timeout);
}

static dbus_bool_t add_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;
	int err;
	char *cb_name;
	time_t sec;
	long nsec;

	err = asprintf(&cb_name, "dbus_timeout_%p", timeout);
	if (err == -1)
		return FALSE;

	dbus_timeout_set_data(timeout, cb_name, free);

	convert_ms(&sec, &nsec, dbus_timeout_get_interval(timeout));
	err = teamd_loop_callback_timer_add(ctx, cb_name, 0, 0, sec, nsec,
					    callback_timeout, timeout);
	if (err)
		return FALSE;
	if (dbus_timeout_get_enabled(timeout))
		teamd_loop_callback_enable(ctx, cb_name);
	return TRUE;
}

static void remove_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;
	char *cb_name = dbus_timeout_get_data(timeout);

	teamd_loop_callback_del(ctx, cb_name);
	dbus_timeout_set_data(timeout, NULL, NULL);
}

static void toggle_timeout(DBusTimeout *timeout, void *priv)
{
	struct teamd_context *ctx = priv;
	char *cb_name = dbus_timeout_get_data(timeout);

	if (dbus_timeout_get_enabled(timeout))
		teamd_loop_callback_enable(ctx, cb_name);
	else
		teamd_loop_callback_disable(ctx, cb_name);
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

static void callback_dispatch(struct teamd_context *ctx, int events,
			      void *func_priv)
{
	struct dispatch_priv *dp = func_priv;
	char byte;
	int err;

	err = read(dp->fd_r, &byte, 1);
	if (err == -1) {
		if (errno != EINTR && errno != EAGAIN) {
			teamd_log_err("dbus: dispatch, read() failed, errno: %d. ",
				      errno);
		}
	} else {
		while (dbus_connection_dispatch(ctx->dbus.con) ==
			DBUS_DISPATCH_DATA_REMAINS);
	}
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

	err = teamd_loop_callback_fd_add(ctx, DISPATCH_CB_NAME, dp->fd_r,
					 TEAMD_LOOP_FD_EVENT_READ,
					 callback_dispatch, dp);
	teamd_loop_callback_enable(ctx, DISPATCH_CB_NAME);
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

	teamd_loop_callback_del(dp->ctx, DISPATCH_CB_NAME);
	close(dp->fd_w);
	close(dp->fd_r);
	free(dp);
}

int teamd_dbus_mainloop_init(struct teamd_context *ctx)
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
