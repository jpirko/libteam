/*
 *   teamd_zmq.c - Teamd ZeroMQ socket api
 *   Copyright (C) 2013 Jiri Zupka <jzupka@redhat.com>
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

#ifdef ENABLE_ZMQ

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>
#include <private/misc.h>
#include <private/list.h>
#include <team.h>

#include "teamd.h"
#include "teamd_zmq.h"
#include "teamd_zmq_common.h"
#include "teamd_ctl.h"
#include "teamd_config.h"

struct zmq_ops_priv {
	char *rcv_msg_args;
	void *sock;
};

struct zmq_acc_conn {
	struct list_item list;
	int sock;
};

static int zmq_op_get_args(void *ops_priv, const char *fmt, ...)
{
	va_list ap;
	struct zmq_ops_priv *zmq_ops_priv = ops_priv;
	char **pstr;
	char *str;
	char *rest = zmq_ops_priv->rcv_msg_args;
	int err = 0;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			pstr = va_arg(ap, char **);
			str = teamd_zmq_msg_getline(&rest);
			if (!str) {
				teamd_log_err("Insufficient number of arguments in message.");
				err = -EINVAL;
				goto out;
			}
			*pstr = str;
			break;
		default:
			teamd_log_err("Unknown argument type requested");
			err = -EINVAL;
			goto out;
		}
	}
out:
	va_end(ap);
	return err;
}

static void zmq_custom_send(struct zmq_ops_priv *zmq_ops_priv,
			    char *buf, size_t buflen)
{
	int ret;

	ret = zmq_send(zmq_ops_priv->sock, buf, buflen, 0);
	if (ret == -1)
		teamd_log_warn("zmq: send failed: %s", strerror(errno));
}

static int zmq_op_reply_err(void *ops_priv, const char *err_code,
			      const char *err_msg)
{
	struct zmq_ops_priv *zmq_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s\n%s\n%s\n", TEAMD_ZMQ_REPLY_ERR_PREFIX,
		       err_code, err_msg);
	if (err == -1)
		return -ENOMEM;
	zmq_custom_send(zmq_ops_priv, strbuf, strlen(strbuf));
	free(strbuf);
	return 0;
}

static int zmq_op_reply_succ(void *ops_priv, const char *msg)
{
	struct zmq_ops_priv *zmq_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s\n%s", TEAMD_ZMQ_REPLY_SUCC_PREFIX,
		       msg ? msg : "");
	if (err == -1)
		return -ENOMEM;
	zmq_custom_send(zmq_ops_priv, strbuf, strlen(strbuf));
	free(strbuf);
	return 0;
}

static const struct teamd_ctl_method_ops teamd_zmq_ctl_method_ops = {
	.get_args = zmq_op_get_args,
	.reply_err = zmq_op_reply_err,
	.reply_succ = zmq_op_reply_succ,
};

static int process_rcv_msg(struct teamd_context *ctx, char *rcv_msg)
{
	struct zmq_ops_priv zmq_ops_priv;
	char *str;
	char *rest = rcv_msg;

	str = teamd_zmq_msg_getline(&rest);
	if (!str) {
		teamd_log_dbg(ctx, "zmq: Incomplete message.");
		return 0;
	}
	if (strcmp(TEAMD_ZMQ_REQUEST_PREFIX, str)) {
		teamd_log_dbg(ctx, "zmq: Unsupported message type.");
		return 0;
	}

	str = teamd_zmq_msg_getline(&rest);
	if (!str) {
		teamd_log_dbg(ctx, "zmq: Incomplete message.");
		return 0;
	}
	if (!teamd_ctl_method_exists(str)) {
		teamd_log_dbg(ctx, "zmq: Unknown method \"%s\".", str);
		return 0;
	}

	zmq_ops_priv.sock = ctx->zmq.sock;
	zmq_ops_priv.rcv_msg_args = rest;

	teamd_log_dbg(ctx, "zmq: calling method \"%s\"", str);

	return teamd_ctl_method_call(ctx, str, &teamd_zmq_ctl_method_ops,
				     &zmq_ops_priv);
}

static int callback_zmq(struct teamd_context *ctx, int events, void *priv)
{
	int err = 0;
	int poolmask;
	size_t poolmask_size = sizeof(poolmask);

	err = zmq_getsockopt(ctx->zmq.sock, ZMQ_EVENTS, &poolmask,
			     &poolmask_size);
	if (err == -1)
		return -errno;

	while (poolmask & ZMQ_POLLIN) {
		zmq_msg_t msg;

		zmq_msg_init(&msg);
		if (zmq_msg_recv(&msg, ctx->zmq.sock, 0) == -1) {
			zmq_msg_close(&msg);
			return -errno;
		}

		err = process_rcv_msg(ctx, zmq_msg_data(&msg));

		zmq_msg_close(&msg);

		if (err == -1)
			break;

		err = zmq_getsockopt(ctx->zmq.sock, ZMQ_EVENTS, &poolmask,
				     &poolmask_size);
		if (err == -1)
			return -errno;
	}
	return err;
}

#define ZMQ_MAX_CLIENT_COUNT 10

static int teamd_zmq_sock_open(struct teamd_context *ctx)
{
	int err;
	void *context, *sock;
	int rc;
	const char *addr;

	context = zmq_ctx_new();
	if (!context) {
		teamd_log_err("zmq: Failed to create context.");
		return -errno;
	}

	sock = zmq_socket(context, ZMQ_REP);
	if (!sock) {
		teamd_log_err("zmq: Failed to create socket.");
		return -errno;
	}

	if (ctx->zmq.addr) {
		addr = ctx->zmq.addr;
	} else {
		err = teamd_config_string_get(ctx, &addr, "$.runner.addr");
		if (err) {
			teamd_log_err("zmq: Failed to get address from config.");
			return err;
		}
	}

	rc = zmq_bind(sock, addr);
	if (rc != 0) {
		teamd_log_err("zmq: Failed to bind socket.");
		err = -errno;
		goto close_sock;
	}

	ctx->zmq.context = context;
	ctx->zmq.sock = sock;
	return 0;

close_sock:
	zmq_close(sock);
	zmq_ctx_destroy(context);
	return err;
}

static void teamd_zmq_sock_close(struct teamd_context *ctx)
{
	zmq_close(ctx->zmq.sock);
	zmq_ctx_destroy(ctx->zmq.context);
}

#define ZMQ_CB_NAME "zmq"

int teamd_zmq_init(struct teamd_context *ctx)
{
	int err;
	int fd;
	size_t fd_size;

	if (!ctx->zmq.enabled)
		return 0;
	err = teamd_zmq_sock_open(ctx);
	if (err)
		return err;


	fd_size = sizeof(fd);
	zmq_getsockopt(ctx->zmq.sock, ZMQ_FD, &fd, &fd_size);

	err = teamd_loop_callback_fd_add(ctx, ZMQ_CB_NAME, ctx, callback_zmq,
					 fd, TEAMD_LOOP_FD_EVENT_READ);
	if (err)
		goto sock_close;
	teamd_loop_callback_enable(ctx, ZMQ_CB_NAME, ctx);
	return 0;
sock_close:
	teamd_zmq_sock_close(ctx);
	return err;
}

void teamd_zmq_fini(struct teamd_context *ctx)
{
	if (!ctx->zmq.enabled)
		return;
	teamd_loop_callback_del(ctx, ZMQ_CB_NAME, ctx);
	teamd_zmq_sock_close(ctx);
}

#endif /* ENABLE_ZMQ */
