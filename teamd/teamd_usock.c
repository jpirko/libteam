/*
 *   teamd_usock.c - Teamd unix socket api
 *   Copyright (C) 2012-2015 Jiri Pirko <jiri@resnulli.us>
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
#include "teamd_usock.h"
#include "teamd_usock_common.h"
#include "teamd_ctl.h"

struct usock_ops_priv {
	char *rcv_msg_args;
	int sock;
};

struct usock_acc_conn {
	struct list_item list;
	int sock;
};

int __strdecode(char *str)
{
	char *cur;
	char *cur2;
	bool escaped = false;

	cur = str;
	while (*cur != '\0') {
		if (!escaped && *cur == '\\') {
			escaped = true;
		} else if (escaped) {
			escaped = false;
			switch (*cur) {
			case 'n':
				*(cur - 1) = '\n';
				break;
			case '\\':
				*(cur - 1) = '\\';
				break;
			default:
				return -EINVAL;
			}
			cur2 = cur;
			while (*cur2 != '\0') {
				*cur2 = *(cur2 + 1);
				cur2++;
			}
		}
		cur++;
	}
	return 0;
}

static int usock_op_get_args(void *ops_priv, const char *fmt, ...)
{
	va_list ap;
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char **pstr;
	char *str;
	char *rest = usock_ops_priv->rcv_msg_args;
	int err = 0;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			pstr = va_arg(ap, char **);
			str = teamd_usock_msg_getline(&rest);
			if (!str) {
				teamd_log_err("Insufficient number of arguments in message.");
				err = -EINVAL;
				goto out;
			}
			err = __strdecode(str);
			if (err) {
				teamd_log_err("Corrupted argument in message.");
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

static void usock_send(struct usock_ops_priv *usock_ops_priv,
		       char *buf, size_t buflen)
{
	int ret;

	ret = send(usock_ops_priv->sock, buf, buflen, 0);
	if (ret == -1)
		teamd_log_warn("Usock send failed: %s", strerror(errno));
}

static int usock_op_reply_err(void *ops_priv, const char *err_code,
			      const char *err_msg)
{
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s\n%s\n%s\n", TEAMD_USOCK_REPLY_ERR_PREFIX,
		       err_code, err_msg);
	if (err == -1)
		return -ENOMEM;
	usock_send(usock_ops_priv, strbuf, strlen(strbuf));
	free(strbuf);
	return 0;
}

static int usock_op_reply_succ(void *ops_priv, const char *msg)
{
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s\n%s", TEAMD_USOCK_REPLY_SUCC_PREFIX,
		       msg ? msg : "");
	if (err == -1)
		return -ENOMEM;
	usock_send(usock_ops_priv, strbuf, strlen(strbuf));
	free(strbuf);
	return 0;
}

static const struct teamd_ctl_method_ops teamd_usock_ctl_method_ops = {
	.get_args = usock_op_get_args,
	.reply_err = usock_op_reply_err,
	.reply_succ = usock_op_reply_succ,
};

static int process_rcv_msg(struct teamd_context *ctx, int sock, char *rcv_msg)
{
	struct usock_ops_priv usock_ops_priv;
	char *str;
	char *rest = rcv_msg;

	str = teamd_usock_msg_getline(&rest);
	if (!str) {
		teamd_log_dbg("usock: Incomplete message.");
		return 0;
	}
	if (strcmp(TEAMD_USOCK_REQUEST_PREFIX, str)) {
		teamd_log_dbg("usock: Unsupported message type.");
		return 0;
	}

	str = teamd_usock_msg_getline(&rest);
	if (!str) {
		teamd_log_dbg("usock: Incomplete message.");
		return 0;
	}
	if (!teamd_ctl_method_exists(str)) {
		teamd_log_dbg("usock: Unknown method \"%s\".", str);
		return 0;
	}

	usock_ops_priv.sock = sock;
	usock_ops_priv.rcv_msg_args = rest;

	teamd_log_dbg("usock: calling method \"%s\"", str);

	return teamd_ctl_method_call(ctx, str, &teamd_usock_ctl_method_ops,
				     &usock_ops_priv);
}

static void acc_conn_destroy(struct teamd_context *ctx,
			     struct usock_acc_conn *acc_conn);

static int callback_usock_acc_conn(struct teamd_context *ctx, int events,
				   void *priv)
{
	struct usock_acc_conn *acc_conn = priv;
	char *msg = NULL; /* gcc needs this initialized */
	int err;

	err = teamd_usock_recv_msg(acc_conn->sock, &msg);
	if (err == -EPIPE || err == -ECONNRESET) {
		acc_conn_destroy(ctx, acc_conn);
		return 0;
	} else if (err) {
		teamd_log_err("usock: Failed to receive data from connection.");
		return err;
	}
	err = process_rcv_msg(ctx, acc_conn->sock, msg);
	free(msg);
	return err;
}

#define USOCK_ACC_CONN_CB_NAME "usock_acc_conn"

static int acc_conn_create(struct teamd_context *ctx, int sock)
{
	struct usock_acc_conn *acc_conn;
	int err;

	acc_conn = myzalloc(sizeof(*acc_conn));
	if (!acc_conn) {
		teamd_log_err("usock: No memory to allocate new connection structure.");
		return -ENOMEM;
	}
	acc_conn->sock = sock;
	err = teamd_loop_callback_fd_add(ctx, USOCK_ACC_CONN_CB_NAME, acc_conn,
					 callback_usock_acc_conn,
					 acc_conn->sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err)
		goto free_acc_conn;
	teamd_loop_callback_enable(ctx, USOCK_ACC_CONN_CB_NAME, acc_conn);
	list_add(&ctx->usock.acc_conn_list, &acc_conn->list);
	return 0;

free_acc_conn:
	free(acc_conn);
	return err;
}

static void acc_conn_destroy(struct teamd_context *ctx,
			     struct usock_acc_conn *acc_conn)
{

	teamd_loop_callback_del(ctx, USOCK_ACC_CONN_CB_NAME, acc_conn);
	close(acc_conn->sock);
	list_del(&acc_conn->list);
	free(acc_conn);
}

static void acc_conn_destroy_all(struct teamd_context *ctx)
{
	struct usock_acc_conn *acc_conn;
	struct usock_acc_conn *tmp;

	list_for_each_node_entry_safe(acc_conn, tmp,
				      &ctx->usock.acc_conn_list, list)
		acc_conn_destroy(ctx, acc_conn);
}

static int callback_usock(struct teamd_context *ctx, int events, void *priv)
{
	struct sockaddr_un addr;
	socklen_t alen;
	int sock;
	int err;

	alen = sizeof(addr);
	sock = accept(ctx->usock.sock, &addr, &alen);
	if (sock == -1) {
		teamd_log_err("usock: Failed to accept connection.");
		return -errno;
	}
	err = acc_conn_create(ctx, sock);
	if (err) {
		close(sock);
		return err;
	}
	return 0;
}

#define USOCK_MAX_CLIENT_COUNT 10

static int teamd_usock_sock_open(struct teamd_context *ctx)
{
	struct sockaddr_un addr;
	int sock;
	int err;

	err = teamd_make_rundir();
	if (err)
		return err;

	sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (sock == -1) {
		teamd_log_err("usock: Failed to create socket.");
		return -errno;
	}

	addr.sun_family = AF_UNIX;
	teamd_usock_get_sockpath(addr.sun_path, sizeof(addr.sun_path),
				 ctx->team_devname);

	teamd_log_dbg("usock: Using sockpath \"%s\"", addr.sun_path);
	err = unlink(addr.sun_path);
	if (err == -1 && errno != ENOENT) {
		teamd_log_err("usock: Failed to remove socket file.");
		err = -errno;
		goto close_sock;
	}

	err = bind(sock, (struct sockaddr *) &addr,
	           strlen(addr.sun_path) + sizeof(addr.sun_family));
	if (err == -1) {
		teamd_log_err("usock: Failed to bind socket.");
		err = -errno;
		goto close_sock;
	}
	listen(sock, USOCK_MAX_CLIENT_COUNT);

	ctx->usock.sock = sock;
	ctx->usock.addr = addr;
	return 0;

close_sock:
	close(sock);
	return err;
}

static void teamd_usock_sock_close(struct teamd_context *ctx)
{
	close(ctx->usock.sock);
	unlink(ctx->usock.addr.sun_path);
}

#define USOCK_CB_NAME "usock"

int teamd_usock_init(struct teamd_context *ctx)
{
	int err;

	if (!ctx->usock.enabled)
		return 0;
	list_init(&ctx->usock.acc_conn_list);
	err = teamd_usock_sock_open(ctx);
	if (err)
		return err;
	err = teamd_loop_callback_fd_add(ctx, USOCK_CB_NAME, ctx,
					 callback_usock, ctx->usock.sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err)
		goto sock_close;
	teamd_loop_callback_enable(ctx, USOCK_CB_NAME, ctx);
	return 0;
sock_close:
	teamd_usock_sock_close(ctx);
	return err;
}

void teamd_usock_fini(struct teamd_context *ctx)
{
	if (!ctx->usock.enabled)
		return;
	acc_conn_destroy_all(ctx);
	teamd_loop_callback_del(ctx, USOCK_CB_NAME, ctx);
	teamd_usock_sock_close(ctx);
}
