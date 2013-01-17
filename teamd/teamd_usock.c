/*
 *   teamd_usock.c - Teamd unix socket api
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <ctype.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_usock.h"
#include "teamd_ctl_methods.h"

struct usock_ops_priv {
	char *rcv_msg_args;
	int sock;
};

static void __getarg(char *str, char **pstart, char **prest)
{
	char *start = NULL;
	char *rest = NULL;

	if (!str)
		return;
	while (1) {
		if (*str == '\0')
			break;
		if ((*str != '\n') && !start)
			start = str;
		if ((*str == '\n') && start) {
			*str = '\0';
			rest = str + 1;
			break;
		}
		str++;
	}
	*pstart = start;
	*prest = rest;
}

static int usock_op_get_args(void *ops_priv, const char *fmt, ...)
{
	va_list ap;
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char **pstr;
	char *str;
	char *rest = usock_ops_priv->rcv_msg_args;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			pstr = va_arg(ap, char **);
			__getarg(rest, &str, &rest);
			if (!str) {
				teamd_log_err("Insufficient number of arguments in message.");
				return -EINVAL;
			}
			*pstr = str;
			break;
		default:
			teamd_log_err("Unknown argument type requested");
			return -EINVAL;
		}
	}
	va_end(ap);
	return 0;
}

static int usock_op_reply_err(void *ops_priv, const char *err_code,
			      const char *err_msg)
{
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s%s\n%s\n", TEAMD_USOCK_ERR_PREFIX,
		       err_code, err_msg);
	if (err == -1)
		return -errno;
	err = send(usock_ops_priv->sock, strbuf, strlen(strbuf), 0);
	free(strbuf);
	if (err == -1)
		return -errno;
	return 0;
}

static int usock_op_reply_succ(void *ops_priv, const char *msg)
{
	struct usock_ops_priv *usock_ops_priv = ops_priv;
	char *strbuf;
	int err;

	err = asprintf(&strbuf, "%s%s", TEAMD_USOCK_SUCC_PREFIX,
		       msg ? msg : "");
	if (err == -1)
		return -errno;
	err = send(usock_ops_priv->sock, strbuf, strlen(strbuf), 0);
	free(strbuf);
	if (err == -1)
		return -errno;
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
	char *rcv_msg_args;
	char *str;

	str = strstr(rcv_msg, "\n\n");
	if (!str || strchr(rcv_msg, '\0') < str) {
		teamd_log_dbg("usock: Incomplete command.");
		return 0;
	}
	*str = '\0';

	__getarg(rcv_msg, &str, &rcv_msg_args);
	if (!str) {
		teamd_log_dbg("usock: Incomplete command.");
		return 0;
	}

	if (!teamd_ctl_method_exists(str)) {
		teamd_log_dbg("usock: Unknown method \"%s\".", str);
		return 0;
	}

	usock_ops_priv.sock = sock;
	usock_ops_priv.rcv_msg_args = rcv_msg_args;

	teamd_log_dbg("usock: calling method \"%s\"", str);

	return teamd_ctl_method_call(ctx, str, &teamd_usock_ctl_method_ops,
				     &usock_ops_priv);
}

#define BUFLEN 2048

static int teamd_usock_recv(int sock, char **pmsg)
{
	ssize_t len;
	char *buf;

	buf = malloc(BUFLEN);
	if (!buf)
		return -ENOMEM;
	len = recv(sock, buf, BUFLEN - 1, 0);
	switch (len) {
	case -1:
		free(buf);
		return -errno;
	case 0:
	default:
		break;
	}
	buf[len] = '\0';
	*pmsg = buf;
	return 0;
}

static int callback_usock(struct teamd_context *ctx, int events, void *priv)
{
	int sock;
	struct sockaddr_un addr;
	socklen_t alen;
	char *msg = msg;
	int err;

	alen = sizeof(addr);
	sock = accept(ctx->usock.sock, &addr, &alen);
	if (sock == -1) {
		teamd_log_err("usock: Failed to accept connection.");
		return -errno;
	}

	err = teamd_usock_recv(sock, &msg);
	if (err) {
		teamd_log_err("usock: Failed to receive data from connection.");
		goto cleanup;
	}
	err = process_rcv_msg(ctx, sock, msg);
	free(msg);

cleanup:
	close(sock);
	return err;
}

#define USOCK_MAX_CLIENT_COUNT 10

static int teamd_usock_sock_open(struct teamd_context *ctx)
{
	struct sockaddr_un addr;
	int sock;
	int err;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		teamd_log_err("usock: Failed to create socket.");
		return -errno;
	}

	addr.sun_family = AF_UNIX;
	teamd_usock_get_sockpath(addr.sun_path, sizeof(addr.sun_path),
				 ctx->team_devname);

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
	err = teamd_usock_sock_open(ctx);
	if (err)
		return err;
	err = teamd_loop_callback_fd_add(ctx, USOCK_CB_NAME, ctx,
					 callback_usock, ctx->usock.sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	teamd_loop_callback_enable(ctx, USOCK_CB_NAME, ctx);
	if (err)
		goto sock_close;
	return 0;
sock_close:
	teamd_usock_sock_close(ctx);
	return err;
}

void teamd_usock_fini(struct teamd_context *ctx)
{
	if (!ctx->usock.enabled)
		return;
	teamd_loop_callback_del(ctx, USOCK_CB_NAME, ctx);
	teamd_usock_sock_close(ctx);
}
