/*
 *   cli_usock.c - Teamd daemon control library teamd Unix Domain socket client
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
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <teamdctl.h>
#include "teamdctl_private.h"
#include "../teamd/teamd_usock.h"

struct cli_usock_priv {
	int sock;
};

static int cli_usock_process_msg(struct teamdctl *tdc, char *msg,
				 char **p_replystr)
{
	char *str;
	char *rest = msg;

	str = teamd_usock_msg_getline(&rest);
	if (!str) {
		err(tdc, "usock: Incomplete message.\n");
		return -EINVAL;;
	}

	if (!strcmp(TEAMD_USOCK_REPLY_SUCC_PREFIX, str)) {
		*p_replystr = rest;
	} else if (!strcmp(TEAMD_USOCK_REPLY_ERR_PREFIX, str)) {
		str = teamd_usock_msg_getline(&rest);
		if (!str) {
			err(tdc, "usock: Incomplete message.\n");
			return -EINVAL;;
		}
		err(tdc, "Error message received: \"%s\"", str);
		str = teamd_usock_msg_getline(&rest);
		if (!str) {
			err(tdc, "usock: Incomplete message.\n");
			return -EINVAL;;
		}
		err(tdc, "Error message content: \"%s\"", str);
		return -EINVAL;;
	} else {
		err(tdc, "Unsupported message type.\n");
		return -EINVAL;
	}
	return 0;
}

static int cli_usock_send(int sock, char *msg)
{
	int err;

	err = send(sock, msg, strlen(msg), MSG_NOSIGNAL);
	if (err == -1)
		return -errno;
	return 0;
}

#define WAIT_USEC (TEAMDCTL_REPLY_TIMEOUT * 1000)

static int cli_usock_wait_recv(int sock)
{
	fd_set rfds;
	int fdmax;
	int ret;
	struct timeval tv;

	tv.tv_sec = 0;
	tv.tv_usec = WAIT_USEC;
	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	fdmax = sock + 1;
	ret = select(fdmax, &rfds, NULL, NULL, &tv);
	if (ret == -1)
		return -errno;
	if (!FD_ISSET(sock, &rfds))
		return -ETIMEDOUT;
	return 0;
}

static int myasprintf(char **p_str, const char *fmt, ...)
{
	char *newstr;
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = vasprintf(&newstr, fmt, ap);
	va_end(ap);
	if (ret == -1)
		return -ENOMEM;
	free(*p_str);
	*p_str = newstr;
	return 0;
}

static int cli_usock_method_call(struct teamdctl *tdc, const char *method_name,
				 char **p_reply, void *priv,
				 const char *fmt, va_list ap)
{
	struct cli_usock_priv *cli_usock = priv;
	char *str;
	char *msg = NULL;
	char *recvmsg = recvmsg;
	char *replystr;
	int err;

	dbg(tdc, "Calling method \"%s\"", method_name);
	err= myasprintf(&msg, "%s\n%s\n", TEAMD_USOCK_REQUEST_PREFIX,
					  method_name);
	if (err)
		return err;
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			str = va_arg(ap, char *);
			err = myasprintf(&msg, "%s%s\n", msg, str);
			if (err)
				goto free_msg;
			break;
		default:
			err(tdc, "Unknown argument type requested.");
			err = -EINVAL;
			goto free_msg;
		}
	}

	err = cli_usock_send(cli_usock->sock, msg);
	if (err)
		goto free_msg;

	err = cli_usock_wait_recv(cli_usock->sock);
	if (err) {
		if (err == -ETIMEDOUT)
			dbg(tdc, "Wait for reply timed-out.");
		goto free_msg;
	}

	err = teamd_usock_recv_msg(cli_usock->sock, &recvmsg);
	if (err)
		goto free_msg;

	err = cli_usock_process_msg(tdc, recvmsg, &replystr);
	if (err)
		goto free_recvmsg;

	if (p_reply) {
		replystr = strdup(replystr);
		if (!replystr) {
			err = -ENOMEM;
			goto free_recvmsg;
		}
		*p_reply = replystr;
	}

free_recvmsg:
	free(recvmsg);
free_msg:
	free(msg);
	return err;
}

static int cli_usock_init(struct teamdctl *tdc, const char *team_name,
			  void *priv)
{
	struct cli_usock_priv *cli_usock = priv;
	struct sockaddr_un addr;
	int err;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	teamd_usock_get_sockpath(addr.sun_path, sizeof(addr.sun_path),
				 team_name);

	cli_usock->sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (cli_usock->sock == -1) {
		err(tdc, "Failed to create socket.");
		return -errno;
	}

	err = connect(cli_usock->sock, (struct sockaddr *) &addr,
		      strlen(addr.sun_path) + sizeof(addr.sun_family));
	if (err == -1) {
		err(tdc, "Failed to connect socket (%s).", addr.sun_path);
		close(cli_usock->sock);
		return -errno;
	}
	return 0;
}

void cli_usock_fini(struct teamdctl *tdc, void *priv)
{
	struct cli_usock_priv *cli_usock = priv;

	close(cli_usock->sock);
}

static const struct teamdctl_cli cli_usock = {
	.name = "usock",
	.init = cli_usock_init,
	.fini = cli_usock_fini,
	.method_call = cli_usock_method_call,
	.priv_size = sizeof(struct cli_usock_priv),
};

const struct teamdctl_cli *teamdctl_cli_usock_get(void)
{
	return &cli_usock;
}
