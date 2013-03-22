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
	struct sockaddr_un addr;
};

static int cli_usock_open(struct teamdctl *tdc,
			  struct cli_usock_priv *cli_usock, int *p_sock)
{
	struct sockaddr_un *addr = &cli_usock->addr;
	int sock;
	int err;

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		err(tdc, "Failed to create socket.");
		return -errno;
	}

	err = connect(sock, (struct sockaddr *) addr,
		      strlen(addr->sun_path) + sizeof(addr->sun_family));
	if (err == -1) {
		err(tdc, "Failed to connect socket (%s).", addr->sun_path);
		close(sock);
		return -errno;
	}

	*p_sock = sock;
	return 0;
}

static int cli_usock_check_error_msg(struct teamdctl *tdc, char *msg)
{
	char *str;
	char *str2;

	if (!strncmp(TEAMD_USOCK_SUCC_PREFIX, msg,
		     strlen(TEAMD_USOCK_SUCC_PREFIX)))
		return 0;
	if (strncmp(TEAMD_USOCK_ERR_PREFIX, msg,
		    strlen(TEAMD_USOCK_ERR_PREFIX)))
		goto corrupted;

	str = strchr(msg, '\n');
	if (!str || str[1] == '\0')
		goto corrupted;
	str++;

	str2 = strchr(str, '\n');
	if (!str2 || str2[1] == '\0')
		goto corrupted;
	str2[0] = '\0';
	str2++;

	err(tdc, "Error message received: \"%s\"", str);

	str = strchr(str2, '\n');
	if (!str)
		goto corrupted;
	str[0] = '\0';

	err(tdc, "Error message content: \"%s\"", str2);

	return 0;
corrupted:
	err(tdc, "Corrupted message received.");
	return -EINVAL;
}

static char *cli_usock_get_reply_str(char *msg)
{
	char *str;

	str = strchr(msg, '\n');
	if (str)
		str++;
	return str;
}

static int cli_usock_send(int sock, char *msg)
{
	int err;

	err = send(sock, msg, strlen(msg), MSG_NOSIGNAL);
	if (err == -1)
		return -errno;
	return 0;
}

#define BUFLEN_STEP 1000

static int cli_usock_recv(int sock, char **pmsg)
{
	ssize_t len;
	char *buf = NULL;
	char *ptr = NULL;
	size_t buflen = 0;

another:
	buflen += BUFLEN_STEP;
	buf = realloc(buf, buflen);
	if (!buf) {
		free(buf);
		return -ENOMEM;
	}
	ptr = ptr ? ptr + BUFLEN_STEP : buf;
	len = recv(sock, ptr, BUFLEN_STEP, 0);
	switch (len) {
	case -1:
		free(buf);
		return -errno;
	case BUFLEN_STEP:
		goto another;
	case 0:
	default:
		break;
	}
	ptr[len] = '\0';
	*pmsg = buf;
	return 0;
}

static int cli_usock_method_call(struct teamdctl *tdc, const char *method_name,
				 char **p_reply, void *priv,
				 const char *fmt, va_list ap)
{
	struct cli_usock_priv *cli_usock = priv;
	char *str;
	char *msg;
	int sock = sock;
	char *recvmsg = recvmsg;
	char *reply;
	int err;

	dbg(tdc, "Calling method \"%s\"", method_name);
	err = asprintf(&msg, "%s\n", method_name);
	if (err == -1)
		return -ENOMEM;
	while (*fmt) {
		switch (*fmt++) {
		case 's': /* string */
			str = va_arg(ap, char *);
			err = asprintf(&msg, "%s%s\n", msg, str);
			if (err == -1) {
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

	err = asprintf(&msg, "%s\n", msg);
	if (err == -1) {
		err = -ENOMEM;
		goto free_msg;
	}

	err = cli_usock_open(tdc, cli_usock, &sock);
	if (err)
		goto free_msg;

	err = cli_usock_send(sock, msg);
	if (err)
		goto close_sock;

	err = cli_usock_recv(sock, &recvmsg);
	if (err)
		goto close_sock;

	err = cli_usock_check_error_msg(tdc, recvmsg);
	if (err)
		goto free_recvmsg;

	reply = cli_usock_get_reply_str(recvmsg);
	if (!reply) {
		err(tdc, "Corrupted message received.");
		err = -EINVAL;
		goto free_recvmsg;
	}

	if (p_reply) {
		reply = strdup(reply);
		if (!reply) {
			err = -ENOMEM;
			goto free_recvmsg;
		}
		*p_reply = reply;
	}

free_recvmsg:
	free(recvmsg);
close_sock:
	close(sock);
free_msg:
	free(msg);
	return err;
}

static int cli_usock_init(struct teamdctl *tdc, const char *team_name,
			  void *priv)
{
	struct cli_usock_priv *cli_usock = priv;
	struct sockaddr_un *addr = &cli_usock->addr;
	int sock;
	int err;

	memset(addr, 0, sizeof(*addr));
	addr->sun_family = AF_UNIX;
	teamd_usock_get_sockpath(addr->sun_path, sizeof(addr->sun_path),
				 team_name);
	err = cli_usock_open(tdc, cli_usock, &sock);
	if (err)
		return err;
	close(sock);
	return 0;
}

void cli_usock_fini(struct teamdctl *tdc, void *priv)
{
}

const struct teamdctl_cli teamdctl_cli_usock = {
	.name = "usock",
	.init = cli_usock_init,
	.fini = cli_usock_fini,
	.method_call = cli_usock_method_call,
	.priv_size = sizeof(struct cli_usock_priv),
};
