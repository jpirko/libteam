/*   cli_zmq.c - Teamd daemon control library teamd ZeroMQ library client
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <zmq.h>
#include <errno.h>
#include <unistd.h>
#include <teamdctl.h>
#include "teamdctl_private.h"
#include "../teamd/teamd_zmq_common.h"

struct cli_zmq_priv {
	void *context;
	void *sock;
};

static int cli_zmq_process_msg(struct teamdctl *tdc, char *msg,
			       char **p_replystr)
{
	char *str;
	char *rest = msg;

	str = teamd_zmq_msg_getline(&rest);
	if (!str) {
		err(tdc, "zmq: Incomplete message.\n");
		return -EINVAL;;
	}

	if (!strcmp(TEAMD_ZMQ_REPLY_SUCC_PREFIX, str)) {
		*p_replystr = rest;
	} else if (!strcmp(TEAMD_ZMQ_REPLY_ERR_PREFIX, str)) {
		str = teamd_zmq_msg_getline(&rest);
		if (!str) {
			err(tdc, "zmq: Incomplete message.\n");
			return -EINVAL;;
		}
		err(tdc, "zmq: Error message received: \"%s\"", str);
		str = teamd_zmq_msg_getline(&rest);
		if (!str) {
			err(tdc, "zmq: Incomplete message.\n");
			return -EINVAL;;
		}
		err(tdc, "zmq: Error message content: \"%s\"", str);
		return -EINVAL;;
	} else {
		err(tdc, "zmq: Unsupported message type.\n");
		return -EINVAL;
	}
	return 0;
}

static int cli_zmq_send(struct teamdctl *tdc, void *sock, char *buf)
{
	int ret;
	int buflen = strlen(buf);

	ret = zmq_send(sock, buf, buflen, 0);

	if (ret == -1) {
		warn(tdc, "zmq: send failed: %s", strerror(errno));
		return -errno;
	}
	free(buf);
	return 0;
}

static int cli_zmq_recv(struct teamdctl *tdc, void *sock, char **p_str)
{
	int ret;
	zmq_msg_t msg;
	char *buf;

	if (zmq_msg_init(&msg) == -1) {
		dbg(tdc, "zmq: Unable initiate message for receive.");
		return -errno;
	}

	ret = zmq_msg_recv(&msg, sock, 0);

	if (ret == -1) {
		warn(tdc, "zmq: send failed: %s", strerror(errno));
		return -errno;
	}

	buf = malloc(ret + 1);
	memcpy(buf, zmq_msg_data(&msg), ret);
	buf[ret] = '\0';

	if (zmq_msg_close(&msg) == -1) {
		free(buf);
		dbg(tdc, "zmq: Unable close message.");
		return -errno;
	}

	*p_str = buf;
	return 0;
}

#define WAIT_MSEC TEAMDCTL_REPLY_TIMEOUT

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

static int cli_zmq_method_call(struct teamdctl *tdc, const char *method_name,
			       char **p_reply, void *priv,
			       const char *fmt, va_list ap)
{
	struct cli_zmq_priv *cli_zmq = priv;
	char *str;
	char *msg = NULL;
	char *recvmsg = recvmsg;
	char *replystr;
	int err;

	dbg(tdc, "zmq: Calling method \"%s\"", method_name);
	err = myasprintf(&msg, "%s\n%s\n", TEAMD_ZMQ_REQUEST_PREFIX,
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
			err(tdc, "zmq: Unknown argument type requested.");
			err = -EINVAL;
			goto free_msg;
		}
	}

	err = cli_zmq_send(tdc, cli_zmq->sock, msg);
	if (err)
		goto send_err;

	err = cli_zmq_recv(tdc, cli_zmq->sock, &recvmsg);
	if (err)
		goto send_err;

	err = cli_zmq_process_msg(tdc, recvmsg, &replystr);
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
	goto send_err;
free_msg:
	free(msg);
send_err:
	return err;
}

static int cli_zmq_init(struct teamdctl *tdc, const char *team_name,
			void *priv)
{
	int err;
	struct cli_zmq_priv *cli_zmq = priv;
	void *context, *sock;
	int recv_timeo;

	context = zmq_ctx_new();
	if (!context) {
		err(tdc, "zmq: Failed to create context.");
		return -errno;
	}

	sock = zmq_socket(context, ZMQ_REQ);
	if (!sock) {
		err(tdc, "zmq: Failed to create socket.");
		return -errno;
	}

	err = zmq_connect(sock, tdc->addr);
	if (err == -1) {
		err(tdc, "zmq: Failed to connect socket (%s).", tdc->addr);
		zmq_close(sock);
		zmq_ctx_destroy(context);
		return -errno;
	}

	recv_timeo = WAIT_MSEC;
	err = zmq_setsockopt(sock, ZMQ_RCVTIMEO, &recv_timeo,
			     sizeof(recv_timeo));
	if (err == -1) {
		err(tdc, "zmq: Failed set socket timeout.");
		zmq_close(sock);
		zmq_ctx_destroy(context);
		return -errno;
	}

	cli_zmq->sock = sock;
	cli_zmq->context = context;

	return 0;
}

void cli_zmq_fini(struct teamdctl *tdc, void *priv)
{
	struct cli_zmq_priv *cli_zmq = priv;

	zmq_close(cli_zmq->sock);
	zmq_ctx_destroy(cli_zmq->context);
}

static const struct teamdctl_cli cli_zmq = {
	.name = "zmq",
	.init = cli_zmq_init,
	.fini = cli_zmq_fini,
	.method_call = cli_zmq_method_call,
	.priv_size = sizeof(struct cli_zmq_priv),
};

const struct teamdctl_cli *teamdctl_cli_zmq_get(void)
{
	return &cli_zmq;
}

#endif /* ENABLE_ZMQ */
