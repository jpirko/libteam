/*
 *   teamd_usock_common.h - Teamd unix socket api common things
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

#ifndef _TEAMD_USOCK_COMMON_H_
#define _TEAMD_USOCK_COMMON_H_

#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#include "teamd.h"

#define TEAMD_USOCK_REQUEST_PREFIX	"REQUEST"
#define TEAMD_USOCK_REPLY_ERR_PREFIX	"REPLY_ERROR"
#define TEAMD_USOCK_REPLY_SUCC_PREFIX	"REPLY_SUCCESS"

static inline void teamd_usock_get_sockpath(char *sockpath, size_t sockpath_len,
					    const char *team_devname)
{
	snprintf(sockpath, sockpath_len, TEAMD_RUN_DIR"%s.sock", team_devname);
}

static inline int teamd_usock_recv_msg(int sock, char **p_str)
{
	ssize_t len;
	int expected_len;
	char *buf;
	int ret;

	ret = ioctl(sock, SIOCINQ, &expected_len);
	if (ret == -1)
		return -errno;

	buf = malloc(expected_len + 1);
	if (!buf)
		return -ENOMEM;
	len = recv(sock, buf, expected_len, 0);
	switch (len) {
	case -1:
		free(buf);
		return -errno;
	case 0:
		free(buf);
		/* use EPIPE to tell caller the connection was broken */
		return -EPIPE;
	}
	buf[len] = '\0';
	*p_str = buf;
	return 0;
}

static inline char *teamd_usock_msg_getline(char **p_rest)
{
	char *start = NULL;
	char *rest = NULL;
	char *str = *p_rest;

	if (!str)
		return NULL;
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
	*p_rest = rest;
	return start;
}

#endif /* _TEAMD_USOCK_COMMON_H_ */
