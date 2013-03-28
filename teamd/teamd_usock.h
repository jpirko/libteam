/*
 *   teamd_usock.h - Teamd unix socket api
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

#ifndef _TEAMD_USOCK_H_
#define _TEAMD_USOCK_H_

#include <stdio.h>
#include <errno.h>

#include "teamd.h"

#define TEAMD_USOCK_ERR_PREFIX	"ERROR\n"
#define TEAMD_USOCK_SUCC_PREFIX	"SUCCESS\n"

static inline void teamd_usock_get_sockpath(char *sockpath, size_t sockpath_len,
					    const char *team_devname)
{
	snprintf(sockpath, sockpath_len, TEAMD_RUN_DIR"%s.sock", team_devname);
}

#define TEAMD_USOCK_BUFLEN_STEP 1000

static inline int teamd_usock_recv_msg(int sock, char **p_str)
{
	ssize_t len;
	char *buf = NULL;
	char *ptr = NULL;
	size_t buflen = 0;
	fd_set rfds;
	int fdmax;
	int ret;

	FD_ZERO(&rfds);
	FD_SET(sock, &rfds);
	fdmax = sock + 1;
	ret = select(fdmax, &rfds, NULL, NULL, NULL);
	if (ret == -1)
		return -errno;
another:
	buflen += TEAMD_USOCK_BUFLEN_STEP;
	buf = realloc(buf, buflen);
	if (!buf) {
		free(buf);
		return -ENOMEM;
	}
	ptr = ptr ? ptr + TEAMD_USOCK_BUFLEN_STEP : buf;
	len = recv(sock, ptr, TEAMD_USOCK_BUFLEN_STEP, MSG_DONTWAIT);
	switch (len) {
	case -1:
		if (errno == EAGAIN) {
			len = 0;
			break;
		}
		free(buf);
		return -errno;
	case TEAMD_USOCK_BUFLEN_STEP:
		goto another;
	case 0:
		free(buf);
		/* use EPIPE to tell caller the connection was broken */
		return -EPIPE;
	}
	ptr[len] = '\0';
	*p_str = buf;
	return 0;
}
#endif /* _TEAMD_USOCK_H_ */
