/*
 *   teamd_zmq_common.h - Teamd unix socket api common things
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

#ifndef _TEAMD_ZMQ_COMMON_H_
#define _TEAMD_ZMQ_COMMON_H_

#include <stdio.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>

#define TEAMD_ZMQ_REQUEST_PREFIX	"REQUEST"
#define TEAMD_ZMQ_REPLY_ERR_PREFIX	"REPLY_ERROR"
#define TEAMD_ZMQ_REPLY_SUCC_PREFIX	"REPLY_SUCCESS"

static inline char *teamd_zmq_msg_getline(char **p_rest)
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

#endif /* _TEAMD_ZMQ_COMMON_H_ */
