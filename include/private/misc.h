/*
 *   misc.c - Miscellaneous helpers
 *   Copyright (C) 2011-2015 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _T_MISC_H_
#define _T_MISC_H_

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <linux/if.h>

static inline void *myzalloc(size_t size)
{
	return calloc(1, size);
}

static inline size_t mystrlcpy(char *dst, const char *src, size_t size)
{
	size_t ret = strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;

		memcpy(dst, src, len);
		dst[len] = '\0';
	}
	return ret;
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static inline void hwaddr_str(char *str, char *hwaddr, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		sprintf(str, "%02x:", (unsigned char) hwaddr[i]);
		str += 3;
	}
	if (len)
		str--;
	*str = '\0';
}

static inline size_t hwaddr_str_len(size_t len)
{
	return len * 3 + 1;
}

static inline char *a_hwaddr_str(char *hwaddr, size_t len)
{
	char *str;

	str = malloc(sizeof(char) * hwaddr_str_len(len));
	if (!str)
		return NULL;
	hwaddr_str(str, hwaddr, len);
	return str;
}

static inline int ifname2ifindex(uint32_t *p_ifindex, char *ifname)
{
	int sock;
	struct ifreq ifr;
	int ret;

	sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (sock == -1)
		return -errno;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ret = ioctl(sock, SIOCGIFINDEX, &ifr);
	close(sock);
	if (ret == -1) {
		if (errno == ENODEV)
			*p_ifindex = 0;
		else
			return -errno;
	} else {
		*p_ifindex = ifr.ifr_ifindex;
	}
	return 0;
}

#endif /* _T_MISC_H_ */
