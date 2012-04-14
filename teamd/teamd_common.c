/*
 *   teamd_common.c - Common teamd functions
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>

#include "teamd.h"

int teamd_packet_sock_open(int *sock_p, const uint32_t ifindex,
			   const unsigned short family,
			   const struct sock_fprog *fprog)
{
	struct sockaddr_ll ll_my;
	int sock;
	int ret;
	int err;

	sock = socket(PF_PACKET, SOCK_DGRAM, 0);
	if (sock == -1) {
		teamd_log_err("Failed to create packet socket.");
		return -errno;
	}

	if (fprog) {
		ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
				 fprog, sizeof(*fprog));
		if (ret == -1) {
			teamd_log_err("Failed to attach filter.");
			err = -errno;
			goto close_sock;
		}
	}

	memset(&ll_my, 0, sizeof(ll_my));
	ll_my.sll_family = AF_PACKET;
	ll_my.sll_ifindex = ifindex;
	ll_my.sll_protocol = family;
	ret = bind(sock, (struct sockaddr *) &ll_my, sizeof(ll_my));
	if (ret == -1) {
		teamd_log_err("Failed to bind socket.");
		err = -errno;
		goto close_sock;
	}

	*sock_p = sock;
	return 0;
close_sock:
	close(sock);
	return err;
}

int teamd_getsockname_hwaddr(int sock, struct sockaddr_ll *addr,
			     size_t expected_len)
{
	socklen_t addr_len;
	int ret;

	addr_len = sizeof(*addr);
	ret = getsockname(sock, (struct sockaddr *) addr, &addr_len);
	if (ret == -1) {
		teamd_log_err("Failed to getsockname.");
		return -errno;
	}
	if (expected_len && addr->sll_halen != expected_len) {
		teamd_log_err("Unexpected length of hw address.");
		return -ENOTSUP;
	}
	return 0;
}
