/*
 *   teamd_common.c - Common teamd functions
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

#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <pwd.h>
#include <sys/stat.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <private/misc.h>

#include "teamd.h"

static struct sock_filter bad_flt[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static const struct sock_fprog bad_fprog = {
	.len = ARRAY_SIZE(bad_flt),
	.filter = bad_flt,
};

static int attach_filter(int sock, const struct sock_fprog *pref_fprog,
			 const struct sock_fprog *alt_fprog)
{
	int ret;
	const struct sock_fprog *fprog;

	if (!pref_fprog)
		return 0;

	/* Now we are in tough situation. Older kernels (<3.8) does not
	 * support SKF_AD_VLAN_TAG_PRESENT and SKF_AD_VLAN_TAG. But the kernel
	 * check if these are supported was added after that:
	 * aa1113d9f85da59dcbdd32aeb5d71da566e46def
	 * But it was added close enough. So try to attach obviously bad
	 * filter and assume that is it does not fail, kernel does not support
	 * accessing skb->vlan_tci getting and use alternative filter instead.
	 */

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			 &bad_fprog, sizeof(bad_fprog));
	if (ret == -1) {
		if (errno != EINVAL)
			return -errno;
		fprog = pref_fprog;
	}
	else if (alt_fprog) {
		teamd_log_warn("Kernel does not support accessing skb->vlan_tci from BPF,\n"
			       "falling back to alternative filter. Expect vlan-tagged ARPs\n"
			       "to be accounted on non-tagged link monitor and vice versa.");
		fprog = alt_fprog;
	} else {
		return 0;
	}

	ret = setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER,
			 fprog, sizeof(*fprog));
	if (ret == -1)
		return -errno;
	return 0;
}

int teamd_packet_sock_open(int *sock_p, const uint32_t ifindex,
			   const unsigned short family,
			   const struct sock_fprog *fprog,
			   const struct sock_fprog *alt_fprog)
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

	err = attach_filter(sock, fprog, alt_fprog);
	if (err) {
		teamd_log_err("Failed to attach filter.");
		goto close_sock;
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

int teamd_sendto(int sockfd, const void *buf, size_t len, int flags,
		 const struct sockaddr *dest_addr, socklen_t addrlen)
{
	ssize_t ret;

resend:
	ret = sendto(sockfd, buf, len, flags, dest_addr, addrlen);
	if (ret == -1) {
		switch(errno) {
		case EINTR:
			goto resend;
		case ENETDOWN:
		case ENETUNREACH:
		case EADDRNOTAVAIL:
		case ENXIO:
			return 0;
		default:
			teamd_log_err("sendto failed.");
			return -errno;
		}
	}
	return 0;
}

int teamd_recvfrom(int sockfd, void *buf, size_t len, int flags,
		   struct sockaddr *src_addr, socklen_t addrlen)
{
	size_t ret;
	socklen_t tmp_addrlen = addrlen;

rerecv:
	ret = recvfrom(sockfd, buf, len, flags, src_addr, &tmp_addrlen);
	if (ret == -1) {
		switch(errno) {
		case EINTR:
			goto rerecv;
		case ENETDOWN:
			return 0;
		default:
			teamd_log_err("recvfrom failed.");
			return -errno;
		}
	}
	return ret;
}
