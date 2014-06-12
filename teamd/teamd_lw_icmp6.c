/*
 *   teamd_lw_icmp6.c - Team port IPv6 NS/NA link watcher
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
 *   Copyright (C) 2014 Erik Hugne <erik.hugne@ericsson.com>
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

#include <netdb.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/if_ether.h>
#include <private/misc.h>
#include "teamd.h"
#include "teamd_link_watch.h"
#include "teamd_config.h"

/*
 * IPV6 NS/NA ping link watch
 */

static int set_sockaddr_in6(struct sockaddr_in6 *sin6, const char *hostname)
{
	int err;

	err = __set_sockaddr((struct sockaddr *) sin6, sizeof(*sin6),
			     AF_INET6, hostname);
	if (err)
		return err;
	return 0;
}

static char *str_sockaddr_in6(struct sockaddr_in6 *sin6)
{
	static char buf[NI_MAXHOST];
	return __str_sockaddr((struct sockaddr *) sin6,
			      sizeof(*sin6), AF_INET6, buf);
}

struct lw_nsnap_port_priv {
	union {
		struct lw_common_port_priv common;
		struct lw_psr_port_priv psr;
	} start; /* must be first */
	int tx_sock;
	struct sockaddr_in6 dst;
};

static struct lw_nsnap_port_priv *
lw_nsnap_ppriv_get(struct lw_psr_port_priv *psr_ppriv)
{
	return (struct lw_nsnap_port_priv *) psr_ppriv;
}

static int icmp6_sock_open(int *sock_p)
{
	int sock;
	struct icmp6_filter flt;
	int ret;
	int err;
	int val;

	sock = socket(PF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	if (sock == -1) {
		teamd_log_err("Failed to create ICMP6 socket.");
		return -errno;
	}

	ICMP6_FILTER_SETBLOCKALL(&flt);
	ret = setsockopt(sock, IPPROTO_ICMPV6, ICMP6_FILTER, &flt, sizeof(flt));
	if (ret == -1) {
		teamd_log_err("Failed to setsockopt ICMP6_FILTER.");
		err = -errno;
		goto close_sock;
	}

	val = 255;
	ret = setsockopt(sock, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
			 &val, sizeof(val));
	if (ret == -1) {
		teamd_log_err("Failed to setsockopt IPV6_MULTICAST_HOPS.");
		err = -errno;
		goto close_sock;
	}

	*sock_p = sock;
	return 0;
close_sock:
	close(sock);
	return err;
}

#define OFFSET_NEXT_HEADER					\
	in_struct_offset(struct ip6_hdr, ip6_nxt)
#define OFFSET_NA_TYPE						\
	sizeof (struct ip6_hdr) +				\
	in_struct_offset(struct nd_neighbor_advert, nd_na_type)

static struct sock_filter na_flt[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, OFFSET_NEXT_HEADER),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, OFFSET_NA_TYPE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static const struct sock_fprog na_fprog = {
	.len = ARRAY_SIZE(na_flt),
	.filter = na_flt,
};

static int lw_nsnap_sock_open(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);
	int err;

	/*
	 * We use two sockets here. NS packets are send through ICMP6 socket.
	 * With this socket, unfortunately, kernel does not provide a way to
	 * deliver incoming ICMP6 packet on inactive ports into userspace.
	 * So we use packet socket to get these packets.
	 */
	err = teamd_packet_sock_open(&psr_ppriv->sock,
				     psr_ppriv->common.tdport->ifindex,
				     htons(ETH_P_IPV6), &na_fprog, NULL);
	if (err)
		return err;
	err = icmp6_sock_open(&nsnap_ppriv->tx_sock);
	if (err)
		goto close_packet_sock;
	return 0;
close_packet_sock:
	close(psr_ppriv->sock);
	return err;
}

static void lw_nsnap_sock_close(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);

	close(nsnap_ppriv->tx_sock);
	close(psr_ppriv->sock);
}

static int lw_nsnap_load_options(struct teamd_context *ctx,
				 struct teamd_port *tdport,
				 struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);
	struct teamd_config_path_cookie *cpcookie = psr_ppriv->common.cpcookie;
	const char *host;
	int err;

	err = teamd_config_string_get(ctx, &host, "@.target_host", cpcookie);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -EINVAL;
	}
	err = set_sockaddr_in6(&nsnap_ppriv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("target address \"%s\".",
		      str_sockaddr_in6(&nsnap_ppriv->dst));

	return 0;
}

static void compute_multi_in6_addr(struct in6_addr *addr)
{
	addr->s6_addr32[0] = htonl(0xFF020000);
	addr->s6_addr32[1] = 0;
	addr->s6_addr32[2] = htonl(0x1);
	addr->s6_addr32[3] |= htonl(0xFF000000);
}

struct ns_packet {
	struct nd_neighbor_solicit	nsh;
	struct nd_opt_hdr		opt;
	unsigned char			hwaddr[ETH_ALEN];
};

static int lw_nsnap_send(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);
	int err;
	struct sockaddr_ll ll_my;
	struct sockaddr_in6 sendto_addr;
	struct ns_packet nsp;

	err = teamd_getsockname_hwaddr(psr_ppriv->sock, &ll_my,
				       sizeof(nsp.hwaddr));
	if (err)
		return err;

	memset(&nsp, 0, sizeof(nsp));

	/* setup ICMP6 header */
	nsp.nsh.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	nsp.nsh.nd_ns_cksum = 0; /* kernel computes this */
	nsp.nsh.nd_ns_target = nsnap_ppriv->dst.sin6_addr;
	nsp.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nsp.opt.nd_opt_len = 1; /* 8 bytes */
	memcpy(nsp.hwaddr, ll_my.sll_addr, sizeof(nsp.hwaddr));

	sendto_addr = nsnap_ppriv->dst;
	compute_multi_in6_addr(&sendto_addr.sin6_addr);
	sendto_addr.sin6_scope_id = psr_ppriv->common.tdport->ifindex;
	err = teamd_sendto(nsnap_ppriv->tx_sock, &nsp, sizeof(nsp), 0,
			   (struct sockaddr *) &sendto_addr,
			   sizeof(sendto_addr));
	return err;
}

struct na_packet {
	struct ip6_hdr			ip6h;
	struct nd_neighbor_advert	nah;
	struct nd_opt_hdr		opt;
	unsigned char			hwaddr[ETH_ALEN];
};

static int lw_nsnap_receive(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);
	struct na_packet nap;
	struct sockaddr_ll ll_from;
	int err;

	err = teamd_recvfrom(psr_ppriv->sock, &nap, sizeof(nap), 0,
			     (struct sockaddr *) &ll_from, sizeof(ll_from));
	if (err <= 0)
		return err;

	/* check IPV6 header */
	if (nap.ip6h.ip6_vfc != 0x60 /* IPV6 */ ||
	    nap.ip6h.ip6_plen != htons(sizeof(nap) - sizeof(nap.ip6h)) ||
	    nap.ip6h.ip6_nxt != IPPROTO_ICMPV6 ||
	    nap.ip6h.ip6_hlim != 255 /* Do not route */ ||
	    memcmp(&nap.ip6h.ip6_src, &nsnap_ppriv->dst.sin6_addr,
		   sizeof(struct in6_addr)))
		return 0;

	/* check ICMP6 header */
	if (nap.nah.nd_na_type != ND_NEIGHBOR_ADVERT ||
	    nap.opt.nd_opt_type != ND_OPT_TARGET_LINKADDR ||
	    nap.opt.nd_opt_len != 1 /* 8 bytes */)
		return 0;

	psr_ppriv->reply_received = true;
	return 0;
}

static const struct lw_psr_ops lw_psr_ops_nsnap = {
	.sock_open		= lw_nsnap_sock_open,
	.sock_close		= lw_nsnap_sock_close,
	.load_options		= lw_nsnap_load_options,
	.send			= lw_nsnap_send,
	.receive		= lw_nsnap_receive,
};

static int lw_nsnap_port_added(struct teamd_context *ctx,
			       struct teamd_port *tdport,
			       void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_port_priv = priv;

	psr_port_priv->ops = &lw_psr_ops_nsnap;
	return lw_psr_port_added(ctx, tdport, priv, creator_priv);
}

static int lw_nsnap_state_target_host_get(struct teamd_context *ctx,
					  struct team_state_gsc *gsc,
				          void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_nsnap_port_priv *nsnap_ppriv = lw_nsnap_ppriv_get(psr_ppriv);

	gsc->data.str_val.ptr = str_sockaddr_in6(&nsnap_ppriv->dst);
	return 0;
}

static const struct teamd_state_val lw_nsnap_state_vals[] = {
	{
		.subpath = "target_host",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_nsnap_state_target_host_get,
	},
	{
		.subpath = "interval",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_interval_get,
	},
	{
		.subpath = "init_wait",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_init_wait_get,
	},
	{
		.subpath = "missed_max",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_missed_max_get,
	},
	{
		.subpath = "missed",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_missed_get,
	},
};

const struct teamd_link_watch teamd_link_watch_nsnap = {
	.name			= "nsna_ping",
	.state_vg		= {
		.vals		= lw_nsnap_state_vals,
		.vals_count	= ARRAY_SIZE(lw_nsnap_state_vals),
	},
	.port_priv = {
		.init		= lw_nsnap_port_added,
		.fini		= lw_psr_port_removed,
		.priv_size	= sizeof(struct lw_nsnap_port_priv),
	},
};


