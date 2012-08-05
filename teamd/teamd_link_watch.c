/*
 *   teamd_link_watch.c - Team port link watchers
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

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <net/if_arp.h>
#include <linux/filter.h>
#include <time.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

struct lw_common_port_priv {
	const struct teamd_link_watch *link_watch;
	json_t *link_watch_json;
};

struct teamd_link_watch {
	const char *name;
	bool (*is_port_up)(struct teamd_context *ctx, struct teamd_port *tdport,
			   struct lw_common_port_priv *common_ppriv);
	struct teamd_port_priv port_priv;
};

static int __set_sockaddr(struct sockaddr *sa, socklen_t sa_len,
			  sa_family_t family, const char *hostname)
{
	struct addrinfo *result;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	err = getaddrinfo(hostname, NULL, &hints, &result);
	if (err) {
		teamd_log_err("getaddrinfo failed: %s", gai_strerror(err));
		return -ENOENT;
	}
	if (sa_len != result->ai_addrlen) {
		/* This should not happen, so just to be safe */
		teamd_log_err("Wrong address length in result.");
		return -EINVAL;
	}
	memcpy(sa, result->ai_addr, sa_len);
	freeaddrinfo(result);
	return 0;
}

static int set_in_addr(struct in_addr *addr, const char *hostname)
{
	struct sockaddr_in sin;
	int err;

	err = __set_sockaddr((struct sockaddr *) &sin, sizeof(sin),
			     AF_INET, hostname);
	if (err)
		return err;
	memcpy(addr, &sin.sin_addr, sizeof(*addr));
	return 0;
}

static int set_sockaddr_in6(struct sockaddr_in6 *sin6, const char *hostname)
{
	int err;

	err = __set_sockaddr((struct sockaddr *) sin6, sizeof(*sin6),
			     AF_INET6, hostname);
	if (err)
		return err;
	return 0;
}

static char *__str_sockaddr(struct sockaddr *sa, socklen_t sa_len,
			    sa_family_t family)
{
	static char buf[NI_MAXHOST];
	int err;

	sa->sa_family = family;
	err = getnameinfo(sa, sa_len, buf, sizeof(buf),
			  NULL, 0, NI_NUMERICHOST);
	if (err) {
		teamd_log_err("getnameinfo failed: %s", gai_strerror(err));
		return NULL;
	}
	return buf;
}

static char *str_in_addr(struct in_addr *addr)
{
	struct sockaddr_in sin;

	memcpy(&sin.sin_addr, addr, sizeof(*addr));
	return __str_sockaddr((struct sockaddr *) &sin,
			      sizeof(sin), AF_INET);
}

static char *str_sockaddr_in6(struct sockaddr_in6 *sin6)
{
	return __str_sockaddr((struct sockaddr *) sin6,
			      sizeof(*sin6), AF_INET6);
}

/*
 * Ethtool link watch
 */

static bool lw_ethtool_is_port_up(struct teamd_context *ctx,
				  struct teamd_port *tdport,
				  struct lw_common_port_priv *common_ppriv)
{
	struct team_port *port;

	team_for_each_port(port, ctx->th)
		if (team_get_port_ifindex(port) == tdport->ifindex)
			return team_is_port_link_up(port);
	return false;
}

struct lw_ethtool_port_priv {
	struct lw_common_port_priv common; /* must be first */
};

const struct teamd_link_watch teamd_link_watch_ethtool = {
	.name			= "ethtool",
	.is_port_up		= lw_ethtool_is_port_up,
	.port_priv = {
		.priv_size	= sizeof(struct lw_ethtool_port_priv),
	},
};


/*
 * Generic periodic send/receive link watch "template"
 */

struct lw_psr_port_priv;

struct lw_psr_ops {
	int (*sock_open)(struct lw_psr_port_priv *psr_ppriv);
	void (*sock_close)(struct lw_psr_port_priv *psr_ppriv);
	int (*load_options)(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    struct lw_psr_port_priv *psr_ppriv);
	int (*send)(struct lw_psr_port_priv *psr_ppriv);
	int (*receive)(struct lw_psr_port_priv *psr_ppriv);
	struct timespec default_init_wait;
};

struct lw_psr_port_priv {
	struct lw_common_port_priv common; /* must be first */
	struct teamd_port *tdport;
	const struct lw_psr_ops *ops;
	struct timespec interval;
	struct timespec init_wait;
	unsigned int missed_max;
	int sock;
	char *cb_name_periodic;
	char *cb_name_socket;
	unsigned int missed;
	bool reply_received;
	bool link_up;
};

static struct lw_psr_port_priv *
lw_psr_ppriv_get(struct lw_common_port_priv *common_ppriv)
{
	return (struct lw_psr_port_priv *) common_ppriv;
}

static int lw_psr_callback_periodic(struct teamd_context *ctx, int events,
				    void *func_priv)
{
	struct lw_psr_port_priv *psr_ppriv = func_priv;
	struct teamd_port *tdport = psr_ppriv->tdport;
	bool orig_link_up = psr_ppriv->link_up;
	const char *lw_name = psr_ppriv->common.link_watch->name;
	int err;

	if (psr_ppriv->reply_received) {
		psr_ppriv->link_up = true;
		psr_ppriv->missed = 0;
	} else {
		psr_ppriv->missed++;
		if (psr_ppriv->missed > psr_ppriv->missed_max &&
		    orig_link_up) {
			teamd_log_dbg("%s: Missed %u replies (max %u).",
				      tdport->ifname, psr_ppriv->missed,
				      psr_ppriv->missed_max);
			psr_ppriv->link_up = false;
		}
	}
	if (psr_ppriv->link_up != orig_link_up) {
		teamd_log_info("%s: %s-link went %s.", tdport->ifname, lw_name,
			       psr_ppriv->link_up ? "up" : "down");
		err = teamd_event_port_link_changed(ctx, tdport);
		if (err)
			return err;
		err = team_set_port_user_linkup(ctx->th,
						psr_ppriv->tdport->ifindex,
						psr_ppriv->link_up);
		if (err)
			return err;
	}
	psr_ppriv->reply_received = false;
	return psr_ppriv->ops->send(psr_ppriv);
}

static int lw_psr_callback_socket(struct teamd_context *ctx, int events,
				  void *func_priv)
{
	struct lw_psr_port_priv *psr_ppriv = func_priv;

	return psr_ppriv->ops->receive(psr_ppriv);
}

static int lw_psr_load_options(struct teamd_context *ctx,
			       struct teamd_port *tdport,
			       struct lw_psr_port_priv *psr_ppriv)
{
	json_t *link_watch_json = psr_ppriv->common.link_watch_json;
	int err;
	int tmp;

	err = json_unpack(link_watch_json, "{s:i}", "interval", &tmp);
	if (err) {
		teamd_log_err("%s: Failed to get \"interval\" link-watch "
			      "option.", tdport->ifname);
		return -ENOENT;
	}
	teamd_log_dbg("%s: Using interval \"%d\".", tdport->ifname, tmp);
	ms_to_timespec(&psr_ppriv->interval, tmp);

	err = json_unpack(link_watch_json, "{s:i}", "init_wait", &tmp);
	if (!err) {
		teamd_log_dbg("%s: Using init_wait \"%d\".",
			      tdport->ifname, tmp);
		ms_to_timespec(&psr_ppriv->init_wait, tmp);
	} else {
		psr_ppriv->init_wait = psr_ppriv->ops->default_init_wait;
	}

	err = json_unpack(link_watch_json, "{s:i}", "missed_max", &tmp);
	if (err) {
		teamd_log_err("%s: Failed to get \"missed_max\" link-watch "
			      "option.", tdport->ifname);
		return -ENOENT;
	}
	if (tmp < 0) {
		teamd_log_err("%s: \"missed_max\" must not be negative "
			      "number.", tdport->ifname);
		return -EINVAL;
	}
	teamd_log_dbg("%s: Using missed_max \"%d\".", tdport->ifname, tmp);
	psr_ppriv->missed_max = tmp;
	return 0;
}

static int lw_psr_port_added(struct teamd_context *ctx,
			     struct teamd_port *tdport,
			     void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_ppriv = priv;
	const char *lw_name = psr_ppriv->common.link_watch->name;
	int err;

	psr_ppriv->tdport = tdport;
	err = psr_ppriv->ops->sock_open(psr_ppriv);
	if (err) {
		teamd_log_err("Failed to create socket.");
		return err;
	}

	err = lw_psr_load_options(ctx, tdport, psr_ppriv);
	if (err) {
		teamd_log_err("Failed to load options.");
		goto close_sock;
	}

	err = psr_ppriv->ops->load_options(ctx, tdport, psr_ppriv);
	if (err) {
		teamd_log_err("Failed to load options.");
		goto close_sock;
	}

	err = asprintf(&psr_ppriv->cb_name_socket, "%s_socket_if%d", lw_name,
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto close_sock;
	}

	err = teamd_loop_callback_fd_add(ctx, psr_ppriv->cb_name_socket,
					 psr_ppriv->sock,
					 TEAMD_LOOP_FD_EVENT_READ,
					 lw_psr_callback_socket, psr_ppriv);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto free_cb_name_socket;
	}

	err = asprintf(&psr_ppriv->cb_name_periodic, "%s_periodic_if%d", lw_name,
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto socket_callback_del;
	}

	err = teamd_loop_callback_timer_add_set(ctx,
						psr_ppriv->cb_name_periodic,
						&psr_ppriv->interval,
						&psr_ppriv->init_wait,
						lw_psr_callback_periodic,
						psr_ppriv);
	if (err) {
		teamd_log_err("Failed add callback timer");
		goto free_periodic_cb_name;
	}

	err = team_set_port_user_linkup_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
		teamd_log_err("%s: Failed to enable user linkup.",
			      tdport->ifname);
		goto periodic_callback_del;
	}

	teamd_loop_callback_enable(ctx, psr_ppriv->cb_name_socket);
	teamd_loop_callback_enable(ctx, psr_ppriv->cb_name_periodic);
	return 0;

periodic_callback_del:
	teamd_loop_callback_del(ctx, psr_ppriv->cb_name_periodic);
free_periodic_cb_name:
	free(psr_ppriv->cb_name_periodic);
socket_callback_del:
	teamd_loop_callback_del(ctx, psr_ppriv->cb_name_socket);
free_cb_name_socket:
	free(psr_ppriv->cb_name_socket);
close_sock:
	psr_ppriv->ops->sock_close(psr_ppriv);
	return err;
}

static void lw_psr_port_removed(struct teamd_context *ctx,
				struct teamd_port *tdport,
				void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_ppriv = priv;

	teamd_loop_callback_del(ctx, psr_ppriv->cb_name_periodic);
	free(psr_ppriv->cb_name_periodic);
	teamd_loop_callback_del(ctx, psr_ppriv->cb_name_socket);
	free(psr_ppriv->cb_name_socket);
	psr_ppriv->ops->sock_close(psr_ppriv);
}

static bool lw_psr_is_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      struct lw_common_port_priv *common_ppriv)
{
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);

	return psr_ppriv->link_up;
}


/*
 * ARP ping link watch
 */

struct lw_ap_port_priv {
	union {
		struct lw_common_port_priv common;
		struct lw_psr_port_priv psr;
	} start; /* must be first */
	struct in_addr src;
	struct in_addr dst;
};

static struct lw_ap_port_priv *
lw_ap_ppriv_get(struct lw_psr_port_priv *psr_ppriv)
{
	return (struct lw_ap_port_priv *) psr_ppriv;
}

#define OFFSET_ARP_OP_CODE					\
	in_struct_offset(struct arphdr, ar_op)

struct sock_filter arp_rpl_flt[] = {
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, OFFSET_ARP_OP_CODE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

const struct sock_fprog arp_rpl_fprog = {
	.len = ARRAY_SIZE(arp_rpl_flt),
	.filter = arp_rpl_flt,
};

static int lw_ap_sock_open(struct lw_psr_port_priv *psr_ppriv)
{
	return teamd_packet_sock_open(&psr_ppriv->sock,
				      psr_ppriv->tdport->ifindex,
				      htons(ETH_P_ARP), &arp_rpl_fprog);
}

static void lw_ap_sock_close(struct lw_psr_port_priv *psr_ppriv)
{
	close(psr_ppriv->sock);
}

static int lw_ap_load_options(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	json_t *link_watch_json = psr_ppriv->common.link_watch_json;
	char *host;
	int err;

	err = json_unpack(link_watch_json, "{s:s}", "source_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"source_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&ap_ppriv->src, host);
	if (err)
		return err;
	teamd_log_dbg("Using source address \"%s\".",
		      str_in_addr(&ap_ppriv->src));

	err = json_unpack(link_watch_json, "{s:s}", "target_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&ap_ppriv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("Using target address \"%s\".", str_in_addr(&ap_ppriv->dst));

	return 0;
}

static void buf_push(char **pos, void *data, size_t data_len)
{
	memcpy(*pos, data, data_len);
	*pos += data_len;
}

static void buf_pull(char **pos, void *data, size_t data_len)
{
	memcpy(data, *pos, data_len);
	*pos += data_len;
}

static int lw_ap_send(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	int err;
	char *buf;
	size_t buf_len;
	char *pos;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_bcast;
	struct arphdr ah;

	err = teamd_getsockname_hwaddr(psr_ppriv->sock, &ll_my, 0);
	if (err)
		return err;
	ll_bcast = ll_my;
	memset(ll_bcast.sll_addr, 0xFF, ll_bcast.sll_halen);

	buf_len = sizeof(ah) + ll_my.sll_halen + sizeof(ap_ppriv->src) +
				ll_bcast.sll_halen + sizeof(ap_ppriv->dst);
	buf = malloc(buf_len);
	if (!buf) {
		teamd_log_err("Failed to alloc packet buffer.");
		return -ENOMEM;
	}
	pos = buf;

	memset(&ah, 0, sizeof(ah));
	ah.ar_hrd = htons(ll_my.sll_hatype);
	ah.ar_pro = htons(ETH_P_IP);
	ah.ar_hln = ll_my.sll_halen;
	ah.ar_pln = 4;
	ah.ar_op = htons(ARPOP_REQUEST);

	buf_push(&pos, &ah, sizeof(ah));
	buf_push(&pos, ll_my.sll_addr, ll_my.sll_halen);
	buf_push(&pos, &ap_ppriv->src, sizeof(ap_ppriv->src));
	buf_push(&pos, ll_bcast.sll_addr, ll_bcast.sll_halen);
	buf_push(&pos, &ap_ppriv->dst, sizeof(ap_ppriv->dst));

	err = teamd_sendto(psr_ppriv->sock, buf, buf_len, 0,
			   (struct sockaddr *) &ll_bcast, sizeof(ll_bcast));
	free(buf);
	return err;
}

static int lw_ap_receive(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	int err;
	char buf[256];
	socklen_t addr_len;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_from;
	struct sockaddr_ll ll_msg1;
	struct sockaddr_ll ll_msg2;
	struct arphdr ah;
	struct in_addr src;
	struct in_addr dst;
	char *pos;

	err = teamd_getsockname_hwaddr(psr_ppriv->sock, &ll_my, 0);
	if (err)
		return err;

	err = teamd_recvfrom(psr_ppriv->sock, buf, sizeof(buf), 0,
			     (struct sockaddr *) &ll_from, &addr_len);
	if (err <= 0)
		return err;

	if (ll_from.sll_pkttype != PACKET_HOST)
		return 0;

	pos = buf;
	buf_pull(&pos, &ah, sizeof(ah));
	if (ah.ar_hrd != htons(ll_my.sll_hatype) ||
	    ah.ar_pro != htons(ETH_P_IP) ||
	    ah.ar_hln != ll_my.sll_halen ||
	    ah.ar_pln != 4 ||
	    ah.ar_op != htons(ARPOP_REPLY))
		return 0;

	buf_pull(&pos, ll_msg1.sll_addr, ll_my.sll_halen);
	buf_pull(&pos, &src, sizeof(src));
	buf_pull(&pos, ll_msg2.sll_addr, ll_my.sll_halen);
	buf_pull(&pos, &dst, sizeof(dst));

	if (ap_ppriv->src.s_addr != dst.s_addr ||
	    ap_ppriv->dst.s_addr != src.s_addr ||
	    memcmp(ll_msg2.sll_addr, ll_my.sll_addr, ll_my.sll_halen) != 0)
		return 0;

	psr_ppriv->reply_received = true;
	return 0;
}

const struct lw_psr_ops lw_psr_ops_ap = {
	.sock_open		= lw_ap_sock_open,
	.sock_close		= lw_ap_sock_close,
	.load_options		= lw_ap_load_options,
	.send			= lw_ap_send,
	.receive		= lw_ap_receive,
	.default_init_wait	= { 0, 1 },
};

static int lw_ap_port_added(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv)
{
	struct lw_ap_port_priv *ap_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = &ap_ppriv->start.psr;

	psr_ppriv->ops = &lw_psr_ops_ap;
	return lw_psr_port_added(ctx, tdport, priv, creator_priv);
}

const struct teamd_link_watch teamd_link_watch_arp_ping = {
	.name			= "arp_ping",
	.is_port_up		= lw_psr_is_port_up,
	.port_priv = {
		.init		= lw_ap_port_added,
		.fini		= lw_psr_port_removed,
		.priv_size	= sizeof(struct lw_ap_port_priv),
	},
};


/*
 * IPV6 NS/NA ping link watch
 */

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

struct sock_filter na_flt[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, OFFSET_NEXT_HEADER),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, OFFSET_NA_TYPE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

const struct sock_fprog na_fprog = {
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
				     psr_ppriv->tdport->ifindex,
				     htons(ETH_P_IPV6), &na_fprog);
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
	json_t *link_watch_json = psr_ppriv->common.link_watch_json;
	char *host;
	int err;

	err = json_unpack(link_watch_json, "{s:s}", "target_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_sockaddr_in6(&nsnap_ppriv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("Using target address \"%s\".",
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
	sendto_addr.sin6_scope_id = psr_ppriv->tdport->ifindex;
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
	socklen_t addr_len;
	struct sockaddr_ll ll_from;
	int err;

	err = teamd_recvfrom(psr_ppriv->sock, &nap, sizeof(nap), 0,
			     (struct sockaddr *) &ll_from, &addr_len);
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

const struct lw_psr_ops lw_psr_ops_nsnap = {
	.sock_open		= lw_nsnap_sock_open,
	.sock_close		= lw_nsnap_sock_close,
	.load_options		= lw_nsnap_load_options,
	.send			= lw_nsnap_send,
	.receive		= lw_nsnap_receive,
	.default_init_wait	= { 2, 0 },
};

static int lw_nsnap_port_added(struct teamd_context *ctx,
			       struct teamd_port *tdport,
			       void *priv, void *creator_priv)
{
	struct lw_psr_port_priv *psr_port_priv = priv;

	psr_port_priv->ops = &lw_psr_ops_nsnap;
	return lw_psr_port_added(ctx, tdport, priv, creator_priv);
}

const struct teamd_link_watch teamd_link_watch_nsnap = {
	.name			= "nsna_ping",
	.is_port_up		= lw_psr_is_port_up,
	.port_priv = {
		.init		= lw_nsnap_port_added,
		.fini		= lw_psr_port_removed,
		.priv_size	= sizeof(struct lw_nsnap_port_priv),
	},
};


/*
 * General link watch code
 */
static const struct teamd_link_watch *teamd_link_watch_list[] = {
	&teamd_link_watch_ethtool,
	&teamd_link_watch_arp_ping,
	&teamd_link_watch_nsnap,
};

#define TEAMD_LINK_WATCH_LIST_SIZE ARRAY_SIZE(teamd_link_watch_list)

/*
 * For port priv identification purposes
 */
#define LW_PORT_PRIV_CREATOR_PRIV (&teamd_link_watch_list)

static const struct teamd_link_watch *teamd_find_link_watch(const char *link_watch_name)
{
	int i;

	for (i = 0; i < TEAMD_LINK_WATCH_LIST_SIZE; i++) {
		if (strcmp(teamd_link_watch_list[i]->name, link_watch_name) == 0)
			return teamd_link_watch_list[i];
	}
	return NULL;
}

bool teamd_link_watch_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	struct lw_common_port_priv *common_ppriv;
	const struct teamd_link_watch *link_watch;

	if (!tdport)
		return true;
	teamd_for_each_port_priv_by_creator(common_ppriv, tdport,
					    LW_PORT_PRIV_CREATOR_PRIV) {
		link_watch = common_ppriv->link_watch;
		if (link_watch->is_port_up)
			return link_watch->is_port_up(ctx, tdport,
						      common_ppriv);
	}
	return true;
}

static int link_watch_event_watch_port_added(struct teamd_context *ctx,
					     struct teamd_port *tdport,
					     void *priv)
{
	int err;
	const char *link_watch_name;
	json_t *link_watch_obj;
	const struct teamd_link_watch *link_watch;
	struct lw_common_port_priv *common_ppriv;

	err = json_unpack(ctx->config_json, "{s:{s:{s:o}}}", "ports",
			  tdport->ifname, "link_watch", &link_watch_obj);
	if (err) {
		teamd_log_dbg("%s: Failed to get link watch from port config.",
			      tdport->ifname);
		err = json_unpack(ctx->config_json, "{s:o}", "link_watch",
				  &link_watch_obj);
		if (err) {
			teamd_log_info("%s: Failed to get link watch "
				       "from config.", tdport->ifname);
			goto nowatch;
		}
	}
	err = json_unpack(link_watch_obj, "{s:s}", "name", &link_watch_name);
	if (err) {
		teamd_log_info("%s: Failed to get link watch name.",
			       tdport->ifname);
		goto nowatch;
	}
	link_watch = teamd_find_link_watch(link_watch_name);
	if (!link_watch) {
		teamd_log_info("No link_watch named \"%s\" available.",
			       link_watch_name);
		goto nowatch;
	}
	teamd_log_info("%s: Using link_watch \"%s\".",
		       tdport->ifname, link_watch_name);
	err = teamd_port_priv_create_and_get((void **) &common_ppriv, tdport,
					     &link_watch->port_priv,
					     LW_PORT_PRIV_CREATOR_PRIV);
	if (err)
		return err;
	common_ppriv->link_watch = link_watch;
	common_ppriv->link_watch_json = link_watch_obj;

nowatch:
	teamd_log_info("%s: Using no link watch!", tdport->ifname);
	return 0;
}

static int link_watch_event_watch_port_changed(struct teamd_context *ctx,
					       struct teamd_port *tdport,
					       void *priv)
{
	return teamd_event_port_link_changed(ctx, tdport);
}

static const struct teamd_event_watch_ops link_watch_port_watch_ops = {
	.port_added = link_watch_event_watch_port_added,
	.port_changed = link_watch_event_watch_port_changed,
};

int teamd_link_watch_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &link_watch_port_watch_ops, NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

void teamd_link_watch_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &link_watch_port_watch_ops, NULL);
}
