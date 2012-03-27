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

const struct teamd_link_watch teamd_link_watch_ethtool;
const struct teamd_link_watch teamd_link_watch_arp_ping;
const struct teamd_link_watch teamd_link_watch_nsnap;

static const struct teamd_link_watch *teamd_link_watch_list[] = {
	&teamd_link_watch_ethtool,
	&teamd_link_watch_arp_ping,
	&teamd_link_watch_nsnap,
};

#define TEAMD_LINK_WATCH_LIST_SIZE ARRAY_SIZE(teamd_link_watch_list)

static const struct teamd_link_watch *teamd_find_link_watch(const char *link_watch_name)
{
	int i;

	for (i = 0; i < TEAMD_LINK_WATCH_LIST_SIZE; i++) {
		if (strcmp(teamd_link_watch_list[i]->name, link_watch_name) == 0)
			return teamd_link_watch_list[i];
	}
	return NULL;
}

static int call_link_watch_handler(struct teamd_context *ctx)
{
	if (ctx->link_watch_handler)
		return ctx->link_watch_handler(ctx);
	return 0;
}

static int port_change_handler_func(struct team_handle *th, void *arg,
				    team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);

	return call_link_watch_handler(ctx);
}

static struct team_change_handler port_change_handler = {
	.func = port_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE,
};

bool teamd_link_watch_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	if (tdport && tdport->link_watch && tdport->link_watch->is_port_up)
		return tdport->link_watch->is_port_up(ctx, tdport);
	return true;
}

void teamd_link_watch_select(struct teamd_context *ctx,
			     struct teamd_port *tdport)
{
	int err;
	const char *link_watch_name;
	json_t *link_watch_obj;

	err = json_unpack(ctx->config_json, "{s:{s:{s:o}}}", "ports",
			  tdport->ifname, "link_watch", &link_watch_obj);
	if (err) {
		teamd_log_dbg("Failed to get link watch from port config.");
		err = json_unpack(ctx->config_json, "{s:o}", "link_watch",
				  &link_watch_obj);
		if (err) {
			teamd_log_info("Failed to get link watch from config.");
			goto nowatch;
		}
	}
	err = json_unpack(link_watch_obj, "{s:s}", "name", &link_watch_name);
	if (err) {
		teamd_log_info("Failed to get link watch name.");
		goto nowatch;
	}
	teamd_log_dbg("Using link_watch \"%s\" for port \"%s\".",
		      link_watch_name, tdport->ifname);
	tdport->link_watch = teamd_find_link_watch(link_watch_name);
	if (!tdport->link_watch) {
		teamd_log_info("No link_watch named \"%s\" available.",
			       link_watch_name);
		goto nowatch;
	}
	tdport->link_watch_json = link_watch_obj;
	return;
nowatch:
	teamd_log_info("Using no link watch for port \"%s\"!", tdport->ifname);
}

int teamd_link_watch_init(struct teamd_context *ctx)
{
	return team_change_handler_register(ctx->th, &port_change_handler);
}

void teamd_link_watch_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &port_change_handler);
}

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

static int packet_sock_open(int *sock_p, const uint32_t ifindex,
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

static int getsockname_hwaddr(int sock, struct sockaddr_ll *addr,
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
	if (addr->sll_halen != expected_len) {
		teamd_log_err("Unexpected length of hw address.");
		return -ENOTSUP;
	}
	return 0;
}

/*
 * Ethtool link watch
 */

static bool lw_ethtool_is_port_up(struct teamd_context *ctx,
				  struct teamd_port *tdport)
{
	struct team_port *port;

	team_for_each_port(port, ctx->th)
		if (team_get_port_ifindex(port) == tdport->ifindex)
			return team_is_port_link_up(port);
	return false;
}

const struct teamd_link_watch teamd_link_watch_ethtool = {
	.name		= "ethtool",
	.is_port_up	= lw_ethtool_is_port_up,
};


/*
 * Generic periodic send/receive link watch "template"
 */

struct lw_psr_port_priv;

struct lw_psr_ops {
	int (*sock_open)(struct lw_psr_port_priv *port_priv);
	void (*sock_close)(struct lw_psr_port_priv *port_priv);
	int (*load_options)(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    struct lw_psr_port_priv *port_priv);
	int (*send)(struct lw_psr_port_priv *port_priv);
	int (*receive)(struct lw_psr_port_priv *port_priv);
	struct timespec default_init_wait;
};

struct lw_psr_port_priv {
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

static int lw_psr_callback_periodic(struct teamd_context *ctx, int events,
				    void *func_priv)
{
	struct lw_psr_port_priv *port_priv = func_priv;
	bool orig_link_up = port_priv->link_up;
	const char *lw_name = port_priv->tdport->link_watch->name;
	int err;

	if (port_priv->reply_received) {
		port_priv->link_up = true;
		port_priv->missed = 0;
	} else {
		port_priv->missed++;
		if (port_priv->missed > port_priv->missed_max) {
			teamd_log_dbg("Missed %u replies (max %u).",
				       port_priv->missed,
				       port_priv->missed_max);
			port_priv->link_up = false;
		}
	}
	if (port_priv->link_up != orig_link_up) {
		teamd_log_info("Port \"%s\" %s-link went %s.",
				port_priv->tdport->ifname,
				lw_name, port_priv->link_up ? "up" : "down");
		err = call_link_watch_handler(ctx);
		if (err)
			return err;
	}
	port_priv->reply_received = false;
	return port_priv->ops->send(port_priv);
}

static int lw_psr_callback_socket(struct teamd_context *ctx, int events,
				  void *func_priv)
{
	struct lw_psr_port_priv *port_priv = func_priv;

	return port_priv->ops->receive(port_priv);
}

static int lw_psr_load_options(struct teamd_context *ctx,
			       struct teamd_port *tdport,
			       struct lw_psr_port_priv *port_priv)
{
	int err;
	int tmp;

	err = json_unpack(tdport->link_watch_json, "{s:i}",
			  "interval", &tmp);
	if (err) {
		teamd_log_err("Failed to get \"interval\" link-watch option.");
		return -ENOENT;
	}
	teamd_log_dbg("Using interval \"%d\".", tmp);
	convert_ms(&port_priv->interval.tv_sec,
		   &port_priv->interval.tv_nsec, tmp);

	err = json_unpack(tdport->link_watch_json, "{s:i}",
			  "init_wait", &tmp);
	if (!err) {
		teamd_log_dbg("Using init_wait \"%d\".", tmp);
		convert_ms(&port_priv->init_wait.tv_sec,
			   &port_priv->init_wait.tv_nsec, tmp);
	} else {
		port_priv->init_wait = port_priv->ops->default_init_wait;
	}

	err = json_unpack(tdport->link_watch_json, "{s:i}",
			  "missed_max", &tmp);
	if (err) {
		teamd_log_err("Failed to get \"missed_max\" link-watch option.");
		return -ENOENT;
	}
	if (tmp < 0) {
		teamd_log_err("\"missed_max\" must not be negative number.");
		return -EINVAL;
	}
	teamd_log_dbg("Using missed_max \"%d\".", tmp);
	port_priv->missed_max = tmp;
	return 0;
}

static int lw_psr_port_added(struct teamd_context *ctx,
			     struct teamd_port *tdport)
{
	struct lw_psr_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);
	const char *lw_name = tdport->link_watch->name;
	int err;

	port_priv->tdport = tdport;
	err = port_priv->ops->sock_open(port_priv);
	if (err) {
		teamd_log_err("Failed to create socket.");
		return err;
	}

	err = lw_psr_load_options(ctx, tdport, port_priv);
	if (err) {
		teamd_log_err("Failed to load options.");
		goto close_sock;
	}

	err = port_priv->ops->load_options(ctx, tdport, port_priv);
	if (err) {
		teamd_log_err("Failed to load options.");
		goto close_sock;
	}

	err = asprintf(&port_priv->cb_name_socket, "%s_socket_if%d", lw_name,
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto close_sock;
	}

	err = teamd_loop_callback_fd_add(ctx, port_priv->cb_name_socket,
					 port_priv->sock,
					 TEAMD_LOOP_FD_EVENT_READ,
					 lw_psr_callback_socket, port_priv);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto free_cb_name_socket;
	}

	err = asprintf(&port_priv->cb_name_periodic, "%s_periodic_if%d", lw_name,
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto socket_callback_del;
	}

	err = teamd_loop_callback_timer_add(ctx, port_priv->cb_name_periodic,
					    port_priv->interval.tv_sec,
					    port_priv->interval.tv_nsec,
					    port_priv->init_wait.tv_sec,
					    port_priv->init_wait.tv_nsec,
					    lw_psr_callback_periodic,
					    port_priv);
	if (err) {
		teamd_log_err("Failed add callback timer");
		goto free_periodic_cb_name;
	}
	teamd_loop_callback_enable(ctx, port_priv->cb_name_socket);
	teamd_loop_callback_enable(ctx, port_priv->cb_name_periodic);
	return 0;

free_periodic_cb_name:
	free(port_priv->cb_name_periodic);
socket_callback_del:
	teamd_loop_callback_del(ctx, port_priv->cb_name_socket);
free_cb_name_socket:
	free(port_priv->cb_name_socket);
close_sock:
	port_priv->ops->sock_close(port_priv);
	return err;
}

static void lw_psr_port_removed(struct teamd_context *ctx,
				struct teamd_port *tdport)
{
	struct lw_psr_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	teamd_loop_callback_del(ctx, port_priv->cb_name_periodic);
	free(port_priv->cb_name_periodic);
	teamd_loop_callback_del(ctx, port_priv->cb_name_socket);
	free(port_priv->cb_name_socket);
	port_priv->ops->sock_close(port_priv);
}

static bool lw_psr_is_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	struct lw_psr_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	return port_priv->link_up;
}


/*
 * ARP ping link watch
 */

struct lw_ap_port_priv {
	struct lw_psr_port_priv psr; /* must be first */
	struct in_addr src;
	struct in_addr dst;
};

static int lw_ap_sock_open(struct lw_psr_port_priv *port_priv)
{
	return packet_sock_open(&port_priv->sock, port_priv->tdport->ifindex,
				htons(ETH_P_ARP), NULL);
}

static void lw_ap_sock_close(struct lw_psr_port_priv *port_priv)
{
	close(port_priv->sock);
}

static int lw_ap_load_options(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      struct lw_psr_port_priv *port_priv)
{
	struct lw_ap_port_priv *ap_port_priv = (struct lw_ap_port_priv *) port_priv;
	char *host;
	int err;

	err = json_unpack(tdport->link_watch_json, "{s:s}", "source_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"source_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&ap_port_priv->src, host);
	if (err)
		return err;
	teamd_log_dbg("Using source address \"%s\".",
		      str_in_addr(&ap_port_priv->src));

	err = json_unpack(tdport->link_watch_json, "{s:s}", "target_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&ap_port_priv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("Using target address \"%s\".", str_in_addr(&ap_port_priv->dst));

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

static int lw_ap_send(struct lw_psr_port_priv *port_priv)
{
	struct lw_ap_port_priv *ap_port_priv = (struct lw_ap_port_priv *) port_priv;
	int err;
	char *buf;
	size_t buf_len;
	char *pos;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_bcast;
	struct arphdr ah;
	int ret;

	err = getsockname_hwaddr(port_priv->sock, &ll_my, 0);
	if (err)
		return err;
	ll_bcast = ll_my;
	memset(ll_bcast.sll_addr, 0xFF, ll_bcast.sll_halen);

	buf_len = sizeof(ah) + ll_my.sll_halen + sizeof(ap_port_priv->src) +
				ll_bcast.sll_halen + sizeof(ap_port_priv->dst);
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
	buf_push(&pos, &ap_port_priv->src, sizeof(ap_port_priv->src));
	buf_push(&pos, ll_bcast.sll_addr, ll_bcast.sll_halen);
	buf_push(&pos, &ap_port_priv->dst, sizeof(ap_port_priv->dst));

	ret = sendto(port_priv->sock, buf, buf_len, 0,
		     (struct sockaddr *) &ll_bcast, sizeof(ll_bcast));
	free(buf);
	if (ret == -1) {
		teamd_log_err("sendto failed.");
		return -errno;
	}
	return 0;
}

static int lw_ap_receive(struct lw_psr_port_priv *port_priv)
{
	struct lw_ap_port_priv *ap_port_priv = (struct lw_ap_port_priv *) port_priv;
	int err;
	char buf[256];
	int ret;
	socklen_t addr_len;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_from;
	struct sockaddr_ll ll_msg1;
	struct sockaddr_ll ll_msg2;
	struct arphdr ah;
	struct in_addr src;
	struct in_addr dst;
	char *pos;

	err = getsockname_hwaddr(port_priv->sock, &ll_my, 0);
	if (err)
		return err;

	ret = recvfrom(port_priv->sock, buf, sizeof(buf), 0,
		       (struct sockaddr *) &ll_from, &addr_len);
	if (ret == -1) {
		teamd_log_err("recvfrom failed.");
		return -errno;
	}

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

	if (ap_port_priv->src.s_addr != dst.s_addr ||
	    ap_port_priv->dst.s_addr != src.s_addr ||
	    memcmp(ll_msg2.sll_addr, ll_my.sll_addr, ll_my.sll_halen) != 0)
		return 0;

	port_priv->reply_received = true;
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
			    struct teamd_port *tdport)
{
	struct lw_psr_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	port_priv->ops = &lw_psr_ops_ap;
	return lw_psr_port_added(ctx, tdport);
}

const struct teamd_link_watch teamd_link_watch_arp_ping = {
	.name		= "arp_ping",
	.port_added	= lw_ap_port_added,
	.port_removed	= lw_psr_port_removed,
	.is_port_up	= lw_psr_is_port_up,
	.port_priv_size	= sizeof(struct lw_ap_port_priv),
};


/*
 * IPV6 NS/NA ping link watch
 */

struct lw_nsnap_port_priv {
	struct lw_psr_port_priv psr; /* must be first */
	int tx_sock;
	struct sockaddr_in6 dst;
};

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
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, OFFSET_NEXT_HEADER),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_ICMPV6, 0, 3),
	BPF_STMT(BPF_LD+BPF_B+BPF_ABS, OFFSET_NA_TYPE),
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ND_NEIGHBOR_ADVERT, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int)-1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

const struct sock_fprog na_fprog = {
	.len = ARRAY_SIZE(na_flt),
	.filter = na_flt,
};

static int lw_nsnap_sock_open(struct lw_psr_port_priv *port_priv)
{
	struct lw_nsnap_port_priv *nsnap_port_priv = (struct lw_nsnap_port_priv *) port_priv;
	int err;

	/*
	 * We use two sockets here. NS packets are send through ICMP6 socket.
	 * With this socket, unfortunately, kernel does not provide a way to
	 * deliver incoming ICMP6 packet on inactive ports into userspace.
	 * So we use packet socket to get these packets.
	 */
	err = packet_sock_open(&port_priv->sock, port_priv->tdport->ifindex,
			       htons(ETH_P_IPV6), &na_fprog);
	if (err)
		return err;
	err = icmp6_sock_open(&nsnap_port_priv->tx_sock);
	if (err)
		goto close_packet_sock;
	return 0;
close_packet_sock:
	close(port_priv->sock);
	return err;
}

static void lw_nsnap_sock_close(struct lw_psr_port_priv *port_priv)
{
	struct lw_nsnap_port_priv *nsnap_port_priv = (struct lw_nsnap_port_priv *) port_priv;

	close(nsnap_port_priv->tx_sock);
	close(port_priv->sock);
}

static int lw_nsnap_load_options(struct teamd_context *ctx,
				 struct teamd_port *tdport,
				 struct lw_psr_port_priv *port_priv)
{
	struct lw_nsnap_port_priv *nsnap_port_priv = (struct lw_nsnap_port_priv *) port_priv;
	char *host;
	int err;

	err = json_unpack(tdport->link_watch_json, "{s:s}", "target_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_sockaddr_in6(&nsnap_port_priv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("Using target address \"%s\".",
		      str_sockaddr_in6(&nsnap_port_priv->dst));

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

static int lw_nsnap_send(struct lw_psr_port_priv *port_priv)
{
	struct lw_nsnap_port_priv *nsnap_port_priv = (struct lw_nsnap_port_priv *) port_priv;
	int err;
	struct sockaddr_ll ll_my;
	struct sockaddr_in6 sendto_addr;
	struct ns_packet nsp;
	int ret;

	err = getsockname_hwaddr(port_priv->sock, &ll_my, sizeof(nsp.hwaddr));
	if (err)
		return err;

	memset(&nsp, 0, sizeof(nsp));

	/* setup ICMP6 header */
	nsp.nsh.nd_ns_type = ND_NEIGHBOR_SOLICIT;
	nsp.nsh.nd_ns_cksum = 0; /* kernel computes this */
	nsp.nsh.nd_ns_target = nsnap_port_priv->dst.sin6_addr;
	nsp.opt.nd_opt_type = ND_OPT_SOURCE_LINKADDR;
	nsp.opt.nd_opt_len = 1; /* 8 bytes */
	memcpy(nsp.hwaddr, ll_my.sll_addr, sizeof(nsp.hwaddr));

	sendto_addr = nsnap_port_priv->dst;
	compute_multi_in6_addr(&sendto_addr.sin6_addr);
	sendto_addr.sin6_scope_id = port_priv->tdport->ifindex;
	ret = sendto(nsnap_port_priv->tx_sock, &nsp, sizeof(nsp), 0,
		     (struct sockaddr *) &sendto_addr, sizeof(sendto_addr));
	if (ret == -1) {
		teamd_log_err("sendto failed.");
		return -errno;
	}

	return 0;
}

struct na_packet {
	struct ip6_hdr			ip6h;
	struct nd_neighbor_advert	nah;
	struct nd_opt_hdr		opt;
	unsigned char			hwaddr[ETH_ALEN];
};

static int lw_nsnap_receive(struct lw_psr_port_priv *port_priv)
{
	struct lw_nsnap_port_priv *nsnap_port_priv = (struct lw_nsnap_port_priv *) port_priv;
	struct na_packet nap;
	socklen_t addr_len;
	struct sockaddr_ll ll_from;
	int ret;

	ret = recvfrom(port_priv->sock, &nap, sizeof(nap), 0,
		       (struct sockaddr *) &ll_from, &addr_len);
	if (ret == -1) {
		teamd_log_err("recvfrom failed.");
		return -errno;
	}

	if (ll_from.sll_ifindex != port_priv->tdport->ifindex)
		return 0;

	/* check IPV6 header */
	if (nap.ip6h.ip6_vfc != 0x60 /* IPV6 */ ||
	    nap.ip6h.ip6_plen != htons(sizeof(nap) - sizeof(nap.ip6h)) ||
	    nap.ip6h.ip6_nxt != IPPROTO_ICMPV6 ||
	    nap.ip6h.ip6_hlim != 255 /* Do not route */ ||
	    memcmp(&nap.ip6h.ip6_src, &nsnap_port_priv->dst.sin6_addr,
		   sizeof(struct in6_addr)))
		return 0;

	/* check ICMP6 header */
	if (nap.nah.nd_na_type != ND_NEIGHBOR_ADVERT ||
	    nap.opt.nd_opt_type != ND_OPT_TARGET_LINKADDR ||
	    nap.opt.nd_opt_len != 1 /* 8 bytes */)
		return 0;

	port_priv->reply_received = true;
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
			       struct teamd_port *tdport)
{
	struct lw_psr_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	port_priv->ops = &lw_psr_ops_nsnap;
	return lw_psr_port_added(ctx, tdport);
}

const struct teamd_link_watch teamd_link_watch_nsnap = {
	.name		= "nsna_ping",
	.port_added	= lw_nsnap_port_added,
	.port_removed	= lw_psr_port_removed,
	.is_port_up	= lw_psr_is_port_up,
	.port_priv_size	= sizeof(struct lw_nsnap_port_priv),
};
