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
#include <net/if_arp.h>
#include <netdb.h>
#include <time.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

const struct teamd_link_watch teamd_link_watch_ethtool;
const struct teamd_link_watch teamd_link_watch_arp_ping;
static const struct teamd_link_watch *teamd_link_watch_list[] = {
	&teamd_link_watch_ethtool,
	&teamd_link_watch_arp_ping,
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
 * ARP ping link watch
 */

struct lw_ap_port_priv {
	struct in_addr src;
	struct in_addr dst;
	struct timespec interval;
	unsigned int missed_max;

	struct teamd_port *tdport;
	int sock;
	char *cb_name_periodic;
	char *cb_name_socket;
	unsigned int missed;
	bool arp_reply_received;
	bool link_up;
};

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

static int send_arp(struct lw_ap_port_priv *port_priv)
{
	int err;
	char *buf;
	size_t buf_len;
	char *pos;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_bcast;
	socklen_t addr_len;
	struct arphdr ah;
	int ret;

	addr_len = sizeof(ll_my);
	err = getsockname(port_priv->sock, (struct sockaddr *) &ll_my, &addr_len);
	if (err == -1) {
		teamd_log_err("Failed to getsockname.");
		return -errno;
	}
	ll_bcast = ll_my;
	memset(ll_bcast.sll_addr, 0xFF, ll_bcast.sll_halen);

	buf_len = sizeof(ah) + ll_my.sll_halen + sizeof(port_priv->src) +
				ll_bcast.sll_halen + sizeof(port_priv->dst);
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
	buf_push(&pos, &port_priv->src, sizeof(port_priv->src));
	buf_push(&pos, ll_bcast.sll_addr, ll_bcast.sll_halen);
	buf_push(&pos, &port_priv->dst, sizeof(port_priv->dst));

	ret = sendto(port_priv->sock, buf, buf_len, 0,
		     (struct sockaddr *) &ll_bcast, sizeof(ll_bcast));
	free(buf);
	if (ret == -1) {
		teamd_log_err("sendto failed.");
		return -errno;
	}
	return 0;
}

static int receive_arp(struct lw_ap_port_priv *port_priv)
{
	int err;
	char buf[256];
	int ret;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_from;
	struct sockaddr_ll ll_msg1;
	struct sockaddr_ll ll_msg2;
	socklen_t addr_len;
	struct arphdr ah;
	struct in_addr src;
	struct in_addr dst;
	char *pos;

	addr_len = sizeof(ll_my);
	err = getsockname(port_priv->sock, (struct sockaddr *) &ll_my, &addr_len);
	if (err == -1) {
		teamd_log_err("Failed to getsockname.");
		return -errno;
	}
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

	if (port_priv->src.s_addr != dst.s_addr ||
	    port_priv->dst.s_addr != src.s_addr ||
	    memcmp(ll_msg2.sll_addr, ll_my.sll_addr, ll_my.sll_halen) != 0)
		return 0;

	port_priv->arp_reply_received = true;
	return 0;
}

static int callback_periodic(struct teamd_context *ctx, int events,
			     void *func_priv)
{
	struct lw_ap_port_priv *port_priv = func_priv;
	bool orig_link_up = port_priv->link_up;
	int err;

	if (port_priv->arp_reply_received) {
		port_priv->link_up = true;
		port_priv->missed = 0;
	} else {
		port_priv->missed++;
		if (port_priv->missed > port_priv->missed_max)
			port_priv->link_up = false;
	}
	if (port_priv->link_up != orig_link_up) {
		teamd_log_info("Port \"%s\" arp-link went %s.",
				port_priv->tdport->ifname,
				port_priv->link_up ? "up" : "down");
		err = call_link_watch_handler(ctx);
		if (err)
			return err;
	}
	port_priv->arp_reply_received = false;
	return send_arp(port_priv);
}

static int callback_socket(struct teamd_context *ctx, int events,
			   void *func_priv)
{
	struct lw_ap_port_priv *port_priv = func_priv;

	return receive_arp(port_priv);
}

static int set_in_addr(struct in_addr *addr, const char *hostname)
{
	if (inet_aton(hostname, addr) != 1) {
		struct hostent *ent;

		ent = gethostbyname2(hostname, AF_INET);
		if (!ent) {
			teamd_log_err("Failed get address for host \"%s\".",
				      hostname);
			return -ENOENT;
		}
		memcpy(addr, ent->h_addr, sizeof(*addr));
	}
	return 0;
}

static int load_options(struct teamd_context *ctx, struct teamd_port *tdport,
			struct lw_ap_port_priv *port_priv)
{
	char *host;
	int err;
	int tmp;

	err = json_unpack(tdport->link_watch_json, "{s:s}", "source_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"source_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&port_priv->src, host);
	if (err)
		return err;
	teamd_log_dbg("Using source address \"%s\".", inet_ntoa(port_priv->src));

	err = json_unpack(tdport->link_watch_json, "{s:s}", "target_host", &host);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -ENOENT;
	}
	err = set_in_addr(&port_priv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("Using target address \"%s\".", inet_ntoa(port_priv->dst));

	err = json_unpack(tdport->link_watch_json, "{s:i}",
			  "interval", &tmp);
	if (err) {
		teamd_log_err("Failed to get \"interval\" link-watch option.");
		return -ENOENT;
	}
	teamd_log_dbg("Using interval \"%d\".", tmp);
	convert_ms(&port_priv->interval.tv_sec, &port_priv->interval.tv_nsec,
		   tmp);

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

static int lw_ap_port_added(struct teamd_context *ctx,
			    struct teamd_port *tdport)
{
	struct lw_ap_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);
	struct sockaddr_ll ll_my;
	int err;

	port_priv->tdport = tdport;
	port_priv->sock =  socket(PF_PACKET, SOCK_DGRAM, 0);
	if (port_priv->sock == -1) {
		teamd_log_err("Failed to create socket.");
		return -errno;
	}
	memset(&ll_my, 0, sizeof(ll_my));
	ll_my.sll_family = AF_PACKET;
	ll_my.sll_ifindex = tdport->ifindex;
	ll_my.sll_protocol = htons(ETH_P_ARP);
	err = bind(port_priv->sock, (struct sockaddr *) &ll_my, sizeof(ll_my));
	if (err == -1) {
		teamd_log_err("Failed to bind socket.");
		err = -errno;
		goto close_sock;
	}

	err = load_options(ctx, tdport, port_priv);
	if (err)
		goto close_sock;

	err = asprintf(&port_priv->cb_name_socket, "arp_ping_socket_if%d",
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto close_sock;
	}

	err = teamd_loop_callback_fd_add(ctx, port_priv->cb_name_socket,
					 port_priv->sock,
					 TEAMD_LOOP_FD_EVENT_READ,
					 callback_socket, port_priv);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto free_cb_name_socket;
	}

	err = asprintf(&port_priv->cb_name_periodic, "arp_ping_periodic_if%d",
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate callback name.");
		err = -ENOMEM;
		goto socket_callback_del;
	}

	err = teamd_loop_callback_timer_add(ctx, port_priv->cb_name_periodic,
					    port_priv->interval.tv_sec,
					    port_priv->interval.tv_nsec, 0, 1,
					    callback_periodic, port_priv);
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
	close(port_priv->sock);
	return err;
}

static void lw_ap_port_removed(struct teamd_context *ctx,
			       struct teamd_port *tdport)
{
	struct lw_ap_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	teamd_loop_callback_del(ctx, port_priv->cb_name_periodic);
	free(port_priv->cb_name_periodic);
	teamd_loop_callback_del(ctx, port_priv->cb_name_socket);
	free(port_priv->cb_name_socket);
	close(port_priv->sock);
}

static bool lw_ap_is_port_up(struct teamd_context *ctx,
			     struct teamd_port *tdport)
{
	struct lw_ap_port_priv *port_priv = teamd_get_link_watch_port_priv(tdport);

	return port_priv->link_up;
}

const struct teamd_link_watch teamd_link_watch_arp_ping = {
	.name		= "arp_ping",
	.port_added	= lw_ap_port_added,
	.port_removed	= lw_ap_port_removed,
	.is_port_up	= lw_ap_is_port_up,
	.port_priv_size	= sizeof(struct lw_ap_port_priv),
};
