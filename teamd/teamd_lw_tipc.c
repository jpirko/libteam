/*
 *   teamd_lw_tipc.c - Team port TIPC link watcher
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

#include <sys/queue.h>
#include <sys/poll.h>
#include <linux/tipc.h>
#include <netinet/in.h>
#include <private/misc.h>
#include "teamd.h"
#include "teamd_link_watch.h"
#include "teamd_config.h"

/*
 * TIPC monitoring
 */

#define LW_TIPC_TOPSRV_SOCKET "lw_tipc"

struct tipc_link {
	LIST_ENTRY(tipc_link) next;
	char name[TIPC_MAX_LINK_NAME];
	unsigned int peer;
	bool up;
};

struct lw_tipc_port_priv {
	struct lw_common_port_priv common;
	int topsrv_sock;
	char bearer[TIPC_MAX_BEARER_NAME];
	LIST_HEAD(links, tipc_link) links;
	int active_links;
};

static int lw_tipc_load_options(struct teamd_context *ctx,
				struct teamd_port *tdport,
				struct lw_tipc_port_priv *tipc_ppriv)
{
	int err;
	const char *tipc_bearer;
	struct teamd_config_path_cookie *cpcookie = tipc_ppriv->common.cpcookie;
	err = teamd_config_string_get(ctx, &tipc_bearer, "@.tipc_bearer", cpcookie);
	if (err)
		return -EINVAL;
	if (strlen(tipc_bearer) >= TIPC_MAX_BEARER_NAME)
		return -EINVAL;
	strcpy(tipc_ppriv->bearer, tipc_bearer);
	return 0;
}

static bool lw_tipc_topology_check(struct lw_tipc_port_priv *priv,
				   unsigned int addr)
{
	struct tipc_link *l;

	LIST_FOREACH(l, &priv->links, next) {
		if ((tipc_cluster(l->peer) == tipc_cluster(addr)) && l->up)
			return true;
	}
	return false;
}

static int lw_tipc_link_state_change(struct teamd_context *ctx,
				     struct tipc_sioc_ln_req *lnr,
				     struct lw_tipc_port_priv *priv,
				     bool link_up)
{
	bool path_ok;
	struct tipc_link *link;
	struct lw_common_port_priv *ppriv = (struct lw_common_port_priv *)priv;

	LIST_FOREACH(link, &priv->links, next) {
		if (strcmp(link->name, lnr->linkname))
			continue;
		link->up = link_up;
		teamd_log_dbg("tipc: link <%s> went %s.",
			       lnr->linkname, link_up ? "up" : "down");
check:
		path_ok = lw_tipc_topology_check(priv, link->peer);
		return teamd_link_watch_check_link_up(ctx, ppriv->tdport, ppriv,
						      path_ok);
	}
	if (!link_up) {
		teamd_log_err("tipc: received spurious down event for link <%s>",
			      lnr->linkname);
		return -EINVAL;
	}
	teamd_log_dbg("tipc: established new link <%s>", lnr->linkname);
	link = malloc(sizeof(struct tipc_link));
	if (!link)
		return -ENOMEM;
	strcpy(link->name, lnr->linkname);
	link->up = link_up;
	link->peer = lnr->peer;
	LIST_INSERT_HEAD(&priv->links, link, next);
	goto check;
}

static int lw_tipc_filter_events(struct lw_tipc_port_priv *tipc_ppriv,
				 struct tipc_sioc_ln_req *lnr)
{
	char name[TIPC_MAX_LINK_NAME];
	char needle[24];
	char *remote, *bearer;

	strcpy(name, lnr->linkname);
	sprintf(needle, "-%u.%u.%u:", tipc_zone(lnr->peer),
		tipc_cluster(lnr->peer), tipc_node(lnr->peer));
	remote = strstr(name, needle);
	*(remote++) = '\0';
	bearer = strchr(name, ':') + 1;
	return strcmp(bearer, tipc_ppriv->bearer);
}

static int lw_tipc_callback_socket(struct teamd_context *ctx, int events, void *priv)
{
	int err;
	struct lw_tipc_port_priv *tipc_ppriv = priv;
	struct tipc_event event;
	struct sockaddr_tipc sa;
	struct tipc_sioc_ln_req lnr = {0};

	err = teamd_recvfrom(tipc_ppriv->topsrv_sock, &event, sizeof(event), 0,
			     (struct sockaddr *)&sa, sizeof(sa));
	if ((err != sizeof(event)) ||
	    (event.s.seq.type != htonl(TIPC_LINK_STATE)))
		goto tipc_cb_err;

	lnr.peer = ntohl(event.found_lower);
	lnr.bearer_id = ntohl(event.port.ref);
	if (ioctl(tipc_ppriv->topsrv_sock, SIOCGETLINKNAME, &lnr) < 0)
		goto tipc_cb_err;

	if (lw_tipc_filter_events(tipc_ppriv, &lnr))
		return 0;
	if (event.event == htonl(TIPC_PUBLISHED))
		return lw_tipc_link_state_change(ctx, &lnr, tipc_ppriv, true);
	else if (event.event == htonl(TIPC_WITHDRAWN))
		return lw_tipc_link_state_change(ctx, &lnr, tipc_ppriv, false);
tipc_cb_err:
	teamd_log_dbg("tipc: link state event error");
	return -EINVAL;
}

static int lw_tipc_topsrv_subscribe(struct teamd_context *ctx, struct lw_tipc_port_priv *priv)
{
	int err;
	struct sockaddr_tipc sa_topsrv = {
		.family = AF_TIPC,
		.addrtype = TIPC_ADDR_NAME,
		.addr.name.name.type = TIPC_TOP_SRV,
		.addr.name.name.instance = TIPC_TOP_SRV,
	};
	struct tipc_subscr sub = {
		.seq.type = htonl(TIPC_LINK_STATE),
		.seq.lower = htonl(0),
		.seq.upper = htonl(~0),
		.timeout = htonl(TIPC_WAIT_FOREVER),
		.filter = htonl(TIPC_SUB_PORTS),
	};

	priv->topsrv_sock = socket(AF_TIPC, SOCK_SEQPACKET, 0);
	if (priv->topsrv_sock == -1) {
		teamd_log_err("Failed to create TIPC socket");
		return -errno;
	}

	err = teamd_loop_callback_fd_add(ctx, LW_TIPC_TOPSRV_SOCKET, priv,
				 lw_tipc_callback_socket,
				 priv->topsrv_sock,
				 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed to add socket callback");
		err = -errno;
		goto close_sock;
	}
	teamd_loop_callback_enable(ctx, LW_TIPC_TOPSRV_SOCKET, priv);
	err = connect(priv->topsrv_sock, (struct sockaddr *) &sa_topsrv, sizeof(sa_topsrv));
	if (err < 0) {
		teamd_log_err("Failed to connect to TIPC topology server");
		err = -errno;
		goto close_sock;
	}
	err = send(priv->topsrv_sock, &sub, sizeof(sub), 0);
	if (err != sizeof(sub)) {
		teamd_log_err("Failed to subscribe for TIPC link status");
		goto close_sock;
	}

	return 0;
close_sock:
	close(priv->topsrv_sock);
	return err;
}

static int lw_tipc_port_added(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      void *priv, void *creator_priv)
{
	struct lw_tipc_port_priv *tipc_ppriv = priv;
	int err;

	err = lw_tipc_load_options(ctx, tdport, priv);
	if (err) {
		teamd_log_err("tipc: Failed to load options");
		return err;
	}
	LIST_INIT(&tipc_ppriv->links);
	err = lw_tipc_topsrv_subscribe(ctx, tipc_ppriv);
	if (err)
		return err;
	return 0;
}

static void lw_tipc_port_removed(struct teamd_context *ctx,
				 struct teamd_port *tdport,
				 void *priv, void *creator_priv)
{
	struct lw_tipc_port_priv *tipc_ppriv = priv;
	struct tipc_link *link;

	teamd_log_dbg("tipc port removed\n");
	teamd_loop_callback_del(ctx, LW_TIPC_TOPSRV_SOCKET, priv);
	close(tipc_ppriv->topsrv_sock);
	while (!LIST_EMPTY(&tipc_ppriv->links)) {
		link = LIST_FIRST(&tipc_ppriv->links);
		LIST_REMOVE(link, next);
		free(link);
	}
}

int lw_tipc_state_bearer_get(struct teamd_context *ctx,
			   struct team_state_gsc *gsc,
			   void *priv)
{
	struct lw_tipc_port_priv *tipc_ppriv = priv;
	gsc->data.str_val.ptr = tipc_ppriv->bearer;
	return 0;
}

static const struct teamd_state_val lw_tipc_state_vals[] = {
	{
		.subpath = "tipc_bearer",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_tipc_state_bearer_get,
	},
};


const struct teamd_link_watch teamd_link_watch_tipc = {
	.name			= "tipc",
	.state_vg		= {
		.vals		= lw_tipc_state_vals,
		.vals_count	= ARRAY_SIZE(lw_tipc_state_vals),
	},
	.port_priv = {
		.init		= lw_tipc_port_added,
		.fini		= lw_tipc_port_removed,
		.priv_size	= sizeof(struct lw_tipc_port_priv),
	},
};
