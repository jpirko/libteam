/*
 *   teamd_runner_loadbalance.c - Load-balancing runners
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

#include <sys/socket.h>
#include <linux/netdevice.h>
#include <team.h>

#include "teamd.h"

struct lb {
	struct teamd_balancer *tb;
};

static int lb_event_watch_port_added(struct teamd_context *ctx,
				     struct teamd_port *tdport, void *priv)
{
	struct lb *lb = priv;
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set port \"%s\" hardware address. ",
			      tdport->ifname);
		return err;
	}
	return teamd_balancer_port_added(lb->tb, tdport);
}

static void lb_event_watch_port_removed(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	struct lb *lb = priv;

	teamd_balancer_port_removed(lb->tb, tdport);
}

static const struct teamd_event_watch_ops lb_port_watch_ops = {
	.port_added = lb_event_watch_port_added,
	.port_removed = lb_event_watch_port_removed,
};

static int lb_init(struct teamd_context *ctx)
{
	struct lb *lb = ctx->runner_priv;
	int err;

	err = teamd_hash_func_set(ctx);
	if (err)
		return err;
	err = teamd_event_watch_register(ctx, &lb_port_watch_ops, lb);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_balancer_init(ctx, &lb->tb);
	if (err) {
		teamd_log_err("Failed to init balanced.");
		goto event_watch_unregister;
	}
	return 0;
event_watch_unregister:
	teamd_event_watch_unregister(ctx, &lb_port_watch_ops, lb);
	return err;
}

static void lb_fini(struct teamd_context *ctx)
{
	struct lb *lb = ctx->runner_priv;

	teamd_balancer_fini(lb->tb);
	teamd_event_watch_unregister(ctx, &lb_port_watch_ops, lb);
}

const struct teamd_runner teamd_runner_loadbalance = {
	.name		= "loadbalance",
	.team_mode_name	= "loadbalance",
	.init		= lb_init,
	.fini		= lb_fini,
	.priv_size	= sizeof(struct lb),
};
