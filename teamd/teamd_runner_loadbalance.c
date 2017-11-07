/*
 *   teamd_runner_loadbalance.c - Load-balancing runners
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

	if (!team_is_port_link_up(tdport->team_port)) {
		err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
		if (err) {
			teamd_log_err("%s: Failed to disable port.",
				      tdport->ifname);
			return TEAMD_ENOENT(err) ? 0 : err;
		}
	}
	return teamd_balancer_port_added(lb->tb, tdport);
}

static void lb_event_watch_port_removed(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	struct lb *lb = priv;

	teamd_balancer_port_removed(lb->tb, tdport);
}

static int lb_event_watch_port_link_changed(struct teamd_context *ctx,
					    struct teamd_port *tdport,
					    void *priv)
{
	bool port_up = teamd_link_watch_port_up(ctx, tdport);

	return teamd_port_check_enable(ctx, tdport, port_up, !port_up);
}

static int lb_event_watch_hwaddr_changed(struct teamd_context *ctx, void *priv)
{
	struct teamd_port *tdport;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
				      ctx->hwaddr_len);
		if (err) {
			teamd_log_err("%s: Failed to set port hardware address.",
				      tdport->ifname);
			return err;
		}
	}

	return 0;
}

static int lb_event_watch_port_hwaddr_changed(struct teamd_context *ctx,
					      struct teamd_port *tdport,
					      void *priv)
{
	int err;

	if (!teamd_port_present(ctx, tdport))
		return 0;

	if (!memcmp(team_get_ifinfo_hwaddr(tdport->team_ifinfo),
		    ctx->hwaddr, ctx->hwaddr_len))
		return 0;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err)
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);

	return err;
}

static const struct teamd_event_watch_ops lb_port_watch_ops = {
	.hwaddr_changed = lb_event_watch_hwaddr_changed,
	.port_hwaddr_changed = lb_event_watch_port_hwaddr_changed,
	.port_added = lb_event_watch_port_added,
	.port_removed = lb_event_watch_port_removed,
	.port_link_changed = lb_event_watch_port_link_changed,
};

static int lb_init(struct teamd_context *ctx, void *priv)
{
	struct lb *lb = priv;
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

static void lb_fini(struct teamd_context *ctx, void *priv)
{
	struct lb *lb = priv;

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
