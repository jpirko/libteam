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
#include <team.h>

#include "teamd.h"

static void call_link_watch_handler(struct teamd_context *ctx)
{
	if (ctx->link_watch_handler)
		ctx->link_watch_handler(ctx);
}

static void port_change_handler_func(struct team_handle *th, void *arg,
				     team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);

	call_link_watch_handler(ctx);
}

static struct team_change_handler port_change_handler = {
	.func = port_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE,
};

static bool lw_ethtool_is_port_up(struct teamd_context *ctx, uint32_t ifindex)
{
	struct team_port *port;

	team_for_each_port(port, ctx->th)
		if (team_get_port_ifindex(port) == ifindex)
			return team_is_port_link_up(port);
	return false;
}

static int lw_ethtool_init(struct teamd_context *ctx)
{
	return team_change_handler_register(ctx->th, &port_change_handler);
}

static void lw_ethtool_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &port_change_handler);
}

const struct teamd_link_watch teamd_link_watch_ethtool = {
	.name		= "ethtool",
	.init		= lw_ethtool_init,
	.fini		= lw_ethtool_fini,
	.is_port_up	= lw_ethtool_is_port_up,
};
