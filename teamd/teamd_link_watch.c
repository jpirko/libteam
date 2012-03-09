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
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

const struct teamd_link_watch teamd_link_watch_ethtool;
static const struct teamd_link_watch *teamd_link_watch_list[] = {
	&teamd_link_watch_ethtool,
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

bool teamd_link_watch_port_up(struct teamd_context *ctx, uint32_t ifindex)
{
	struct teamd_port *tdport = teamd_get_port(ctx, ifindex);

	if (tdport && tdport->link_watch && tdport->link_watch->is_port_up)
		return tdport->link_watch->is_port_up(ctx, ifindex);
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

static bool lw_ethtool_is_port_up(struct teamd_context *ctx, uint32_t ifindex)
{
	struct team_port *port;

	team_for_each_port(port, ctx->th)
		if (team_get_port_ifindex(port) == ifindex)
			return team_is_port_link_up(port);
	return false;
}

const struct teamd_link_watch teamd_link_watch_ethtool = {
	.name		= "ethtool",
	.is_port_up	= lw_ethtool_is_port_up,
};
