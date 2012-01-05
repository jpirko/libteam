/*
 * teamd_runner_activebackup.c - Active-backup runners
 * Copyright (c) 2012 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <team.h>

#include "teamd.h"

struct abl_priv {
	char		old_active_hwaddr[MAX_ADDR_LEN];
	char		tmp_hwaddr[MAX_ADDR_LEN];
};

static struct abl_priv *abl_priv(struct teamd_context *ctx)
{
	return (struct abl_priv *) ctx->runner_priv;
}

static void change_active_port(struct teamd_context *ctx,
			       uint32_t old_active_ifindex,
			       uint32_t new_active_ifindex)
{
	int err;

	if (old_active_ifindex) {
		err = team_hwaddr_set(ctx->th, old_active_ifindex,
				      abl_priv(ctx)->old_active_hwaddr,
				      ctx->hwaddr_len);
		if (err)
			teamd_log_err("Failed to set old active original hardware address: %s",
				      strerror(-err));
	}

	err = team_set_active_port(ctx->th, new_active_ifindex);
	if (err)
		teamd_log_err("Failed to set active port: %s", strerror(-err));

	err = team_hwaddr_get(ctx->th, ctx->ifindex, abl_priv(ctx)->tmp_hwaddr,
			      ctx->hwaddr_len);
	if (err)
		teamd_log_err("Failed to get team device hardware address: %s",
			      strerror(-err));

	err = team_hwaddr_get(ctx->th, new_active_ifindex, abl_priv(ctx)->old_active_hwaddr,
			      ctx->hwaddr_len);
	if (err)
		teamd_log_err("Failed to get new active device hardware address: %s",
			      strerror(-err));

	err = team_hwaddr_set(ctx->th, new_active_ifindex, abl_priv(ctx)->tmp_hwaddr,
			      ctx->hwaddr_len);
	if (err)
		teamd_log_err("Failed to set new active hardware address: %s",
			      strerror(-err));
}

static void port_change_handler_func(struct team_handle *th, void *arg,
				     team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = arg;
	struct team_port *port;
	uint32_t active_ifindex;
	char *active_ifname;
	bool active_down = false;
	uint32_t best_ifindex = 0;
	char *best_ifname;
	uint32_t best_speed;
	uint8_t best_duplex;
	int err;

	err = team_get_active_port(th, &active_ifindex);
	if (err) {
		teamd_log_err("Failed to get active port.");
		return;
	}

	active_ifname = dev_name_dup(ctx, active_ifindex);
	teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\").",
		      active_ifname, active_ifindex);

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		if (team_is_port_link_up(port)) {
			uint32_t speed = team_get_port_speed(port);
			uint8_t duplex = team_get_port_duplex(port);

			if (!best_ifindex ||
			    (speed > best_speed) ||
			    (speed == best_speed && duplex > best_duplex)) {
				best_ifindex = ifindex;
				best_speed = speed;
				best_duplex = duplex;
			}
		} else if (ifindex == active_ifindex) {
			active_down = true;
		}
	}

	best_ifname = dev_name_dup(ctx, best_ifindex);
	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\").",
		      dev_name(ctx, best_ifindex), best_ifindex);
	if ((active_down || !active_ifindex) && best_ifindex) {
		teamd_log_info("Changing active port to from \"%s\" to \"%s\".",
			       active_ifname, best_ifname);
		change_active_port(ctx, active_ifindex, best_ifindex);
	}
}

static struct team_change_handler port_change_handler = {
	.func		= port_change_handler_func,
	.type_mask	= TEAM_PORT_CHANGE,
};

static int abl_init(struct teamd_context *ctx)
{
	port_change_handler.func_priv = ctx;
	return team_change_handler_register(ctx->th, &port_change_handler);
}

static void abl_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &port_change_handler);
}

const struct teamd_runner teamd_runner_activebackup = {
	.name		= "activebackup_linkmon",
	.team_mode_name	= "activebackup",
	.init		= abl_init,
	.fini		= abl_fini,
	.priv_size	= sizeof(struct abl_priv),
};
