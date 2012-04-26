/*
 *   teamd_runner_activebackup.c - Active-backup runners
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
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <jansson.h>
#include <limits.h>
#include <team.h>

#include "teamd.h"

struct abl_priv {
	char		old_active_hwaddr[MAX_ADDR_LEN];
};

static struct abl_priv *abl_priv(struct teamd_context *ctx)
{
	return (struct abl_priv *) ctx->runner_priv;
}

static int get_port_prio(struct teamd_context *ctx, const char *port_name)
{
	int prio;
	int err;

	err = json_unpack(ctx->config_json, "{s:{s:{s:i}}}", "ports", port_name,
							     "prio", &prio);
	if (err) {
		teamd_log_dbg("%s: Using default port priority.", port_name);
		return 0; /* return default priority */
	}
	return prio;
}

static bool is_port_sticky(struct teamd_context *ctx, const char *port_name)
{
	int sticky;
	int err;

	err = json_unpack(ctx->config_json, "{s:{s:{s:b}}}", "ports", port_name,
							     "sticky", &sticky);
	if (err) {
		teamd_log_dbg("%s: Using default port stickiness.", port_name);
		return false; /* return default stickiness */
	}
	return sticky;
}

static void change_active_port(struct teamd_context *ctx,
			       struct teamd_port *old_tdport,
			       struct teamd_port *new_tdport)
{
	uint32_t new_active_ifindex = new_tdport->ifindex;
	uint32_t old_active_ifindex = 0;
	int err;

	if (old_tdport) {
		old_active_ifindex = old_tdport->ifindex;
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

	memcpy(abl_priv(ctx)->old_active_hwaddr,
	       team_get_ifinfo_hwaddr(new_tdport->team_ifinfo),
	       ctx->hwaddr_len);

	err = team_hwaddr_set(ctx->th, new_active_ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err)
		teamd_log_err("Failed to set new active hardware address: %s",
			      strerror(-err));
}

static int link_watch_handler(struct teamd_context *ctx)
{
	uint32_t ifindex;
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct teamd_port *best_tdport = NULL;
	uint32_t best_speed = 0;
	uint8_t best_duplex = 0;
	int best_prio = INT_MIN;
	int err;

	err = team_get_active_port(ctx->th, &ifindex);
	if (err) {
		teamd_log_err("Failed to get active port.");
		return err;
	}
	active_tdport = teamd_get_port(ctx, ifindex);
	if (active_tdport)
		teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      get_port_prio(ctx, active_tdport->ifname));

	teamd_for_each_tdport(tdport, ctx) {
		struct team_port *port = tdport->team_port;

		if (teamd_link_watch_port_up(ctx, tdport)) {
			uint32_t speed = team_get_port_speed(port);
			uint8_t duplex = team_get_port_duplex(port);
			int prio = get_port_prio(ctx, tdport->ifname);

			if (!best_tdport ||
			    (prio > best_prio) ||
			    (speed > best_speed) ||
			    (speed == best_speed && duplex > best_duplex)) {
				best_tdport = tdport;
				best_prio = prio;
				best_speed = speed;
				best_duplex = duplex;
			}
		}
	}

	if (!best_tdport || best_tdport == active_tdport)
		return 0;

	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best_tdport->ifname, best_tdport->ifindex, best_prio);
	if (!active_tdport ||
	    !teamd_link_watch_port_up(ctx, active_tdport) ||
	    !is_port_sticky(ctx, active_tdport->ifname)) {
		teamd_log_info("Changing active port to \"%s\".",
			       best_tdport->ifname);
		change_active_port(ctx, active_tdport, best_tdport);
	}
	return 0;
}

static int abl_init(struct teamd_context *ctx)
{
	teamd_link_watch_set_handler(ctx, link_watch_handler);
	return 0;
}

static void abl_fini(struct teamd_context *ctx)
{
	teamd_link_watch_set_handler(ctx, NULL);
}

const struct teamd_runner teamd_runner_activebackup = {
	.name		= "activebackup",
	.team_mode_name	= "activebackup",
	.init		= abl_init,
	.fini		= abl_fini,
	.priv_size	= sizeof(struct abl_priv),
};
