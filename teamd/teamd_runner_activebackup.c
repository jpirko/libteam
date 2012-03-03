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
	char		tmp_hwaddr[MAX_ADDR_LEN];
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
		teamd_log_dbg("Using default priority for \"%s\".", port_name);
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
		teamd_log_dbg("Using default stickiness for \"%s\".", port_name);
		return false; /* return default stickiness */
	}
	return sticky;
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

static void link_watch_handler(struct teamd_context *ctx)
{
	struct team_port *port;
	uint32_t active_ifindex;
	char *active_ifname;
	bool active_down = false;
	uint32_t best_ifindex = 0;
	char *best_ifname;
	uint32_t best_speed = 0;
	uint8_t best_duplex = 0;
	int best_prio = INT_MIN;
	int err;

	err = team_get_active_port(ctx->th, &active_ifindex);
	if (err) {
		teamd_log_err("Failed to get active port.");
		return;
	}

	active_ifname = dev_name_dup(ctx, active_ifindex);
	teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      active_ifname, active_ifindex,
		      get_port_prio(ctx, active_ifname));

	team_for_each_port(port, ctx->th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		if (teamd_link_watch_port_up(ctx, ifindex)) {
			uint32_t speed = team_get_port_speed(port);
			uint8_t duplex = team_get_port_duplex(port);
			char *ifname = dev_name(ctx, ifindex);
			int prio = get_port_prio(ctx, ifname);

			if (!best_ifindex ||
			    (prio > best_prio) ||
			    (speed > best_speed) ||
			    (speed == best_speed && duplex > best_duplex)) {
				best_prio = prio;
				best_ifindex = ifindex;
				best_speed = speed;
				best_duplex = duplex;
			}
		} else if (ifindex == active_ifindex) {
			active_down = true;
		}
	}

	if (!best_ifindex || best_ifindex == active_ifindex)
		goto nochange;

	best_ifname = dev_name_dup(ctx, best_ifindex);
	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best_ifname, best_ifindex, best_prio);
	if ((active_down || !active_ifindex ||
	     !is_port_sticky(ctx, active_ifname))) {
		teamd_log_info("Changing active port to from \"%s\" to \"%s\".",
			       active_ifname, best_ifname);
		change_active_port(ctx, active_ifindex, best_ifindex);
	}
	free(best_ifname);

nochange:
	free(active_ifname);
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
