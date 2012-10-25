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

struct ab_priv {
	char active_orig_hwaddr[MAX_ADDR_LEN];
	uint32_t active_ifindex;
};

static struct ab_priv *ab_priv(struct teamd_context *ctx)
{
	return (struct ab_priv *) ctx->runner_priv;
}

static int ab_get_port_prio(struct teamd_context *ctx,
			    struct teamd_port *tdport)
{
	int prio;
	int err;

	err = team_get_port_priority(ctx->th, tdport->ifindex, &prio);
	if (err) {
		teamd_log_warn("%s: Can't get port priority. Using default.",
			       tdport->ifname);
		return 0; /* return default priority */
	}
	return prio;
}

static bool ab_is_port_sticky(struct teamd_context *ctx, const char *port_name)
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

static int ab_clear_active_port(struct teamd_context *ctx)
{
	struct teamd_port *tdport;
	int err;

	tdport = teamd_get_port(ctx, ab_priv(ctx)->active_ifindex);
	if (!tdport)
		return 0;
	teamd_log_dbg("Clearing active port \"%s\".", tdport->ifname);

	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable active port.",
			      tdport->ifname);
		return err;
	}
	err = team_hwaddr_set(ctx->th, tdport->ifindex,
			      ab_priv(ctx)->active_orig_hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set restore active port original hardware address.",
			      tdport->ifname);
		return err;
	}
	ab_priv(ctx)->active_ifindex = 0;
	return 0;
}

static int ab_set_active_port(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	int err;

	teamd_log_info("Changing active port to \"%s\".",
		       tdport->ifname);

	err = team_set_port_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
		teamd_log_err("%s: Failed to enable active port.",
			      tdport->ifname);
		return err;
	}
	memcpy(ab_priv(ctx)->active_orig_hwaddr,
	       team_get_ifinfo_hwaddr(tdport->team_ifinfo),
	       ctx->hwaddr_len);

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set active port hardware address.",
			      tdport->ifname);
		return err;
	}
	ab_priv(ctx)->active_ifindex = tdport->ifindex;
	return 0;
}

struct ab_port_state_info {
	struct teamd_port *tdport;
	uint32_t speed;
	uint8_t duplex;
	int prio;
};

static void ab_best_port_check_set(struct teamd_context *ctx,
				   struct ab_port_state_info *best,
				   struct teamd_port *tdport)
{
	struct team_port *port;
	uint32_t speed;
	uint8_t duplex;
	int prio;

	if (!teamd_link_watch_port_up(ctx, tdport) || best->tdport == tdport)
		return;

	port = tdport->team_port;
	speed = team_get_port_speed(port);
	duplex = team_get_port_duplex(port);
	prio = ab_get_port_prio(ctx, tdport);

	if (!best->tdport || (prio > best->prio) || (speed > best->speed) ||
	    (speed == best->speed && duplex > best->duplex)) {
		best->tdport = tdport;
		best->prio = prio;
		best->speed = speed;
		best->duplex = duplex;
	}
}

static int ab_link_watch_handler(struct teamd_context *ctx)
{
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct ab_port_state_info best;
	int err;

	memset(&best, 0, sizeof(best));
	best.prio = INT_MIN;

	active_tdport = teamd_get_port(ctx, ab_priv(ctx)->active_ifindex);
	if (active_tdport) {
		teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      ab_get_port_prio(ctx, active_tdport));

		/*
		 * When active port went down, clear it and proceed as if
		 * none was set in the first place.
		 */
		if (!teamd_link_watch_port_up(ctx, active_tdport)) {
			err = ab_clear_active_port(ctx);
			if (err)
				return err;
			active_tdport = NULL;
		}
	}

	/*
	 * Find the best port amond all ports. Prefer the currently active
	 * port, if there's any. This is because other port might have the
	 * same prio, speed and duplex. We do not want to change in that case
	 */
	if (active_tdport)
		ab_best_port_check_set(ctx, &best, active_tdport);
	teamd_for_each_tdport(tdport, ctx)
		ab_best_port_check_set(ctx, &best, tdport);

	if (!best.tdport || best.tdport == active_tdport)
		return 0;

	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best.tdport->ifname, best.tdport->ifindex, best.prio);

	if (!active_tdport || !ab_is_port_sticky(ctx, active_tdport->ifname)) {
		err = ab_clear_active_port(ctx);
		if (err)
			return err;
		err = ab_set_active_port(ctx, best.tdport);
		if (err)
			return err;
	}
	return 0;
}

static int ab_event_watch_port_added(struct teamd_context *ctx,
				     struct teamd_port *tdport, void *priv)
{
	int err;

	/* Newly added ports are enabled */
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		return err;
	}

	return 0;
}

static void ab_event_watch_port_removed(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	ab_link_watch_handler(ctx);
}

static int ab_port_link_changed(struct teamd_context *ctx,
				struct teamd_port *tdport, void *priv)
{
	return ab_link_watch_handler(ctx);
}

static int ab_prio_option_changed(struct teamd_context *ctx,
				   struct team_option *option, void *priv)
{
	return ab_link_watch_handler(ctx);
}

static const struct teamd_event_watch_ops ab_event_watch_ops = {
	.port_added = ab_event_watch_port_added,
	.port_removed = ab_event_watch_port_removed,
	.port_link_changed = ab_port_link_changed,
	.option_changed = ab_prio_option_changed,
	.option_changed_match_name = "priority",
};

static int ab_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &ab_event_watch_ops, NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

static void ab_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, NULL);
}

static int ab_state_json_dump(struct teamd_context *ctx,
			       json_t **pstate_json, void *priv)
{
	struct teamd_port *active_tdport;
	json_t *state_json;
	char *active_port;

	active_tdport = teamd_get_port(ctx, ab_priv(ctx)->active_ifindex);
	active_port = active_tdport ? active_tdport->ifname : "";
	state_json = json_pack("{s:s}", "active_port", active_port);
	if (!state_json)
		return -ENOMEM;
	*pstate_json = state_json;
	return 0;
}

const struct teamd_runner teamd_runner_activebackup = {
	.name			= "activebackup",
	.team_mode_name		= "broadcast",
	.priv_size		= sizeof(struct ab_priv),
	.init			= ab_init,
	.fini			= ab_fini,
	.state_json_dump	= ab_state_json_dump,
};
