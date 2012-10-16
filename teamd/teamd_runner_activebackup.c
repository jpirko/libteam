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
	char old_active_hwaddr[MAX_ADDR_LEN];
};

static struct abl_priv *abl_priv(struct teamd_context *ctx)
{
	return (struct abl_priv *) ctx->runner_priv;
}

static int get_port_prio(struct teamd_context *ctx, struct teamd_port *tdport)
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

static int change_active_port(struct teamd_context *ctx,
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
		if (err) {
			teamd_log_err("Failed to set old active original hardware address.");
			return err;
		}
	}

	err = team_set_active_port(ctx->th, new_active_ifindex);
	if (err) {
		teamd_log_err("Failed to set active port.");
		return err;
	}

	memcpy(abl_priv(ctx)->old_active_hwaddr,
	       team_get_ifinfo_hwaddr(new_tdport->team_ifinfo),
	       ctx->hwaddr_len);

	err = team_hwaddr_set(ctx->th, new_active_ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set new active hardware address.");
		return err;
	}
	return 0;
}

static int abl_get_active_tdport(struct teamd_context *ctx,
				 struct teamd_port **pactive_tdport)
{
	int err;
	uint32_t ifindex;

	err = team_get_active_port(ctx->th, &ifindex);
	if (err) {
		teamd_log_err("Failed to get active port.");
		return err;
	}
	*pactive_tdport = teamd_get_port(ctx, ifindex);
	return 0;
}

struct abl_port_state_info {
	struct teamd_port *tdport;
	uint32_t speed;
	uint8_t duplex;
	int prio;
};

static void abl_best_port_check_set(struct teamd_context *ctx,
				    struct abl_port_state_info *best,
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
	prio = get_port_prio(ctx, tdport);

	if (!best->tdport || (prio > best->prio) || (speed > best->speed) ||
	    (speed == best->speed && duplex > best->duplex)) {
		best->tdport = tdport;
		best->prio = prio;
		best->speed = speed;
		best->duplex = duplex;
	}
}

static int link_watch_handler(struct teamd_context *ctx)
{
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct abl_port_state_info best;
	int err;

	memset(&best, 0, sizeof(best));
	best.prio = INT_MIN;

	err = abl_get_active_tdport(ctx, &active_tdport);
	if (err)
		return err;
	if (active_tdport) {
		teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      get_port_prio(ctx, active_tdport));
		abl_best_port_check_set(ctx, &best, active_tdport);
	}

	teamd_for_each_tdport(tdport, ctx)
		abl_best_port_check_set(ctx, &best, tdport);

	if (!best.tdport || best.tdport == active_tdport)
		return 0;

	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best.tdport->ifname, best.tdport->ifindex, best.prio);
	if (!active_tdport ||
	    !teamd_link_watch_port_up(ctx, active_tdport) ||
	    !is_port_sticky(ctx, active_tdport->ifname)) {
		teamd_log_info("Changing active port to \"%s\".",
			       best.tdport->ifname);
		err = change_active_port(ctx, active_tdport, best.tdport);
		if (err)
			return err;
	}
	return 0;
}

static int abl_event_watch_port_added(struct teamd_context *ctx,
				      struct teamd_port *tdport, void *priv)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set port \"%s\" hardware address. ",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int abl_port_link_changed(struct teamd_context *ctx,
				 struct teamd_port *tdport, void *priv)
{
	return link_watch_handler(ctx);
}

static int abl_prio_option_changed(struct teamd_context *ctx,
				   struct team_option *option, void *priv)
{
	return link_watch_handler(ctx);
}

static const struct teamd_event_watch_ops abl_event_watch_ops = {
	.port_added = abl_event_watch_port_added,
	.port_link_changed = abl_port_link_changed,
	.option_changed = abl_prio_option_changed,
	.option_changed_match_name = "priority",
};

static int abl_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &abl_event_watch_ops, NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

static void abl_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &abl_event_watch_ops, NULL);
}

static int abl_state_json_dump(struct teamd_context *ctx,
			       json_t **pstate_json, void *priv)
{
	int err;
	struct teamd_port *active_tdport;
	json_t *state_json;
	char *active_port;

	err = abl_get_active_tdport(ctx, &active_tdport);
	if (err)
		return err;

	active_port = active_tdport ? active_tdport->ifname : "";
	state_json = json_pack("{s:s}", "active_port", active_port);
	if (!state_json)
		return -ENOMEM;
	*pstate_json = state_json;
	return 0;
}

const struct teamd_runner teamd_runner_activebackup = {
	.name			= "activebackup",
	.team_mode_name		= "activebackup",
	.priv_size		= sizeof(struct abl_priv),
	.init			= abl_init,
	.fini			= abl_fini,
	.state_json_dump	= abl_state_json_dump,
};
