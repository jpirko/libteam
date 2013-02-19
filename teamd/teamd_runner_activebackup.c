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
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

struct ab_priv;

struct ab_hwaddr_policy {
	const char *name;
	int (*hwaddr_changed)(struct teamd_context *ctx,
			      struct ab_priv *ab_priv);
	int (*port_added)(struct teamd_context *ctx, struct ab_priv *ab_priv,
			  struct teamd_port *tdport);
	int (*active_set)(struct teamd_context *ctx, struct ab_priv *ab_priv,
			  struct teamd_port *tdport);
	int (*active_clear)(struct teamd_context *ctx, struct ab_priv *ab_priv,
			    struct teamd_port *tdport);
};

struct ab_priv {
	uint32_t active_ifindex;
	char active_orig_hwaddr[MAX_ADDR_LEN];
	const struct ab_hwaddr_policy *hwaddr_policy;
};

static int ab_hwaddr_policy_same_all_hwaddr_changed(struct teamd_context *ctx,
						    struct ab_priv *ab_priv)
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

static int ab_hwaddr_policy_same_all_port_added(struct teamd_context *ctx,
						struct ab_priv *ab_priv,
						struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_same_all = {
	.name = "same_all",
	.hwaddr_changed = ab_hwaddr_policy_same_all_hwaddr_changed,
	.port_added = ab_hwaddr_policy_same_all_port_added,
};

static int ab_hwaddr_policy_by_active_active_set(struct teamd_context *ctx,
						 struct ab_priv *ab_priv,
						 struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, ctx->ifindex,
			      team_get_ifinfo_hwaddr(tdport->team_ifinfo),
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to team hardware address.");
		return err;
	}
	return 0;
}

static const struct ab_hwaddr_policy ab_hwaddr_policy_by_active = {
	.name = "by_active",
	.active_set = ab_hwaddr_policy_by_active_active_set,
};

static int ab_hwaddr_policy_only_active_hwaddr_changed(struct teamd_context *ctx,
						       struct ab_priv *ab_priv)
{
	struct teamd_port *tdport;
	int err;

	tdport = teamd_get_port(ctx, ab_priv->active_ifindex);
	if (!tdport)
		return 0;
	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int ab_hwaddr_policy_only_active_active_set(struct teamd_context *ctx,
						   struct ab_priv *ab_priv,
						   struct teamd_port *tdport)
{
	int err;

	memcpy(ab_priv->active_orig_hwaddr,
	       team_get_ifinfo_hwaddr(tdport->team_ifinfo),
	       ctx->hwaddr_len);
	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int ab_hwaddr_policy_only_active_active_clear(struct teamd_context *ctx,
						     struct ab_priv *ab_priv,
						     struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex,
			      ab_priv->active_orig_hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set port hardware address.",
			      tdport->ifname);
		return err;
	}
	return 0;
}


static const struct ab_hwaddr_policy ab_hwaddr_policy_only_active = {
	.name = "only_active",
	.hwaddr_changed = ab_hwaddr_policy_only_active_hwaddr_changed,
	.active_set = ab_hwaddr_policy_only_active_active_set,
	.active_clear = ab_hwaddr_policy_only_active_active_clear,
};

static const struct ab_hwaddr_policy *ab_hwaddr_policy_list[] = {
	&ab_hwaddr_policy_same_all,
	&ab_hwaddr_policy_by_active,
	&ab_hwaddr_policy_only_active,
};

#define AB_HWADDR_POLICY_LIST_SIZE ARRAY_SIZE(ab_hwaddr_policy_list)

static int ab_assign_hwaddr_policy(struct ab_priv *ab_priv,
				   char *hwaddr_policy_name)
{
	int i = 0;

	if (!hwaddr_policy_name)
		goto found;
	for (i = 0; i < AB_HWADDR_POLICY_LIST_SIZE; i++)
		if (!strcmp(ab_hwaddr_policy_list[i]->name, hwaddr_policy_name))
			goto found;
	return -ENOENT;
found:
	ab_priv->hwaddr_policy = ab_hwaddr_policy_list[i];
	return 0;
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

static int ab_clear_active_port(struct teamd_context *ctx,
				struct ab_priv *ab_priv)
{
	struct teamd_port *tdport;
	int err;

	tdport = teamd_get_port(ctx, ab_priv->active_ifindex);
	if (!tdport || team_is_port_removed(tdport->team_port))
		return 0;
	teamd_log_dbg("Clearing active port \"%s\".", tdport->ifname);

	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		if (teamd_err_port_disappeared(err, ctx, tdport))
			goto finish;
		teamd_log_err("%s: Failed to disable active port.",
			      tdport->ifname);
		return err;
	}
	if (ab_priv->hwaddr_policy->active_clear) {
		err =  ab_priv->hwaddr_policy->active_clear(ctx, ab_priv,
							    tdport);
		if (err)
			return err;
	}
finish:
	ab_priv->active_ifindex = 0;
	return 0;
}

static int ab_set_active_port(struct teamd_context *ctx,
			      struct ab_priv *ab_priv,
			      struct teamd_port *tdport)
{
	int err;

	err = team_set_port_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
		if (teamd_err_port_disappeared(err, ctx, tdport))
			return 0;
		teamd_log_err("%s: Failed to enable active port.",
			      tdport->ifname);
		return err;
	}
	err = team_set_active_port(ctx->th, tdport->ifindex);
	if (err) {
		teamd_log_err("%s: Failed to set as active port.",
			      tdport->ifname);
		return err;
	}
	ab_priv->active_ifindex = tdport->ifindex;
	if (ab_priv->hwaddr_policy->active_set) {
		err =  ab_priv->hwaddr_policy->active_set(ctx, ab_priv,
							  tdport);
		if (err)
			return err;
	}
	teamd_log_info("Changed active port to \"%s\".",
		       tdport->ifname);
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
	struct team_port *port = tdport->team_port;
	uint32_t speed;
	uint8_t duplex;
	int prio;

	if (!teamd_link_watch_port_up(ctx, tdport) || best->tdport == tdport ||
	    team_is_port_removed(port))
		return;

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

static int ab_link_watch_handler(struct teamd_context *ctx,
				 struct ab_priv *ab_priv)
{
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct ab_port_state_info best;
	int err;
	uint32_t active_ifindex;

	memset(&best, 0, sizeof(best));
	best.prio = INT_MIN;

	active_tdport = teamd_get_port(ctx, ab_priv->active_ifindex);
	if (active_tdport) {
		teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      ab_get_port_prio(ctx, active_tdport));

		err = team_get_active_port(ctx->th, &active_ifindex);
		if (err) {
			teamd_log_err("Failed to get active port.");
			return err;
		}

		/*
		 * When active port went down or it is other than currently set,
		 * clear it and proceed as if none was set in the first place.
		 */
		if (!teamd_link_watch_port_up(ctx, active_tdport) ||
		    active_ifindex != active_tdport->ifindex) {
			err = ab_clear_active_port(ctx, ab_priv);
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
		err = ab_clear_active_port(ctx, ab_priv);
		if (err)
			return err;
		err = ab_set_active_port(ctx, ab_priv, best.tdport);
		if (err)
			return err;
	}
	return 0;
}

static int ab_event_watch_hwaddr_changed(struct teamd_context *ctx, void *priv)
{
	struct ab_priv *ab_priv = priv;

	if (ab_priv->hwaddr_policy->hwaddr_changed)
		return ab_priv->hwaddr_policy->hwaddr_changed(ctx, ab_priv);
	return 0;
}

static int ab_event_watch_port_added(struct teamd_context *ctx,
				     struct teamd_port *tdport, void *priv)
{
	struct ab_priv *ab_priv = priv;
	int err;

	/* Newly added ports are enabled */
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		return err;
	}

	if (ab_priv->hwaddr_policy->port_added)
		return ab_priv->hwaddr_policy->port_added(ctx, ab_priv, tdport);
	return 0;
}

static void ab_event_watch_port_removed(struct teamd_context *ctx,
					struct teamd_port *tdport, void *priv)
{
	ab_link_watch_handler(ctx, priv);
}

static int ab_event_watch_port_link_changed(struct teamd_context *ctx,
					    struct teamd_port *tdport,
					    void *priv)
{
	return ab_link_watch_handler(ctx, priv);
}

static int ab_event_watch_prio_option_changed(struct teamd_context *ctx,
					      struct team_option *option,
					      void *priv)
{
	return ab_link_watch_handler(ctx, priv);
}

static const struct teamd_event_watch_ops ab_event_watch_ops = {
	.hwaddr_changed = ab_event_watch_hwaddr_changed,
	.port_added = ab_event_watch_port_added,
	.port_removed = ab_event_watch_port_removed,
	.port_link_changed = ab_event_watch_port_link_changed,
	.option_changed = ab_event_watch_prio_option_changed,
	.option_changed_match_name = "priority",
};

static int ab_load_config(struct teamd_context *ctx, struct ab_priv *ab_priv)
{
	int err;
	char *hwaddr_policy_name;

	err = json_unpack(ctx->config_json, "{s:{s:s}}", "runner", "hwaddr_policy",
			  &hwaddr_policy_name);
	if (err)
		hwaddr_policy_name = NULL;
	err = ab_assign_hwaddr_policy(ab_priv, hwaddr_policy_name);
	if (err) {
		teamd_log_err("Unknown \"hwaddr_policy\" named \"%s\" passed.",
			      hwaddr_policy_name);
		return err;
	}
	teamd_log_dbg("Using hwaddr_policy \"%s\".", ab_priv->hwaddr_policy->name);
	return 0;
}

static int ab_init(struct teamd_context *ctx)
{
	struct ab_priv *ab_priv = ctx->runner_priv;
	int err;

	err = ab_load_config(ctx, ab_priv);
	if (err) {
		teamd_log_err("Failed to load config values.");
		return err;
	}
	err = teamd_event_watch_register(ctx, &ab_event_watch_ops, ab_priv);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

static void ab_fini(struct teamd_context *ctx)
{
	struct ab_priv *ab_priv = ctx->runner_priv;

	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, ab_priv);
}

static int ab_state_json_dump(struct teamd_context *ctx,
			       json_t **pstate_json, void *priv)
{
	struct ab_priv *ab_priv = priv;
	struct teamd_port *active_tdport;
	json_t *state_json;
	char *active_port;

	active_tdport = teamd_get_port(ctx, ab_priv->active_ifindex);
	active_port = active_tdport ? active_tdport->ifname : "";
	state_json = json_pack("{s:s}", "active_port", active_port);
	if (!state_json)
		return -ENOMEM;
	*pstate_json = state_json;
	return 0;
}

static const struct teamd_state_json_ops ab_state_ops = {
	.dump			= ab_state_json_dump,
	.name			= TEAMD_RUNNER_STATE_JSON_NAME,
};

const struct teamd_runner teamd_runner_activebackup = {
	.name			= "activebackup",
	.team_mode_name		= "activebackup",
	.priv_size		= sizeof(struct ab_priv),
	.init			= ab_init,
	.fini			= ab_fini,
	.state_json_ops		= &ab_state_ops,
};
