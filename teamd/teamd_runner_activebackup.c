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
#include <limits.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_state.h"

struct ab;

struct ab_hwaddr_policy {
	const char *name;
	int (*hwaddr_changed)(struct teamd_context *ctx,
			      struct ab *ab);
	int (*port_added)(struct teamd_context *ctx, struct ab *ab,
			  struct teamd_port *tdport);
	int (*active_set)(struct teamd_context *ctx, struct ab *ab,
			  struct teamd_port *tdport);
	int (*active_clear)(struct teamd_context *ctx, struct ab *ab,
			    struct teamd_port *tdport);
};

struct ab {
	uint32_t active_ifindex;
	char active_orig_hwaddr[MAX_ADDR_LEN];
	const struct ab_hwaddr_policy *hwaddr_policy;
};

struct ab_port {
	struct teamd_port *tdport;
	struct {
		bool sticky;
#define		AB_DFLT_PORT_STICKY false
	} cfg;
};

static struct ab_port *ab_port_get(struct ab *ab, struct teamd_port *tdport)
{
	/*
	 * When calling this after teamd_event_watch_register() which is in
	 * ab_init() it is ensured that this will always return valid priv
	 * pointer for an existing port.
	 */
	return teamd_get_first_port_priv_by_creator(tdport, ab);
}

static bool ab_is_port_sticky(struct ab *ab, struct teamd_port *tdport)
{
	return ab_port_get(ab, tdport)->cfg.sticky;
}

static int ab_hwaddr_policy_same_all_hwaddr_changed(struct teamd_context *ctx,
						    struct ab *ab)
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
						struct ab *ab,
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
						 struct ab *ab,
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
						       struct ab *ab)
{
	struct teamd_port *tdport;
	int err;

	tdport = teamd_get_port(ctx, ab->active_ifindex);
	if (!tdport || !teamd_port_present(ctx, tdport))
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
						   struct ab *ab,
						   struct teamd_port *tdport)
{
	int err;

	memcpy(ab->active_orig_hwaddr,
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
						     struct ab *ab,
						     struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex,
			      ab->active_orig_hwaddr,
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

static int ab_assign_hwaddr_policy(struct ab *ab,
				   const char *hwaddr_policy_name)
{
	int i = 0;

	if (!hwaddr_policy_name)
		goto found;
	for (i = 0; i < AB_HWADDR_POLICY_LIST_SIZE; i++)
		if (!strcmp(ab_hwaddr_policy_list[i]->name, hwaddr_policy_name))
			goto found;
	return -ENOENT;
found:
	ab->hwaddr_policy = ab_hwaddr_policy_list[i];
	return 0;
}

static int ab_clear_active_port(struct teamd_context *ctx, struct ab *ab,
				struct teamd_port *tdport)
{
	int err;

	ab->active_ifindex = 0;
	if (!tdport || !teamd_port_present(ctx, tdport))
		return 0;
	teamd_log_dbg("Clearing active port \"%s\".", tdport->ifname);

	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable active port.",
			      tdport->ifname);
		return err;
	}
	if (ab->hwaddr_policy->active_clear) {
		err =  ab->hwaddr_policy->active_clear(ctx, ab, tdport);
		if (err)
			return err;
	}
	return 0;
}

static int ab_set_active_port(struct teamd_context *ctx, struct ab *ab,
			      struct teamd_port *tdport)
{
	int err;

	err = team_set_port_enabled(ctx->th, tdport->ifindex, true);
	if (err) {
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
	ab->active_ifindex = tdport->ifindex;
	if (ab->hwaddr_policy->active_set) {
		err =  ab->hwaddr_policy->active_set(ctx, ab, tdport);
		if (err)
			return err;
	}
	teamd_log_info("Changed active port to \"%s\".", tdport->ifname);
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

	if (!teamd_link_watch_port_up(ctx, tdport) || best->tdport == tdport)
		return;

	speed = team_get_port_speed(port);
	duplex = team_get_port_duplex(port);
	prio = teamd_port_prio(ctx, tdport);

	if (!best->tdport || (prio > best->prio) || (speed > best->speed) ||
	    (speed == best->speed && duplex > best->duplex)) {
		best->tdport = tdport;
		best->prio = prio;
		best->speed = speed;
		best->duplex = duplex;
	}
}

static int ab_link_watch_handler(struct teamd_context *ctx, struct ab *ab)
{
	struct teamd_port *tdport;
	struct teamd_port *active_tdport;
	struct ab_port_state_info best;
	int err;
	uint32_t active_ifindex;

	memset(&best, 0, sizeof(best));
	best.prio = INT_MIN;

	active_tdport = teamd_get_port(ctx, ab->active_ifindex);
	if (active_tdport) {
		teamd_log_dbg("Current active port: \"%s\" (ifindex \"%d\", prio \"%d\").",
			      active_tdport->ifname, active_tdport->ifindex,
			      teamd_port_prio(ctx, active_tdport));

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
			err = ab_clear_active_port(ctx, ab, active_tdport);
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
	if (active_tdport && teamd_port_present(ctx, active_tdport))
		ab_best_port_check_set(ctx, &best, active_tdport);
	teamd_for_each_tdport(tdport, ctx)
		ab_best_port_check_set(ctx, &best, tdport);

	if (!best.tdport || best.tdport == active_tdport)
		return 0;

	teamd_log_dbg("Found best port: \"%s\" (ifindex \"%d\", prio \"%d\").",
		      best.tdport->ifname, best.tdport->ifindex, best.prio);

	if (!active_tdport || !ab_is_port_sticky(ab, active_tdport)) {
		err = ab_clear_active_port(ctx, ab, active_tdport);
		if (err)
			return err;
		err = ab_set_active_port(ctx, ab, best.tdport);
		if (err)
			return err;
	}
	return 0;
}

static int ab_event_watch_hwaddr_changed(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;

	if (ab->hwaddr_policy->hwaddr_changed)
		return ab->hwaddr_policy->hwaddr_changed(ctx, ab);
	return 0;
}

static int ab_port_load_config(struct teamd_context *ctx,
			       struct ab_port *ab_port)
{
	const char *port_name = ab_port->tdport->ifname;
	int err;

	err = teamd_config_bool_get(ctx, &ab_port->cfg.sticky,
				    "$.ports.%s.sticky", port_name);
	if (err)
		ab_port->cfg.sticky = AB_DFLT_PORT_STICKY;
	teamd_log_dbg("%s: Using sticky \"%d\".", port_name,
		      ab_port->cfg.sticky);
	return 0;
}

static int ab_port_added(struct teamd_context *ctx,
			 struct teamd_port *tdport,
			 void *priv, void *creator_priv)
{
	struct ab_port *ab_port = priv;
	struct ab *ab = creator_priv;
	int err;

	ab_port->tdport = tdport;
	err = ab_port_load_config(ctx, ab_port);
	if (err) {
		teamd_log_err("Failed to load port config.");
		return err;
	}
	/* Newly added ports are enabled */
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		return err;
	}

	if (ab->hwaddr_policy->port_added)
		return ab->hwaddr_policy->port_added(ctx, ab, tdport);
	return 0;
}

static void ab_port_removed(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv)
{
	struct ab *ab = creator_priv;

	ab_link_watch_handler(ctx, ab);
}

static const struct teamd_port_priv ab_port_priv = {
	.init = ab_port_added,
	.fini = ab_port_removed,
	.priv_size = sizeof(struct ab_port),
};

static int ab_event_watch_port_added(struct teamd_context *ctx,
				     struct teamd_port *tdport, void *priv)
{
	struct ab *ab = priv;

	return teamd_port_priv_create(tdport, &ab_port_priv, ab);
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
	.port_link_changed = ab_event_watch_port_link_changed,
	.option_changed = ab_event_watch_prio_option_changed,
	.option_changed_match_name = "priority",
};

static int ab_load_config(struct teamd_context *ctx, struct ab *ab)
{
	int err;
	const char *hwaddr_policy_name;

	err = teamd_config_string_get(ctx, &hwaddr_policy_name, "$.runner.hwaddr_policy");
	if (err)
		hwaddr_policy_name = NULL;
	err = ab_assign_hwaddr_policy(ab, hwaddr_policy_name);
	if (err) {
		teamd_log_err("Unknown \"hwaddr_policy\" named \"%s\" passed.",
			      hwaddr_policy_name);
		return err;
	}
	teamd_log_dbg("Using hwaddr_policy \"%s\".", ab->hwaddr_policy->name);
	return 0;
}

static int ab_state_active_port_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	struct ab *ab = priv;
	struct teamd_port *active_tdport;

	active_tdport = teamd_get_port(ctx, ab->active_ifindex);
	gsc->data.str_val.ptr = active_tdport ? active_tdport->ifname : "";
	return 0;
}

static const struct teamd_state_val ab_state_vals[] = {
	{
		.subpath = "active_port",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ab_state_active_port_get,
	},
};

static const struct teamd_state_val_group ab_state_vg = {
	.subpath = "runner",
	.vals = ab_state_vals,
	.vals_count = ARRAY_SIZE(ab_state_vals),
};

static int ab_init(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;
	int err;

	err = ab_load_config(ctx, ab);
	if (err) {
		teamd_log_err("Failed to load config values.");
		return err;
	}
	err = teamd_event_watch_register(ctx, &ab_event_watch_ops, ab);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_state_val_group_register(ctx, &ab_state_vg, ab);
	if (err) {
		teamd_log_err("Failed to register state group.");
		goto event_watch_unregister;
	}
	return 0;

event_watch_unregister:
	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, ab);
	return err;
}

static void ab_fini(struct teamd_context *ctx, void *priv)
{
	struct ab *ab = priv;

	teamd_state_val_group_unregister(ctx, &ab_state_vg, ab);
	teamd_event_watch_unregister(ctx, &ab_event_watch_ops, ab);
}

const struct teamd_runner teamd_runner_activebackup = {
	.name			= "activebackup",
	.team_mode_name		= "activebackup",
	.priv_size		= sizeof(struct ab),
	.init			= ab_init,
	.fini			= ab_fini,
};
