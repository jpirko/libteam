/*
 *   teamd_link_watch.c - Team port link watchers
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
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
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <time.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_link_watch.h"

extern const struct teamd_link_watch teamd_link_watch_ethtool;
extern const struct teamd_link_watch teamd_link_watch_arp_ping;
extern const struct teamd_link_watch teamd_link_watch_nsnap;
extern const struct teamd_link_watch teamd_link_watch_tipc;

int __set_sockaddr(struct sockaddr *sa, socklen_t sa_len, sa_family_t family,
		   const char *hostname)
{
	struct addrinfo *result;
	struct addrinfo hints;
	int err;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	err = getaddrinfo(hostname, NULL, &hints, &result);
	if (err) {
		teamd_log_err("getaddrinfo failed: %s", gai_strerror(err));
		return -EINVAL;
	}
	if (sa_len != result->ai_addrlen) {
		/* This should not happen, so just to be safe */
		teamd_log_err("Wrong address length in result.");
		return -EINVAL;
	}
	memcpy(sa, result->ai_addr, sa_len);
	freeaddrinfo(result);
	return 0;
}


char *__str_sockaddr(struct sockaddr *sa, socklen_t sa_len, sa_family_t family,
		     char *buf, size_t buflen)
{
	int err;

	sa->sa_family = family;
	err = getnameinfo(sa, sa_len, buf, buflen, NULL, 0, NI_NUMERICHOST);
	if (err) {
		teamd_log_err("getnameinfo failed: %s", gai_strerror(err));
		return NULL;
	}
	return buf;
}

int teamd_link_watch_check_link_up(struct teamd_context *ctx,
				   struct teamd_port *tdport,
				   struct lw_common_port_priv *common_ppriv,
				   bool new_link_up)
{
	const char *lw_name = common_ppriv->link_watch->name;

	if (!teamd_link_watch_link_up_differs(common_ppriv, new_link_up))
		return 0;
	common_ppriv->link_up = new_link_up;
	teamd_log_info("%s: %s-link went %s.", tdport->ifname, lw_name,
		       new_link_up ? "up" : "down");
	return teamd_event_port_link_changed(ctx, tdport);
}

/*
 * General link watch code
 */
static const struct teamd_link_watch *teamd_link_watch_list[] = {
	&teamd_link_watch_ethtool,
	&teamd_link_watch_arp_ping,
	&teamd_link_watch_nsnap,
	&teamd_link_watch_tipc,
};

#define TEAMD_LINK_WATCH_LIST_SIZE ARRAY_SIZE(teamd_link_watch_list)

/*
 * For port priv identification purposes
 */
#define LW_PORT_PRIV_CREATOR_PRIV (&teamd_link_watch_list)

static const struct teamd_link_watch *teamd_find_link_watch(const char *link_watch_name)
{
	int i;

	for (i = 0; i < TEAMD_LINK_WATCH_LIST_SIZE; i++) {
		if (strcmp(teamd_link_watch_list[i]->name, link_watch_name) == 0)
			return teamd_link_watch_list[i];
	}
	return NULL;
}

bool teamd_link_watch_port_up(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	struct lw_common_port_priv *common_ppriv;
	bool link;

	if (!tdport)
		return true;
	link = true;
	teamd_for_each_port_priv_by_creator(common_ppriv, tdport,
					    LW_PORT_PRIV_CREATOR_PRIV) {
		link = common_ppriv->link_up;
		if (link)
			return link;
	}
	return link;
}

static int teamd_link_watch_refresh_user_linkup(struct teamd_context *ctx,
						struct teamd_port *tdport)
{
	bool link;
	bool cur_link;
	int err;

	if (!teamd_port_present(ctx, tdport))
		return 0;

	link = teamd_link_watch_port_up(ctx, tdport);
	err = team_get_port_user_linkup(ctx->th, tdport->ifindex,
					&cur_link);
	if (!err && link == cur_link)
		return 0;
	err = team_set_port_user_linkup(ctx->th, tdport->ifindex,
					link);
	if (err)
		return err;
	return 0;
}

static int link_watch_state_name_get(struct teamd_context *ctx,
				     struct team_state_gsc *gsc,
				     void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;

	gsc->data.str_val.ptr = common_ppriv->link_watch->name;
	return 0;
}

static int link_watch_state_up_get(struct teamd_context *ctx,
				   struct team_state_gsc *gsc,
				   void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;

	gsc->data.bool_val = common_ppriv->link_up;
	return 0;
}

static const struct teamd_state_val link_watch_state_vals[] = {
	{
		.subpath = "name",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = link_watch_state_name_get,
	},
	{
		.subpath = "up",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = link_watch_state_up_get,
	},
};

static const struct teamd_state_val link_watch_state_vg = {
	.vals = link_watch_state_vals,
	.vals_count = ARRAY_SIZE(link_watch_state_vals),
};

#define LW_STATE_SUBPATH "link_watches"
#define LW_LIST_STATE_SUBPATH LW_STATE_SUBPATH ".list"

static int link_watch_state_register(struct teamd_context *ctx,
				     struct lw_common_port_priv *common_ppriv)
{
	int err;

	err = teamd_state_val_register_ex(ctx, &link_watch_state_vg,
					  common_ppriv, common_ppriv->tdport,
					  LW_LIST_STATE_SUBPATH
					  ".link_watch_%d",
					  common_ppriv->id);
	if (err)
		return err;

	err = teamd_state_val_register_ex(ctx,
					  &common_ppriv->link_watch->state_vg,
					  common_ppriv, common_ppriv->tdport,
					  LW_LIST_STATE_SUBPATH
					  ".link_watch_%d",
					  common_ppriv->id);
	if (err)
		goto errout;
	return 0;
errout:
	teamd_state_val_unregister(ctx, &link_watch_state_vg, common_ppriv);
	return err;
}

static void link_watch_state_unregister(struct teamd_context *ctx,
					struct lw_common_port_priv *common_ppriv)
{
	teamd_state_val_unregister(ctx, &common_ppriv->link_watch->state_vg,
				   common_ppriv);
	teamd_state_val_unregister(ctx, &link_watch_state_vg, common_ppriv);
}

static unsigned int link_watch_select_free_id(struct teamd_port *tdport)
{
	struct lw_common_port_priv *common_ppriv;
	unsigned int id = 0;

	teamd_for_each_port_priv_by_creator(common_ppriv, tdport,
					    LW_PORT_PRIV_CREATOR_PRIV) {
		if (id <= common_ppriv->id)
			id = common_ppriv->id + 1;
	}
	return id;
}

static int link_watch_load_config_one(struct teamd_context *ctx,
				      struct teamd_port *tdport,
				      struct teamd_config_path_cookie *cpcookie)
{
	int err;
	const char *link_watch_name;
	const struct teamd_link_watch *link_watch;
	unsigned int id;
	struct lw_common_port_priv *common_ppriv;
	bool linkup = false;

	err = team_get_port_user_linkup(ctx->th, tdport->ifindex, &linkup);
	if (!err) {
		teamd_log_dbg("%s: Current user link state is \"%s\".",
			      tdport->ifname, linkup ? "up" : "down");
	}

	err = teamd_config_string_get(ctx, &link_watch_name,
				      "@.name", cpcookie);
	if (err) {
		teamd_log_err("%s: Failed to get link watch name.",
			      tdport->ifname);
		return err;
	}
	link_watch = teamd_find_link_watch(link_watch_name);
	if (!link_watch) {
		teamd_log_err("No link_watch named \"%s\" available.",
			      link_watch_name);
		return -EINVAL;
	}
	id = link_watch_select_free_id(tdport);
	err = teamd_port_priv_create_and_get((void **) &common_ppriv, tdport,
					     &link_watch->port_priv,
					     LW_PORT_PRIV_CREATOR_PRIV);
	if (err)
		return err;
	common_ppriv->id = id;
	common_ppriv->link_watch = link_watch;
	common_ppriv->ctx = ctx;
	common_ppriv->tdport = tdport;
	common_ppriv->cpcookie = cpcookie;
	common_ppriv->link_up = linkup;

	err = link_watch_state_register(ctx, common_ppriv);
	if (err)
		return err;
	return 0;
}

static int link_watch_load_config(struct teamd_context *ctx,
				  struct teamd_port *tdport,
				  struct teamd_config_path_cookie *cpcookie)
{
	int i;
	int err;

	if (!teamd_config_path_is_arr(ctx, "@", cpcookie))
		return link_watch_load_config_one(ctx, tdport, cpcookie);

	teamd_config_for_each_arr_index(i, ctx, "@", cpcookie) {
		struct teamd_config_path_cookie *item_cpcookie;

		item_cpcookie = teamd_config_path_cookie_get(ctx, "@[%d]",
							     cpcookie, i);
		err = link_watch_load_config_one(ctx, tdport, item_cpcookie);
		if (err)
			return err;
	}
	return 0;
}

#define TEAMD_DEFAULT_LINK_WATCH_NAME "ethtool"

static int link_watch_event_watch_port_added(struct teamd_context *ctx,
					     struct teamd_port *tdport,
					     void *priv)
{
	struct teamd_config_path_cookie *cpcookie;
	int err;

	cpcookie = teamd_config_path_cookie_get(ctx, "$.ports.%s.link_watch",
						tdport->ifname);
	if (cpcookie) {
		teamd_log_dbg("%s: Got link watch from port config.",
			      tdport->ifname);
		err = link_watch_load_config(ctx, tdport, cpcookie);
		if (err)
			return err;
	}

	cpcookie = teamd_config_path_cookie_get(ctx, "$.link_watch");
	if (cpcookie) {
		teamd_log_dbg("%s: Got link watch from global config.",
			      tdport->ifname);
		err = link_watch_load_config(ctx, tdport, cpcookie);
		if (err)
			return err;
	}

	if (!teamd_get_first_port_priv_by_creator(tdport,
						  LW_PORT_PRIV_CREATOR_PRIV)) {
		/* In case no link watch was found for this port, edit config
		 * by adding implicit one and call this function recursively.
		 */
		err = teamd_config_string_set(ctx, TEAMD_DEFAULT_LINK_WATCH_NAME,
					      "$.ports.%s.link_watch.name",
					      tdport->ifname);
		if (err) {
			teamd_log_err("%s: Failed to set implicit link watch name in config.",
				      tdport->ifname);
			return err;
		}
		teamd_log_dbg("%s: Using implicit link watch.", tdport->ifname);
		return link_watch_event_watch_port_added(ctx, tdport, priv);
	}
	return 0;
}

static void link_watch_event_watch_port_removed(struct teamd_context *ctx,
						struct teamd_port *tdport,
						void *priv)
{
	struct lw_common_port_priv *common_ppriv;

	teamd_for_each_port_priv_by_creator(common_ppriv, tdport,
					    LW_PORT_PRIV_CREATOR_PRIV)
		link_watch_state_unregister(ctx, common_ppriv);
}

static int link_watch_event_watch_port_link_changed(struct teamd_context *ctx,
						    struct teamd_port *tdport,
						    void *priv)
{
	return teamd_link_watch_refresh_user_linkup(ctx, tdport);
}

static void __set_forced_send_for_port(struct teamd_port *tdport,
				       bool forced_send)
{
	struct lw_common_port_priv *common_ppriv;

	teamd_for_each_port_priv_by_creator(common_ppriv, tdport,
					    LW_PORT_PRIV_CREATOR_PRIV) {
		common_ppriv->forced_send = forced_send;
	}
}

static int link_watch_refresh_forced_send(struct teamd_context *ctx)
{
	struct teamd_port *tdport;
	bool port_enabled;
	int enabled_port_count = 0;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		err = teamd_port_enabled(ctx, tdport, &port_enabled);
		if (err)
			return err;
		__set_forced_send_for_port(tdport, port_enabled);
		if (port_enabled)
			enabled_port_count++;
	}

	/*
	 * In case no ports are enabled, set forced_send to true for all
	 * ports. That enforces active linkwatch approach to regain link
	 * on some port again.
	 */
	if (enabled_port_count == 0) {
		teamd_for_each_tdport(tdport, ctx)
			__set_forced_send_for_port(tdport, true);
	}
	return 0;
}

static int link_watch_enabled_option_changed(struct teamd_context *ctx,
					     struct team_option *option,
					     void *priv)
{
	return link_watch_refresh_forced_send(ctx);
}

static const struct teamd_event_watch_ops link_watch_port_watch_ops = {
	.port_added = link_watch_event_watch_port_added,
	.port_removed = link_watch_event_watch_port_removed,
	.port_link_changed = link_watch_event_watch_port_link_changed,
	.option_changed = link_watch_enabled_option_changed,
	.option_changed_match_name = "enabled",
};

static int port_link_state_up_get(struct teamd_context *ctx,
				  struct team_state_gsc *gsc,
				  void *priv)
{
	gsc->data.bool_val = teamd_link_watch_port_up(ctx, gsc->info.tdport);
	return 0;
}

static const struct teamd_state_val link_watch_root_state_vals[] = {
	{
		.subpath = "up",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = port_link_state_up_get,
	},
};

static const struct teamd_state_val link_watch_root_state_vg = {
	.subpath = LW_STATE_SUBPATH,
	.vals = link_watch_root_state_vals,
	.vals_count = ARRAY_SIZE(link_watch_root_state_vals),
	.per_port = true,
};

int teamd_link_watch_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &link_watch_port_watch_ops, NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_state_val_register(ctx, &link_watch_root_state_vg, ctx);
	if (err)
		goto event_watch_unregister;
	return 0;

event_watch_unregister:
	teamd_event_watch_unregister(ctx, &link_watch_port_watch_ops, NULL);
	return err;
}

void teamd_link_watch_fini(struct teamd_context *ctx)
{
	teamd_state_val_unregister(ctx, &link_watch_root_state_vg, ctx);
	teamd_event_watch_unregister(ctx, &link_watch_port_watch_ops, NULL);
}
