/*
 *   teamd_per_port.c - Per-port data structures and actions
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

struct port_priv_item {
	struct list_item list;
	const struct teamd_port_priv *pp;
	void *creator_priv;
	long priv[0];
};

struct port_obj {
	struct teamd_port port; /* must be first */
	struct list_item list;
	struct list_item priv_list;
};

#define _port(port_obj) (&(port_obj)->port)

int teamd_port_priv_create_and_get(void **ppriv, struct teamd_port *tdport,
				   const struct teamd_port_priv *pp,
				   void *creator_priv)
{
	struct port_priv_item *ppitem;
	struct port_obj *port_obj;

	ppitem = myzalloc(sizeof(*ppitem) + pp->priv_size);
	if (!ppitem)
		return -ENOMEM;
	ppitem->pp = pp;
	ppitem->creator_priv = creator_priv;
	port_obj = get_container(tdport, struct port_obj, port);
	list_add(&port_obj->priv_list, &ppitem->list);
	if (ppriv)
		*ppriv = ppitem->priv;
	return 0;
}
int teamd_port_priv_create(struct teamd_port *tdport,
			   const struct teamd_port_priv *pp, void *creator_priv)
{
	return teamd_port_priv_create_and_get(NULL, tdport, pp, creator_priv);
}

void *teamd_get_next_port_priv_by_creator(struct teamd_port *tdport,
					  void *creator_priv, void *priv)
{
	struct port_priv_item *ppitem = NULL;
	struct port_obj *port_obj;

	if (priv)
		ppitem = get_container(priv, struct port_priv_item, priv);
	port_obj = get_container(tdport, struct port_obj, port);

next_ppitem:
	ppitem = list_get_next_node_entry(&port_obj->priv_list, ppitem, list);
	if (!ppitem)
		return NULL;
	if (ppitem->creator_priv != creator_priv)
		goto next_ppitem;
	return ppitem->priv;
}

void *teamd_get_first_port_priv_by_creator(struct teamd_port *tdport,
					   void *creator_priv)
{
	return teamd_get_next_port_priv_by_creator(tdport, creator_priv, NULL);
}

static int port_priv_init_all(struct teamd_context *ctx, struct port_obj *port_obj)
{
	struct port_priv_item *ppitem;
	int err;

	list_for_each_node_entry(ppitem, &port_obj->priv_list, list) {
		if (!ppitem->pp->init)
			continue;
		err = ppitem->pp->init(ctx, _port(port_obj), &ppitem->priv,
				       ppitem->creator_priv);
		if (err) {
			teamd_log_err("Failed to init port priv.");
			goto rollback;
		}
	}
	return 0;
rollback:
	list_for_each_node_entry_continue_reverse(ppitem, &port_obj->priv_list,
						  list) {
		if (!ppitem->pp->fini)
			continue;
		ppitem->pp->fini(ctx, _port(port_obj), &ppitem->priv,
				 ppitem->creator_priv);
	}
	return err;
}

static void port_priv_fini_all(struct teamd_context *ctx, struct port_obj *port_obj)
{
	struct port_priv_item *ppitem;

	list_for_each_node_entry(ppitem, &port_obj->priv_list, list) {
		if (!ppitem->pp->fini)
			continue;
		ppitem->pp->fini(ctx, _port(port_obj), &ppitem->priv,
				 ppitem->creator_priv);
	}
}

static void port_priv_free_all(struct port_obj *port_obj)
{
	struct port_priv_item *ppitem, *tmp;

	list_for_each_node_entry_safe(ppitem, tmp, &port_obj->priv_list, list)
		free(ppitem);
}

static struct port_obj *port_obj_alloc(struct teamd_context *ctx,
				       uint32_t ifindex,
				       struct team_port *team_port)
{
	struct port_obj *port_obj;
	struct teamd_port *tdport;
	struct team_ifinfo *team_ifinfo;

	port_obj = myzalloc(sizeof(*port_obj));
	if (!port_obj) {
		teamd_log_err("Failed to alloc port object.");
		return NULL;
	}
	list_init(&port_obj->priv_list);
	tdport = _port(port_obj);
	tdport->ifindex = ifindex;
	team_ifinfo = team_get_port_ifinfo(team_port);
	tdport->ifname = team_get_ifinfo_ifname(team_ifinfo);
	tdport->team_port = team_port;
	tdport->team_ifinfo = team_ifinfo;
	return port_obj;
}

static void port_obj_free(struct port_obj *port_obj)
{
	port_priv_free_all(port_obj);
	free(port_obj);
}

static void port_obj_destroy(struct teamd_context *ctx,
			     struct port_obj *port_obj)
{
	list_del(&port_obj->list);
	ctx->port_obj_list_count--;
	port_priv_fini_all(ctx, port_obj);
}

static int port_obj_create(struct teamd_context *ctx,
			   struct port_obj **p_port_obj,
			   uint32_t ifindex,
			   struct team_port *team_port)
{
	struct port_obj *port_obj;
	struct teamd_port *tdport;
	int err;

	port_obj = port_obj_alloc(ctx, ifindex, team_port);
	if (!port_obj)
		return -ENOMEM;
	tdport = _port(port_obj);
	list_add(&ctx->port_obj_list, &port_obj->list);
	ctx->port_obj_list_count++;
	err = teamd_event_port_added(ctx, tdport);
	if (err)
		goto list_del;
	err = port_priv_init_all(ctx, port_obj);
	if (err)
		goto teamd_event_port_removed;
	*p_port_obj = port_obj;
	return 0;

teamd_event_port_removed:
	teamd_event_port_removed(ctx, tdport);
list_del:
	port_obj_destroy(ctx, port_obj);
	port_obj_free(port_obj);
	return err;
}

static void port_obj_remove(struct teamd_context *ctx,
			    struct port_obj *port_obj)
{
	struct teamd_port *tdport = _port(port_obj);

	teamd_event_port_removed(ctx, tdport);
	port_obj_destroy(ctx, port_obj);
	port_obj_free(port_obj);
}

static struct port_obj *get_port_obj(struct teamd_context *ctx,
				     uint32_t ifindex)
{
	struct port_obj *port_obj;

	list_for_each_node_entry(port_obj, &ctx->port_obj_list, list) {
		if (_port(port_obj)->ifindex == ifindex)
			return port_obj;
	}
	return NULL;
}

static struct port_obj *get_port_obj_by_ifname(struct teamd_context *ctx,
					       const char *ifname)
{
	struct port_obj *port_obj;

	list_for_each_node_entry(port_obj, &ctx->port_obj_list, list) {
		if (!strcmp(_port(port_obj)->ifname, ifname))
			return port_obj;
	}
	return NULL;
}

static int port_priv_change_handler_func(struct team_handle *th, void *priv,
					 team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = priv;
	struct team_port *port;
	struct port_obj *port_obj;
	int err;

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		port_obj = get_port_obj(ctx, ifindex);
		if (!port_obj) {
			if (team_is_port_removed(port))
				continue;
			err = port_obj_create(ctx, &port_obj, ifindex, port);
			if (err)
				return err;
		}
		if (team_is_port_changed(port)) {
			err = teamd_event_port_changed(ctx, _port(port_obj));
			if (err)
				return err;
		}
		if (team_is_port_removed(port))
			port_obj_remove(ctx, port_obj);
	}
	return 0;
}

static const struct team_change_handler port_priv_change_handler = {
	.func = port_priv_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE,
};

int teamd_per_port_init(struct teamd_context *ctx)
{
	int err;

	list_init(&ctx->port_obj_list);
	err = team_change_handler_register(ctx->th,
					   &port_priv_change_handler, ctx);
	return err;
}

void teamd_per_port_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th,
				       &port_priv_change_handler, ctx);
}

struct teamd_port *teamd_get_port(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_obj *port_obj;

	port_obj = get_port_obj(ctx, ifindex);
	if (!port_obj)
		return NULL;
	return _port(port_obj);
}

struct teamd_port *teamd_get_port_by_ifname(struct teamd_context *ctx,
					    const char *ifname)
{
	struct port_obj *port_obj;

	port_obj = get_port_obj_by_ifname(ctx, ifname);
	if (!port_obj)
		return NULL;
	return _port(port_obj);
}

struct teamd_port *teamd_get_next_tdport(struct teamd_context *ctx,
					 struct teamd_port *tdport)
{
	struct port_obj *port_obj = NULL;

next_one:
	if (tdport)
		port_obj = get_container(tdport, struct port_obj, port);
	port_obj = list_get_next_node_entry(&ctx->port_obj_list, port_obj, list);
	if (!port_obj)
		return NULL;
	tdport = _port(port_obj);
	if (!teamd_port_present(ctx, tdport))
		goto next_one;
	return tdport;
}

int teamd_port_enabled(struct teamd_context *ctx, struct teamd_port *tdport,
		       bool *enabled)
{
	struct team_option *option;

	option = team_get_option(ctx->th, "np", "enabled", tdport->ifindex);
	if (!option) {
		teamd_log_err("%s: Failed to find \"enabled\" option.",
			      tdport->ifname);
		return -ENOENT;
	}
	if (team_get_option_type(option) != TEAM_OPTION_TYPE_BOOL) {
		teamd_log_err("Unexpected type of \"enabled\" option.");
		return -EINVAL;
	}

	*enabled = team_get_option_value_bool(option);
	return 0;
}

int teamd_port_prio(struct teamd_context *ctx, struct teamd_port *tdport)
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

int teamd_port_check_enable(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    bool should_enable, bool should_disable)
{
	bool new_enabled_state;
	bool curr_enabled_state;
	int err;

	if (!teamd_port_present(ctx, tdport))
		return 0;
	err = teamd_port_enabled(ctx, tdport, &curr_enabled_state);
	if (err)
		return err;

	if (!curr_enabled_state && should_enable)
		new_enabled_state = true;
	else if (curr_enabled_state && should_disable)
		new_enabled_state = false;
	else
		return 0;

	teamd_log_dbg("%s: %s port", tdport->ifname,
		      new_enabled_state ? "Enabling": "Disabling");
	err = team_set_port_enabled(ctx->th, tdport->ifindex,
				    new_enabled_state);
	if (err) {
		teamd_log_err("%s: Failed to %s port.", tdport->ifname,
			      new_enabled_state ? "enable": "disable");
		if (!TEAMD_ENOENT(err))
			return err;
	}
	return 0;
}
