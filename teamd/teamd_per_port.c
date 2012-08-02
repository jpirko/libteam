/*
 *   teamd_per_port.c - Per-port data structures and actions
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
	bool to_be_freed;
	void *link_watch_priv;
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
	return teamd_port_priv_create_and_get(NULL, tdport,pp, creator_priv);
}

void *teamd_get_next_port_priv_by_creator(struct teamd_port *tdport,
					  void *creator_priv, void *priv)
{
	struct port_priv_item *ppitem = NULL;
	struct port_obj *port_obj;

	if (priv)
		ppitem = get_container(priv, struct port_priv_item, priv);
	port_obj = get_container(tdport, struct port_obj, port);
	ppitem = list_get_next_node_entry(&port_obj->priv_list, ppitem, list);
	if (!ppitem)
		return NULL;
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

static void port_priv_free_all(struct teamd_context *ctx, struct port_obj *port_obj)
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
	if (!port_obj)
		goto err_out;
	list_init(&port_obj->priv_list);
	tdport = _port(port_obj);
	tdport->ifindex = ifindex;
	team_ifinfo = team_get_port_ifinfo(team_port);
	tdport->ifname = team_get_ifinfo_ifname(team_ifinfo);
	tdport->team_port = team_port;
	tdport->team_ifinfo = team_ifinfo;
	teamd_link_watch_select(ctx, tdport);
	if (tdport->link_watch && tdport->link_watch->port_priv_size) {
		port_obj->link_watch_priv =
				myzalloc(tdport->link_watch->port_priv_size);
		if (!port_obj->link_watch_priv)
			goto free_port_obj;
	}
	return port_obj;

free_port_obj:
	free(port_obj);
err_out:
	teamd_log_err("Failed to alloc port object.");
	return NULL;
}

static void port_obj_free(struct port_obj *port_obj)
{
	free(port_obj->link_watch_priv);
	free(port_obj);
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
	if (tdport->link_watch && tdport->link_watch->port_added) {
		err = tdport->link_watch->port_added(ctx, tdport);
		if (err) {
			teamd_log_err("Link watch port_added failed: %s.",
				      strerror(-err));
			goto teamd_event_port_removed;
		}
	}
	err = port_priv_init_all(ctx, port_obj);
	if (err)
		goto lw_port_removed;
	*p_port_obj = port_obj;
	return 0;
lw_port_removed:
	if (tdport->link_watch && tdport->link_watch->port_removed)
		tdport->link_watch->port_removed(ctx, tdport);
teamd_event_port_removed:
	teamd_event_port_removed(ctx, tdport);
list_del:
	list_del(&port_obj->list);
	ctx->port_obj_list_count--;
	port_obj_free(port_obj);
	return err;
}

static void port_obj_destroy(struct teamd_context *ctx,
			     struct port_obj *port_obj)
{
	struct teamd_port *tdport = _port(port_obj);

	teamd_event_port_removed(ctx, tdport);
	list_del(&port_obj->list);
	ctx->port_obj_list_count--;
	port_priv_fini_all(ctx, port_obj);
	port_priv_free_all(ctx, port_obj);
	if (tdport->link_watch && tdport->link_watch->port_removed)
		tdport->link_watch->port_removed(ctx, tdport);
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

void *teamd_get_link_watch_port_priv(struct teamd_port *tdport)
{
	struct port_obj *port_obj = (struct port_obj *) tdport;

	return port_obj->link_watch_priv;
}

static void check_port_objs_to_be_freed(struct teamd_context *ctx)
{
	struct port_obj *port_obj, *tmp;

	list_for_each_node_entry_safe(port_obj, tmp,
				      &ctx->port_obj_list, list) {
		if (port_obj->to_be_freed)
			port_obj_free(port_obj);
	}
}

static int port_priv_change_handler_func(struct team_handle *th, void *arg,
					 team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_port *port;
	struct port_obj *port_obj;
	int err;

	check_port_objs_to_be_freed(ctx);

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		port_obj = get_port_obj(ctx, ifindex);
		if (!port_obj) {
			err = port_obj_create(ctx, &port_obj, ifindex, port);
			if (err)
				return err;
		}
		if (team_is_port_removed(port)) {
			port_obj_destroy(ctx, port_obj);
			port_obj->to_be_freed = true;
		}
	}
	return 0;
}

static struct team_change_handler port_priv_change_handler = {
	.func = port_priv_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE,
};

int teamd_per_port_init(struct teamd_context *ctx)
{
	int err;

	list_init(&ctx->port_obj_list);
	err = team_change_handler_register(ctx->th, &port_priv_change_handler);
	return err;
}

void teamd_per_port_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &port_priv_change_handler);
	check_port_objs_to_be_freed(ctx);
}

struct teamd_port *teamd_get_port(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_obj *port_obj;

	port_obj = get_port_obj(ctx, ifindex);
	if (!port_obj)
		return NULL;
	return _port(port_obj);
}

struct teamd_port *teamd_get_next_tdport(struct teamd_context *ctx,
					 struct teamd_port *tdport)
{
	struct port_obj *port_obj = NULL;

	if (tdport)
		port_obj = get_container(tdport, struct port_obj, port);
	port_obj = list_get_next_node_entry(&ctx->port_obj_list, port_obj, list);
	if (!port_obj)
		return NULL;
	return _port(port_obj);
}
