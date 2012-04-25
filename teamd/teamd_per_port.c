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
	struct teamd_port port; /* must be first */
	struct list_item list;
	bool to_be_freed;
	void *runner_priv;
	void *link_watch_priv;
};

#define _port(ppitem) (&(ppitem)->port)

static struct port_priv_item *ppitem_alloc(struct teamd_context *ctx,
					   uint32_t ifindex,
					   struct team_port *team_port)
{
	struct port_priv_item *ppitem;
	struct teamd_port *tdport;
	struct team_ifinfo *team_ifinfo;

	ppitem = myzalloc(sizeof(*ppitem));
	if (!ppitem)
		goto err_out;
	tdport = _port(ppitem);
	tdport->ifindex = ifindex;
	team_ifinfo = team_get_port_ifinfo(team_port);
	tdport->ifname = team_get_ifinfo_ifname(team_ifinfo);
	tdport->team_port = team_port;
	tdport->team_ifinfo = team_ifinfo;
	if (ctx->runner->port_priv_size) {
		ppitem->runner_priv = myzalloc(ctx->runner->port_priv_size);
		if (!ppitem->runner_priv)
			goto free_ppitem;
	}
	teamd_link_watch_select(ctx, tdport);
	if (tdport->link_watch && tdport->link_watch->port_priv_size) {
		ppitem->link_watch_priv =
				myzalloc(tdport->link_watch->port_priv_size);
		if (!ppitem->link_watch_priv)
			goto free_runner_priv;
	}
	return ppitem;

free_runner_priv:
	free(ppitem->runner_priv);
free_ppitem:
	free(ppitem);
err_out:
	teamd_log_err("Failed to alloc port priv.");
	return NULL;
}

static void ppitem_free(struct port_priv_item *ppitem)
{
	free(ppitem->link_watch_priv);
	free(ppitem->runner_priv);
	free(ppitem);
}

static int ppitem_create(struct teamd_context *ctx,
			 struct port_priv_item **p_ppitem,
			 uint32_t ifindex,
			 struct team_port *team_port)
{
	struct port_priv_item *ppitem;
	struct teamd_port *tdport;
	int err;

	ppitem = ppitem_alloc(ctx, ifindex, team_port);
	if (!ppitem)
		return -ENOMEM;
	tdport = _port(ppitem);
	list_add(&ctx->port_priv_list, &ppitem->list);
	if (tdport->link_watch && tdport->link_watch->port_added) {
		err = tdport->link_watch->port_added(ctx, tdport);
		if (err) {
			teamd_log_err("Link watch port_added failed: %s.",
				      strerror(-err));
			goto list_del;
		}
	}
	if (ctx->runner && ctx->runner->port_added) {
		err = ctx->runner->port_added(ctx, tdport);
		if (err) {
			teamd_log_err("Runner port_added failed: %s.",
				      strerror(-err));
			goto lw_port_removed;
		}
	}
	*p_ppitem = ppitem;
	return 0;
lw_port_removed:
	if (tdport->link_watch && tdport->link_watch->port_removed)
		tdport->link_watch->port_removed(ctx, tdport);
list_del:
	list_del(&ppitem->list);
	ppitem_free(ppitem);
	return err;
}

static void ppitem_destroy(struct teamd_context *ctx,
			   struct port_priv_item *ppitem)
{
	struct teamd_port *tdport = _port(ppitem);

	list_del(&ppitem->list);
	if (ctx->runner && ctx->runner->port_removed)
		ctx->runner->port_removed(ctx, tdport);
	if (tdport->link_watch && tdport->link_watch->port_removed)
		tdport->link_watch->port_removed(ctx, tdport);
}

static struct port_priv_item *get_ppitem(struct teamd_context *ctx,
					 uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	list_for_each_node_entry(ppitem, &ctx->port_priv_list, list) {
		if (_port(ppitem)->ifindex == ifindex)
			return ppitem;
	}
	return NULL;
}

void *teamd_get_runner_port_priv(struct teamd_port *tdport)
{
	struct port_priv_item *ppitem = (struct port_priv_item *) tdport;

	return ppitem->runner_priv;
}

void *teamd_get_link_watch_port_priv(struct teamd_port *tdport)
{
	struct port_priv_item *ppitem = (struct port_priv_item *) tdport;

	return ppitem->link_watch_priv;
}

static void check_ppitems_to_be_freed(struct teamd_context *ctx)
{
	struct port_priv_item *ppitem, *tmp;

	list_for_each_node_entry_safe(ppitem, tmp,
				      &ctx->port_priv_list, list) {
		if (ppitem->to_be_freed)
			ppitem_free(ppitem);
	}
}

static int port_priv_change_handler_func(struct team_handle *th, void *arg,
					  team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_port *port;
	struct port_priv_item *ppitem;
	int err;

	check_ppitems_to_be_freed(ctx);

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		ppitem = get_ppitem(ctx, ifindex);
		if (!ppitem) {
			err = ppitem_create(ctx, &ppitem, ifindex, port);
			if (err)
				return err;
		}
		if (team_is_port_removed(port)) {
			ppitem_destroy(ctx, ppitem);
			ppitem->to_be_freed = true;
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

	list_init(&ctx->port_priv_list);
	err = team_change_handler_register(ctx->th, &port_priv_change_handler);
	return err;
}

void teamd_per_port_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &port_priv_change_handler);
	check_ppitems_to_be_freed(ctx);
}

struct teamd_port *teamd_get_port(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	ppitem = get_ppitem(ctx, ifindex);
	if (!ppitem)
		return NULL;
	return _port(ppitem);
}

struct teamd_port *teamd_get_next_tdport(struct teamd_context *ctx,
					 struct teamd_port *tdport)
{
	struct port_priv_item *ppitem = NULL;

	if (tdport)
		ppitem = get_container(tdport, struct port_priv_item, port);
	ppitem = list_get_next_node_entry(&ctx->port_priv_list, ppitem, list);
	if (!ppitem)
		return NULL;
	return _port(ppitem);
}
