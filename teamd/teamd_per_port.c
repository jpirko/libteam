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
	struct teamd_port port;
	struct list_item list;
	bool to_be_removed;
	void *runner_priv;
	void *link_watch_priv;
};

#define _port(ppitem) (&(ppitem)->port)

static struct port_priv_item *alloc_ppitem(struct teamd_context *ctx,
					   uint32_t ifindex)
{
	struct port_priv_item *ppitem;
	struct teamd_port *tdport;

	ppitem = myzalloc(sizeof(*ppitem));
	if (!ppitem)
		goto err_out;
	tdport = _port(ppitem);
	tdport->ifindex = ifindex;
	tdport->ifname = dev_name_dup(ctx, ifindex);
	if (!tdport->ifname)
		goto free_ppitem;
	if (ctx->runner->port_priv_size) {
		ppitem->runner_priv = myzalloc(ctx->runner->port_priv_size);
		if (!ppitem->runner_priv)
			goto free_ifname;
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
free_ifname:
	free(_port(ppitem)->ifname);
free_ppitem:
	free(ppitem);
err_out:
	teamd_log_err("Failed to alloc port priv.");
	return NULL;
}

static void ppitem_free(struct port_priv_item *ppitem)
{
	list_del(&ppitem->list);
	free(ppitem->link_watch_priv);
	free(ppitem->runner_priv);
	free(_port(ppitem)->ifname);
	free(ppitem);
}

static int create_ppitem(struct teamd_context *ctx,
			 struct port_priv_item **p_ppitem,
			 uint32_t ifindex)
{
	struct port_priv_item *ppitem;
	struct teamd_port *tdport;
	int err;

	ppitem = alloc_ppitem(ctx, ifindex);
	if (!ppitem)
		return -ENOMEM;
	tdport = _port(ppitem);
	list_add(&ctx->port_priv_list, &ppitem->list);
	if (tdport->link_watch && tdport->link_watch->port_added) {
		err = tdport->link_watch->port_added(ctx, ifindex,
						     ppitem->link_watch_priv);
		if (err) {
			teamd_log_err("Link watch port_added failed: %s.",
				      strerror(-err));
			goto list_del;
		}
	}
	if (ctx->runner->port_added) {
		err = ctx->runner->port_added(ctx, ifindex,
					      ppitem->runner_priv);
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
		tdport->link_watch->port_removed(ctx, ifindex,
						 ppitem->link_watch_priv);
list_del:
	list_del(&ppitem->list);
	ppitem_free(ppitem);
	return err;
}

static void ppitem_destroy(struct teamd_context *ctx,
			   struct port_priv_item *ppitem)
{
	struct teamd_port *tdport = _port(ppitem);

	if (ctx->runner->port_removed)
		ctx->runner->port_removed(ctx, tdport->ifindex,
					  ppitem->runner_priv);
	if (tdport->link_watch && tdport->link_watch->port_removed)
		tdport->link_watch->port_removed(ctx, tdport->ifindex,
						 ppitem->link_watch_priv);
	ppitem_free(ppitem);
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

void *teamd_get_runner_port_priv(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	ppitem = get_ppitem(ctx, ifindex);
	if (!ppitem)
		return NULL;
	return ppitem->runner_priv;
}

void *teamd_get_link_watch_port_priv(struct teamd_context *ctx,
				     uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	ppitem = get_ppitem(ctx, ifindex);
	if (!ppitem)
		return NULL;
	return ppitem->link_watch_priv;
}

static void check_ppitems_to_be_removed(struct teamd_context *ctx, bool killall)
{
	struct port_priv_item *ppitem, *tmp;

	list_for_each_node_entry_safe(ppitem, tmp,
				      &ctx->port_priv_list, list) {
		if (killall || ppitem->to_be_removed)
			ppitem_destroy(ctx, ppitem);
	}
}

static void teamd_free_port_privs(struct teamd_context *ctx)
{
	check_ppitems_to_be_removed(ctx, true);
}

static void port_priv_change_handler_func(struct team_handle *th, void *arg,
					  team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_port *port;
	struct port_priv_item *ppitem;
	int err;

	check_ppitems_to_be_removed(ctx, false);

	team_for_each_port(port, th) {
		uint32_t ifindex = team_get_port_ifindex(port);

		ppitem = get_ppitem(ctx, ifindex);
		if (!ppitem) {
			err = create_ppitem(ctx, &ppitem, ifindex);
			if (err) {
				teamd_run_loop_quit(ctx, err);
				return;
			}
		}
		if (team_is_port_removed(port))
			ppitem->to_be_removed = true;
	}
}

static struct team_change_handler port_priv_change_handler = {
	.func = port_priv_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE | TEAM_OPTION_CHANGE,
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
	teamd_free_port_privs(ctx);
}

struct teamd_port *teamd_get_port(struct teamd_context *ctx, uint32_t ifindex)
{
	struct port_priv_item *ppitem;

	ppitem = get_ppitem(ctx, ifindex);
	if (!ppitem)
		return NULL;
	return _port(ppitem);
}
