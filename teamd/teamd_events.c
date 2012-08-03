/*
 *   teamd_events.c - Infrastructure for watching all sorts of events
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

struct event_watch_item {
	struct list_item list;
	const struct teamd_event_watch_ops *ops;
	void *priv;
};

int teamd_event_port_added(struct teamd_context *ctx,
			   struct teamd_port *tdport)
{
	struct event_watch_item *watch;
	int err;

	list_for_each_node_entry(watch, &ctx->event_watch_list, list) {
		if (!watch->ops->port_added)
			continue;
		err = watch->ops->port_added(ctx, tdport, watch->priv);
		if (err)
			return err;
	}
	return 0;
}

void teamd_event_port_removed(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	struct event_watch_item *watch;

	list_for_each_node_entry(watch, &ctx->event_watch_list, list) {
		if (!watch->ops->port_removed)
			continue;
		watch->ops->port_removed(ctx, tdport, watch->priv);
	}
}

int teamd_event_option_changed(struct teamd_context *ctx,
			       struct team_option *option)
{
	struct event_watch_item *watch;
	int err;

	list_for_each_node_entry(watch, &ctx->event_watch_list, list) {
		if (!watch->ops->option_changed)
			continue;
		err = watch->ops->option_changed(ctx, option, watch->priv);
		if (err)
			return err;
	}
	return 0;
}

int teamd_events_init(struct teamd_context *ctx)
{
	list_init(&ctx->event_watch_list);
	return 0;
}

void teamd_events_fini(struct teamd_context *ctx)
{
}

static struct event_watch_item *
__find_event_watch(struct teamd_context *ctx,
		   const struct teamd_event_watch_ops *ops,
		   void *priv)
{
	struct event_watch_item *watch;

	list_for_each_node_entry(watch, &ctx->event_watch_list, list) {
		if (watch->ops == ops && watch->priv == priv)
			return watch;
	}
	return NULL;
}

int teamd_event_watch_register(struct teamd_context *ctx,
			       const struct teamd_event_watch_ops *ops,
			       void *priv)
{
	struct event_watch_item *watch;

	if (__find_event_watch(ctx, ops, priv))
		return -EEXIST;
	watch = malloc(sizeof(*watch));
	if (!watch)
		return -ENOMEM;
	watch->ops = ops;
	watch->priv = priv;
	list_add_tail(&ctx->event_watch_list, &watch->list);
	return 0;
}

void teamd_event_watch_unregister(struct teamd_context *ctx,
				  const struct teamd_event_watch_ops *ops,
				  void *priv)
{
	struct event_watch_item *watch;

	watch = __find_event_watch(ctx, ops, priv);
	if (!watch)
		return;
	list_del(&watch->list);
	free(watch);
}
