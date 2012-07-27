/*
 *   teamd_option_watch.c - Infrastructure for watching option changes
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

struct tow_item {
	struct list_item list;
	const struct teamd_option_watch *option_watch;
	void *option_watch_priv;
};

static struct tow_item *tow_find_item(struct teamd_context *ctx,
				      const struct teamd_option_watch *option_watch,
				      void *option_watch_priv)
{
	struct tow_item *item;

	list_for_each_node_entry(item, &ctx->option_watch_list, list) {
		if (item->option_watch == option_watch &&
		    item->option_watch_priv == option_watch_priv)
			return item;
	}
	return NULL;
}

static int tow_call_handlers_for_option(struct teamd_context *ctx,
					struct team_option *option)
{
	char *opt_name = team_get_option_name(option);
	struct tow_item *item;
	int err;

	list_for_each_node_entry(item, &ctx->option_watch_list, list) {
		if (strcmp(opt_name, item->option_watch->option_name))
			continue;
		err = item->option_watch->handler(ctx, option,
						  item->option_watch_priv);
		if (err)
			return err;
	}
	return 0;
}

static int tow_option_change_handler_func(struct team_handle *th, void *arg,
					  team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_option *option;
	int err;

	team_for_each_option(option, th) {
		err = tow_call_handlers_for_option(ctx, option);
		if (err)
			return err;
	}
	return 0;
}

static struct team_change_handler tow_option_change_handler = {
	.func = tow_option_change_handler_func,
	.type_mask = TEAM_OPTION_CHANGE,
};

int teamd_option_watch_init(struct teamd_context *ctx)
{
	int err;

	list_init(&ctx->option_watch_list);
	err = team_change_handler_register(ctx->th, &tow_option_change_handler);
	return err;
}

void teamd_option_watch_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &tow_option_change_handler);
}

int teamd_option_watch_register(struct teamd_context *ctx,
				const struct teamd_option_watch *option_watch,
				void *option_watch_priv)
{
	struct tow_item *item;

	if (tow_find_item(ctx, option_watch, option_watch_priv))
		return -EEXIST;
	item = malloc(sizeof(*item));
	if (!item)
		return -ENOMEM;
	item->option_watch = option_watch;
	item->option_watch_priv = option_watch_priv;
	list_add_tail(&ctx->option_watch_list, &item->list);
	return 0;
}

void teamd_option_watch_unregister(struct teamd_context *ctx,
				   const struct teamd_option_watch *option_watch,
				   void *option_watch_priv)
{
	struct tow_item *item;

	item = tow_find_item(ctx, option_watch, option_watch_priv);
	if (!item)
		return;
	list_del(&item->list);
	free(item);
}
