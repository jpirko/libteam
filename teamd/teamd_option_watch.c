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

static int tow_option_change_handler_func(struct team_handle *th, void *arg,
					  team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct team_option *option;
	int err;

	team_for_each_option(option, th) {
		if (!team_is_option_changed(option))
			continue;
		err = teamd_event_option_changed(ctx, option);
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
	return team_change_handler_register(ctx->th, &tow_option_change_handler);
}

void teamd_option_watch_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &tow_option_change_handler);
}

struct teamd_option_watch {
	struct list_item list;
	const struct teamd_option_watch_ops *ops;
	void *priv;
	struct teamd_context *ctx;
};

static int tow_option_changed(struct teamd_context *ctx,
			      struct team_option *option, void *priv)
{
	struct teamd_option_watch *watch = (struct teamd_option_watch *) priv;
	char *opt_name = team_get_option_name(option);
	int err;

	if (strcmp(opt_name, watch->ops->option_name))
		return 0;
	err = watch->ops->option_changed(ctx, option, watch->priv);
	if (err)
		return err;
	return 0;
}

struct teamd_event_watch_ops tow_event_watch_ops = {
	.option_changed = tow_option_changed,
};

int teamd_option_watch_register(struct teamd_option_watch **pwatch,
				struct teamd_context *ctx,
				const struct teamd_option_watch_ops *ops,
				void *priv)
{
	struct teamd_option_watch *watch;
	int err;

	watch = malloc(sizeof(*watch));
	if (!watch)
		return -ENOMEM;
	watch->ops = ops;
	watch->priv = priv;
	watch->ctx = ctx;
	err = teamd_event_watch_register(ctx, &tow_event_watch_ops, watch);
	if (err) {
		free(watch);
		return err;
	}
	*pwatch = watch;
	return 0;
}

void teamd_option_watch_unregister(struct teamd_option_watch *watch)
{
	teamd_event_watch_unregister(watch->ctx, &tow_event_watch_ops, watch);
	free(watch);
}
