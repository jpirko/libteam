/*
 *   teamd_state_json.c - State of Teamd in JSON format
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <jansson.h>

#include "teamd.h"

struct state_json_item {
	struct list_item list;
	const struct teamd_state_json_ops *ops;
	void *priv;
};

int teamd_state_json_init(struct teamd_context *ctx)
{
	list_init(&ctx->state_json_list);
	return 0;
}

void teamd_state_json_fini(struct teamd_context *ctx)
{
}

static struct state_json_item *__find_item(struct teamd_context *ctx,
					   const struct teamd_state_json_ops *ops,
					   void *priv)
{
	struct state_json_item *item;

	list_for_each_node_entry(item, &ctx->state_json_list, list) {
		if (item->ops == ops && item->priv == priv)
			return item;
	}
	return NULL;
}

static struct state_json_item *__find_item_by_name(struct teamd_context *ctx,
						   const char *name)
{
	struct state_json_item *item;

	list_for_each_node_entry(item, &ctx->state_json_list, list) {
		if (item->ops->name == name)
			return item;
	}
	return NULL;
}

int teamd_state_json_register(struct teamd_context *ctx,
			      const struct teamd_state_json_ops *ops,
			      void *priv)
{
	struct state_json_item *item;

	if (__find_item_by_name(ctx, ops->name))
		return -EBUSY;
	item = malloc(sizeof(*item));
	if (!item)
		return -ENOMEM;
	item->ops = ops;
	item->priv = priv;
	list_add_tail(&ctx->state_json_list, &item->list);
	return 0;
}

void teamd_state_json_unregister(struct teamd_context *ctx,
				 const struct teamd_state_json_ops *ops,
				 void *priv)
{
	struct state_json_item *item;

	item = __find_item(ctx, ops, priv);
	if (!item)
		return;
	list_del(&item->list);
	free(item);
}

int teamd_state_json_dump(struct teamd_context *ctx, json_t **pstate_json)
{
	struct state_json_item *item;
	json_t *state_json;
	json_t *substate_json;
	int err;

	state_json = json_object();
	if (!state_json)
		return -ENOMEM;
	list_for_each_node_entry(item, &ctx->state_json_list, list) {
		if (!item->ops->dump)
			continue;
		err = item->ops->dump(ctx, &substate_json, item->priv);
		if (err)
			goto errout;
		err = json_object_set_new(state_json, item->ops->name,
					  substate_json);
		if (err) {
			err = -ENOMEM;
			goto errout;
		}
	}
	*pstate_json = state_json;
	return 0;
errout:
	json_decref(state_json);
	return err;
}
