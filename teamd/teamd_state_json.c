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
#include <team.h>
#include <private/misc.h>

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


/*
 * state basics
 */

static json_t *__fill_ifinfo(struct team_ifinfo *ifinfo)
{
	size_t hwaddr_len = team_get_ifinfo_hwaddr_len(ifinfo);
	char addr_str[hwaddr_str_len(hwaddr_len)];

	hwaddr_str(addr_str, team_get_ifinfo_hwaddr(ifinfo), hwaddr_len);
	return json_pack("{s:i, s:s, s:s, s:i}",
			 "ifindex", team_get_ifinfo_ifindex(ifinfo),
			 "ifname", team_get_ifinfo_ifname(ifinfo),
			 "dev_addr", addr_str,
			 "add_len", team_get_ifinfo_hwaddr_len(ifinfo));
}

static int teamdev_state_dump(struct teamd_context *ctx,
			      json_t **pstate_json, void *priv)
{
	json_t *state_json;
	json_t *ifinfo_json;

	ifinfo_json = __fill_ifinfo(team_get_ifinfo(ctx->th));
	if (!ifinfo_json)
		return -ENOMEM;
	state_json = json_pack("{s:o}", "ifinfo", ifinfo_json);
	if (!state_json) {
		json_decref(ifinfo_json);
		return -ENOMEM;
	}
	*pstate_json = state_json;
	return 0;
}

static const struct teamd_state_json_ops teamdev_state_ops = {
	.dump = teamdev_state_dump,
	.name = "team_device",
};

static json_t *__fill_tdport(struct teamd_port *tdport)
{
	struct team_port *port = tdport->team_port;
	json_t *ifinfo_json;
	json_t *tdport_json;

	ifinfo_json = __fill_ifinfo(tdport->team_ifinfo);
	if (!ifinfo_json)
		return NULL;

	tdport_json = json_pack("{s:o, s:{s:b, s:i, s:s}}",
				"ifinfo", ifinfo_json,
				"link", "up",
				team_is_port_link_up(port),
				"speed", team_get_port_speed(port),
				"duplex",
				team_get_port_duplex(port) ? "full" : "half");
	if (!tdport_json)
		json_decref(ifinfo_json);
	return tdport_json;
}

static int portdevs_state_dump(struct teamd_context *ctx,
			       json_t **pstate_json, void *priv)
{
	struct teamd_port *tdport;
	int err;
	json_t *state_json;
	json_t *tdport_json;

	state_json = json_object();
	if (!state_json)
		return -ENOMEM;

	teamd_for_each_tdport(tdport, ctx) {
		tdport_json = __fill_tdport(tdport);
		if (!tdport_json)
			goto errout;
		err = json_object_set_new(state_json, tdport->ifname,
					  tdport_json);
		if (err) {
			err = -ENOMEM;
			goto errout;
		}
	}

	*pstate_json = state_json;
	return 0;
errout:
	json_decref(state_json);
	return -ENOMEM;
}

static const struct teamd_state_json_ops portdevs_state_ops = {
	.dump = portdevs_state_dump,
	.name = "port_devices",
};

static int setup_state_dump(struct teamd_context *ctx,
			    json_t **pstate_json, void *priv)
{
	json_t *state_json;

	state_json = json_pack("{s:s, s:s, s:b, s:i, s:b, s:i, s:s}",
			       "runner_name", ctx->runner->name,
			       "kernel_team_mode_name", ctx->runner->team_mode_name,
			       "dbus_enabled", ctx->dbus.enabled,
			       "debug_level", ctx->debug,
			       "daemonized", ctx->daemonize,
			       "pid", getpid(),
			       "pid_file", ctx->pid_file ? ctx->pid_file : "");
	if (!state_json) {
		return -ENOMEM;
	}
	*pstate_json = state_json;
	return 0;
}

static const struct teamd_state_json_ops setup_state_ops = {
	.dump = setup_state_dump,
	.name = "setup",
};

int teamd_state_json_basics_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_state_json_register(ctx, &teamdev_state_ops, ctx);
	if (err)
		return err;
	err = teamd_state_json_register(ctx, &portdevs_state_ops, ctx);
	if (err)
		goto teamdev_state_unreg;
	err = teamd_state_json_register(ctx, &setup_state_ops, ctx);
	if (err)
		goto portdevs_state_unreg;
	return 0;

portdevs_state_unreg:
	teamd_state_json_unregister(ctx, &portdevs_state_ops, ctx);
teamdev_state_unreg:
	teamd_state_json_unregister(ctx, &teamdev_state_ops, ctx);
	return err;
}

void teamd_state_json_basics_fini(struct teamd_context *ctx)
{
	teamd_state_json_unregister(ctx, &setup_state_ops, ctx);
	teamd_state_json_unregister(ctx, &portdevs_state_ops, ctx);
	teamd_state_json_unregister(ctx, &teamdev_state_ops, ctx);
}
