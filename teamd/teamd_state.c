/*
 *   teamd_state.c - Teamd state
 *   Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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
#include "teamd_state.h"
#include "teamd_json.h"

struct teamd_state_vg_item {
	struct list_item list;
	char *subpath;
	const struct teamd_state_val_group *vg;
	void *priv;
};

static struct teamd_state_vg_item *
__find_vg_item(struct teamd_context *ctx,
	       const struct teamd_state_val_group *vg, void *priv)
{
	struct teamd_state_vg_item *item;

	list_for_each_node_entry(item, &ctx->state_vg_list, list) {
		if (item->vg == vg && item->priv == priv)
			return item;
	}
	return NULL;
}

int teamd_state_val_group_register(struct teamd_context *ctx,
				   const struct teamd_state_val_group *vg,
				   void *priv, const char *fmt, ...)
{
	va_list ap;
	struct teamd_state_vg_item *item;
	char *subpath;
	int ret;

	if (__find_vg_item(ctx, vg, priv))
		return -EEXIST;
	va_start(ap, fmt);
	ret = vasprintf(&subpath, fmt, ap);
	va_end(ap);
	if (ret == -1)
		return -ENOMEM;

	item = malloc(sizeof(*item));
	if (!item) {
		free(subpath);
		return -ENOMEM;
	}
	item->subpath = subpath;
	item->vg = vg;
	item->priv = priv;
	list_add_tail(&ctx->state_vg_list, &item->list);
	return 0;
}

void teamd_state_val_group_unregister(struct teamd_context *ctx,
				      const struct teamd_state_val_group *vg,
				      void *priv)
{
	struct teamd_state_vg_item *item;

	item = __find_vg_item(ctx, vg, priv);
	if (!item)
		return;
	list_del(&item->list);
	free(item->subpath);
	free(item);
}

static int teamd_state_build_val_group_subpath(json_t **p_vg_json_obj,
					       json_t *root_json_obj,
					       struct teamd_port *tdport,
					       const char *subpath)
{
	char *path;
	int ret;
	int err;

	if (tdport)
		ret = asprintf(&path, "$.ports.%s.%s", tdport->ifname, subpath);
	else
		ret = asprintf(&path, "$.%s", subpath);
	if (ret == -1)
		return -ENOMEM;
	err = teamd_json_path_lite_build(p_vg_json_obj, root_json_obj, path);
	free(path);
	return err;
}

static int teamd_state_val_group_dump(struct teamd_context *ctx,
				      json_t *root_json_obj,
				      struct teamd_port *tdport,
				      const char *subpath,
				      const struct teamd_state_val_group *vg,
				      void *priv)
{
	const struct teamd_state_val *val;
	struct team_state_val_gsetter_ctx gsc;
	json_t *val_json_obj = val_json_obj;
	json_t *vg_json_obj = vg_json_obj;
	int i;
	int err;
	int ret;

	err = teamd_state_build_val_group_subpath(&vg_json_obj, root_json_obj,
						  tdport, subpath);
	if (err)
		return err;

	for (i = 0; i < vg->vals_count; i++) {
		val = &vg->vals[i];
		memset(&gsc, 0, sizeof(gsc));
		gsc.info.tdport = tdport;
		err = val->getter(ctx, &gsc, priv);
		if (err)
			return err;
		switch (val->type) {
		case TEAMD_STATE_ITEM_TYPE_INT:
			val_json_obj = json_integer(gsc.data.int_val);
			break;
		case TEAMD_STATE_ITEM_TYPE_STRING:
			val_json_obj = json_string(gsc.data.str_val.ptr);
			if (gsc.data.str_val.free)
				free((void *) gsc.data.str_val.ptr);
			break;
		case TEAMD_STATE_ITEM_TYPE_BOOL:
			val_json_obj = json_boolean(gsc.data.bool_val);
		}
		if (!val_json_obj)
			return -ENOMEM;
		ret = json_object_set_new(vg_json_obj, val->subpath, val_json_obj);
		if (ret)
			return -EINVAL;
	}
	return 0;
}

static int teamd_state_val_groups_dump(struct teamd_context *ctx,
				       json_t *root_json_obj)
{
	struct teamd_state_vg_item *item;
	int err;

	list_for_each_node_entry(item, &ctx->state_vg_list, list) {
		if (item->vg->per_port) {
			struct teamd_port *tdport;

			teamd_for_each_tdport(tdport, ctx) {
				err = teamd_state_val_group_dump(ctx,
								 root_json_obj,
								 tdport,
								 item->subpath,
								 item->vg,
								 item->priv);
				if (err)
					return err;
			}
		} else {
			err = teamd_state_val_group_dump(ctx,
							 root_json_obj,
							 NULL,
							 item->subpath,
							 item->vg,
							 item->priv);
			if (err)
				return err;
		}
	}
	return 0;
}

struct state_ops_item {
	struct list_item list;
	const struct teamd_state_ops *ops;
	void *priv;
};

int teamd_state_init(struct teamd_context *ctx)
{
	list_init(&ctx->state_ops_list);
	list_init(&ctx->state_vg_list);
	return 0;
}

void teamd_state_fini(struct teamd_context *ctx)
{
}

static struct state_ops_item *__find_item(struct teamd_context *ctx,
					  const struct teamd_state_ops *ops,
					  void *priv)
{
	struct state_ops_item *item;

	list_for_each_node_entry(item, &ctx->state_ops_list, list) {
		if (item->ops == ops && item->priv == priv)
			return item;
	}
	return NULL;
}

static struct state_ops_item *__find_item_by_name(struct teamd_context *ctx,
						  const char *name)
{
	struct state_ops_item *item;

	list_for_each_node_entry(item, &ctx->state_ops_list, list) {
		if (item->ops->name == name)
			return item;
	}
	return NULL;
}

int teamd_state_ops_register(struct teamd_context *ctx,
			     const struct teamd_state_ops *ops,
			     void *priv)
{
	struct state_ops_item *item;

	if (__find_item_by_name(ctx, ops->name))
		return -EBUSY;
	item = malloc(sizeof(*item));
	if (!item)
		return -ENOMEM;
	item->ops = ops;
	item->priv = priv;
	list_add_tail(&ctx->state_ops_list, &item->list);
	return 0;
}

void teamd_state_ops_unregister(struct teamd_context *ctx,
				const struct teamd_state_ops *ops,
				void *priv)
{
	struct state_ops_item *item;

	item = __find_item(ctx, ops, priv);
	if (!item)
		return;
	list_del(&item->list);
	free(item);
}

int teamd_state_dump(struct teamd_context *ctx, char **p_state_dump)
{
	struct state_ops_item *item;
	json_t *state_json;
	json_t *substate_json;
	char *dump;
	int err;

	state_json = json_object();
	if (!state_json)
		return -ENOMEM;

	list_for_each_node_entry(item, &ctx->state_ops_list, list) {
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
	err = teamd_state_val_groups_dump(ctx, state_json);
	if (err)
		goto errout;
	dump = json_dumps(state_json, TEAMD_JSON_DUMPS_FLAGS);
	json_decref(state_json);
	if (!dump)
		return -ENOMEM;
	*p_state_dump = dump;
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
			 "dev_addr_len", team_get_ifinfo_hwaddr_len(ifinfo));
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

static const struct teamd_state_ops teamdev_state_ops = {
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

static int __fill_per_port(struct teamd_context *ctx, json_t *tdport_json,
			   struct teamd_port *tdport)
{
	struct state_ops_item *item;
	json_t *substate_json;
	int err;

	list_for_each_node_entry(item, &ctx->state_ops_list, list) {
		if (!item->ops->per_port_dump)
			continue;
		err = item->ops->per_port_dump(ctx, tdport, &substate_json,
					       item->priv);
		if (err)
			return err;
		err = json_object_set_new(tdport_json, item->ops->name,
					  substate_json);
		if (err)
			return -ENOMEM;
	}
	return 0;
}

static int ports_state_dump(struct teamd_context *ctx,
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
		err = __fill_per_port(ctx, tdport_json, tdport);
		if (err)
			goto errout;
	}

	*pstate_json = state_json;
	return 0;
errout:
	json_decref(state_json);
	return -ENOMEM;
}

static const struct teamd_state_ops ports_state_ops = {
	.dump = ports_state_dump,
	.name = "ports",
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

static const struct teamd_state_ops setup_state_ops = {
	.dump = setup_state_dump,
	.name = "setup",
};

int teamd_state_basics_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_state_ops_register(ctx, &teamdev_state_ops, ctx);
	if (err)
		return err;
	err = teamd_state_ops_register(ctx, &ports_state_ops, ctx);
	if (err)
		goto teamdev_state_unreg;
	err = teamd_state_ops_register(ctx, &setup_state_ops, ctx);
	if (err)
		goto ports_state_unreg;
	return 0;

ports_state_unreg:
	teamd_state_ops_unregister(ctx, &ports_state_ops, ctx);
teamdev_state_unreg:
	teamd_state_ops_unregister(ctx, &teamdev_state_ops, ctx);
	return err;
}

void teamd_state_basics_fini(struct teamd_context *ctx)
{
	teamd_state_ops_unregister(ctx, &setup_state_ops, ctx);
	teamd_state_ops_unregister(ctx, &ports_state_ops, ctx);
	teamd_state_ops_unregister(ctx, &teamdev_state_ops, ctx);
}
