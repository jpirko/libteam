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

int teamd_state_val_group_register_subpath(struct teamd_context *ctx,
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

int teamd_state_val_group_register(struct teamd_context *ctx,
				   const struct teamd_state_val_group *vg,
				   void *priv)
{
	if (!vg->subpath)
		return -EINVAL;
	return teamd_state_val_group_register_subpath(ctx, vg,
						      priv, vg->subpath);
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

int teamd_state_val_group_register_many(struct teamd_context *ctx,
					const struct teamd_state_val_group **vg,
					unsigned int vg_count, void *priv)
{
	int i;
	int err;

	for (i = 0; i < vg_count; i++) {
		err = teamd_state_val_group_register(ctx, vg[i], priv);
		if (err)
			goto rollback;
	}
	return 0;

rollback:
	while (--i >= 0)
		teamd_state_val_group_unregister(ctx, vg[i], priv);
	return err;
}

void teamd_state_val_group_unregister_many(struct teamd_context *ctx,
					   const struct teamd_state_val_group **vg,
					   unsigned int vg_count, void *priv)
{
	int i;

	for (i = 0; i < vg_count; i++)
		teamd_state_val_group_unregister(ctx, vg[i], priv);
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
	struct team_state_gsc gsc;
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

static struct team_ifinfo *__get_ifinfo(struct teamd_context *ctx,
					struct team_state_gsc *gsc)
{
	if (gsc->info.tdport)
		return gsc->info.tdport->team_ifinfo;
	else
		return team_get_ifinfo(ctx->th);
}

static int ifinfo_state_ifindex_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	gsc->data.int_val = team_get_ifinfo_ifindex(__get_ifinfo(ctx, gsc));
	return 0;
}

static int ifinfo_state_ifname_get(struct teamd_context *ctx,
				   struct team_state_gsc *gsc,
				   void *priv)
{
	gsc->data.str_val.ptr = team_get_ifinfo_ifname(__get_ifinfo(ctx, gsc));
	return 0;
}

static int ifinfo_state_dev_addr_len_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv)
{
	gsc->data.int_val = team_get_ifinfo_hwaddr_len(__get_ifinfo(ctx, gsc));
	return 0;
}


static int ifinfo_state_dev_addr_get(struct teamd_context *ctx,
				     struct team_state_gsc *gsc,
				     void *priv)
{
	struct team_ifinfo *ifinfo = __get_ifinfo(ctx, gsc);
	char *addr_str;

	addr_str = a_hwaddr_str(team_get_ifinfo_hwaddr(ifinfo),
				team_get_ifinfo_hwaddr_len(ifinfo));
	if (!addr_str)
		return -ENOMEM;
	gsc->data.str_val.ptr = addr_str;
	gsc->data.str_val.free = true;
	return 0;
}

static const struct teamd_state_val ifinfo_state_vals[] = {
	{
		.subpath = "ifindex",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ifinfo_state_ifindex_get,
	},
	{
		.subpath = "ifname",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ifinfo_state_ifname_get,
	},
	{
		.subpath = "dev_addr",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = ifinfo_state_dev_addr_get,
	},
	{
		.subpath = "dev_addr_len",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = ifinfo_state_dev_addr_len_get,
	},
};

static const struct teamd_state_val_group teamdev_ifinfo_state_vg = {
	.subpath = "team_device.ifinfo",
	.vals = ifinfo_state_vals,
	.vals_count = ARRAY_SIZE(ifinfo_state_vals),
};

static const struct teamd_state_val_group ports_ifinfo_state_vg = {
	.subpath = "ifinfo",
	.vals = ifinfo_state_vals,
	.vals_count = ARRAY_SIZE(ifinfo_state_vals),
	.per_port = true,
};

static int port_link_state_up_get(struct teamd_context *ctx,
				  struct team_state_gsc *gsc,
				  void *priv)
{
	gsc->data.bool_val = team_is_port_link_up(gsc->info.tdport->team_port);
	return 0;
}

static int port_link_state_speed_get(struct teamd_context *ctx,
				     struct team_state_gsc *gsc,
				     void *priv)
{
	gsc->data.int_val = team_get_port_speed(gsc->info.tdport->team_port);
	return 0;
}

static int port_link_state_duplex_get(struct teamd_context *ctx,
				      struct team_state_gsc *gsc,
				      void *priv)
{
	gsc->data.str_val.ptr =
		team_get_port_duplex(gsc->info.tdport->team_port) ? "full" : "half";
	return 0;
}


static const struct teamd_state_val port_link_state_vals[] = {
	{
		.subpath = "up",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = port_link_state_up_get,
	},
	{
		.subpath = "speed",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = port_link_state_speed_get,
	},
	{
		.subpath = "duplex",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = port_link_state_duplex_get,
	},
};

static const struct teamd_state_val_group ports_link_state_vg = {
	.subpath = "link",
	.vals = port_link_state_vals,
	.vals_count = ARRAY_SIZE(port_link_state_vals),
	.per_port = true,
};

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
		tdport_json = json_object();
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

static int setup_state_runner_name_get(struct teamd_context *ctx,
				       struct team_state_gsc *gsc,
				       void *priv)
{
	gsc->data.str_val.ptr = ctx->runner->name;
	return 0;
}

static int setup_state_kernel_team_mode_name_get(struct teamd_context *ctx,
						 struct team_state_gsc *gsc,
						 void *priv)
{
	gsc->data.str_val.ptr = ctx->runner->team_mode_name;
	return 0;
}

static int setup_state_dbus_enabled_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void *priv)
{
#ifdef ENABLED_DBUS
	gsc->data.bool_val = ctx->dbus.enabled;
#else
	gsc->data.bool_val = false;
#endif
	return 0;
}

static int setup_state_debug_level_get(struct teamd_context *ctx,
				       struct team_state_gsc *gsc,
				       void *priv)
{
	gsc->data.int_val = ctx->debug;
	return 0;
}

static int setup_state_daemonized_get(struct teamd_context *ctx,
				      struct team_state_gsc *gsc,
				      void *priv)
{
	gsc->data.bool_val = ctx->daemonize;
	return 0;
}

static int setup_state_pid_get(struct teamd_context *ctx,
			       struct team_state_gsc *gsc,
			       void *priv)
{
	gsc->data.int_val = getpid();
	return 0;
}

static int setup_state_pid_file_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	gsc->data.str_val.ptr = ctx->pid_file ? ctx->pid_file : "";
	return 0;
}

static const struct teamd_state_val setup_state_vals[] = {
	{
		.subpath = "runner_name",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = setup_state_runner_name_get,
	},
	{
		.subpath = "kernel_team_mode_name",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = setup_state_kernel_team_mode_name_get,
	},
	{
		.subpath = "dbus_enabled",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = setup_state_dbus_enabled_get,
	},
	{
		.subpath = "debug_level",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = setup_state_debug_level_get,
	},
	{
		.subpath = "daemonized",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = setup_state_daemonized_get,
	},
	{
		.subpath = "pid",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = setup_state_pid_get,
	},
	{
		.subpath = "pid_file",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = setup_state_pid_file_get,
	},
};

static const struct teamd_state_val_group setup_state_vg = {
	.subpath = "setup",
	.vals = setup_state_vals,
	.vals_count = ARRAY_SIZE(setup_state_vals),
};

static const struct teamd_state_val_group *state_vgs[] = {
	&ports_ifinfo_state_vg,
	&ports_link_state_vg,
	&setup_state_vg,
};

int teamd_state_basics_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_state_val_group_register(ctx, &teamdev_ifinfo_state_vg, ctx);
	if (err)
		return err;

	err = teamd_state_ops_register(ctx, &ports_state_ops, ctx);
	if (err)
		goto teamdev_ifinfo_state_unreg;

	err = teamd_state_val_group_register_many(ctx, state_vgs,
						  ARRAY_SIZE(state_vgs), ctx);
	if (err)
		goto ports_state_unreg;

	return 0;

ports_state_unreg:
	teamd_state_ops_unregister(ctx, &ports_state_ops, ctx);
teamdev_ifinfo_state_unreg:
	teamd_state_val_group_unregister(ctx, &teamdev_ifinfo_state_vg, ctx);
	return err;
}

void teamd_state_basics_fini(struct teamd_context *ctx)
{
	teamd_state_val_group_unregister_many(ctx, state_vgs,
					      ARRAY_SIZE(state_vgs), ctx);
	teamd_state_ops_unregister(ctx, &ports_state_ops, ctx);
	teamd_state_val_group_unregister(ctx, &teamdev_ifinfo_state_vg, ctx);
}
