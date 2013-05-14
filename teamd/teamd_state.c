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
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <jansson.h>
#include <team.h>
#include <private/misc.h>

#include "teamd.h"
#include "teamd_state.h"
#include "teamd_json.h"

struct teamd_state_val_item {
	struct list_item list;
	char *subpath;
	const struct teamd_state_val *val;
	void *priv;
	const struct teamd_state_val *parent_val;
	bool per_port;
	struct teamd_port *tdport;
};

static struct teamd_state_val_item *
__find_val_item(struct teamd_context *ctx,
		const struct teamd_state_val *val,
		void *priv, const struct teamd_state_val *parent_val)
{
	struct teamd_state_val_item *item;

	list_for_each_node_entry(item, &ctx->state_val_list, list) {
		if (item->val == val && item->parent_val == parent_val &&
		    item->priv == priv)
			return item;
	}
	return NULL;
}

void __unreg_val(struct teamd_context *ctx, const struct teamd_state_val *val,
		 void *priv, const struct teamd_state_val *parent_val)
{
	struct teamd_state_val_item *item;

	if (val->type == TEAMD_STATE_ITEM_TYPE_NODE) {
		int i;

		TEAMD_BUG_ON(!val->vals); /* consistency check */
		for (i = 0; i < val->vals_count; i++)
			__unreg_val(ctx, &val->vals[i], priv, val);
	} else {
		item = __find_val_item(ctx, val, priv, parent_val);
		if (!item)
			return;
		list_del(&item->list);
		free(item->subpath);
		free(item);
	}
}

int __reg_val(struct teamd_context *ctx, const struct teamd_state_val *val,
	      void *priv, const char *parent_subpath, const char *val_subpath,
	      bool per_port, struct teamd_port *tdport,
	      const struct teamd_state_val *parent_val)
{
	char *subpath;
	int ret;
	int err;

	if (val->type == TEAMD_STATE_ITEM_TYPE_NODE && !val_subpath) {
		subpath = strdup(parent_subpath);
		if (!subpath)
			return -ENOMEM;
	} else {
		ret = asprintf(&subpath, "%s.%s", parent_subpath, val_subpath);
		if (ret == -1)
			return -ENOMEM;
	}
	if (val->per_port)
		per_port = true;
	if (per_port && tdport)
		return -EINVAL;

	if (val->type == TEAMD_STATE_ITEM_TYPE_NODE) {
		int i;

		TEAMD_BUG_ON(!val->vals); /* consistency check */
		for (i = 0; i < val->vals_count; i++) {
			const struct teamd_state_val *child_val = &val->vals[i];

			err = __reg_val(ctx, child_val, priv, subpath,
					child_val->subpath, per_port,
					tdport, val);
			if (err)
				break;
		}
		/* rollback in case for did not finish */
		if (i != val->vals_count)
			while (--i >= 0)
				__unreg_val(ctx, &val->vals[i], priv, val);
		free(subpath);
	} else {
		struct teamd_state_val_item *item;

		if (__find_val_item(ctx, val, priv, parent_val)) {
			err = -EEXIST;
			goto errout;
		}
		item = malloc(sizeof(*item));
		if (!item) {
			err = -ENOMEM;
			goto errout;
		}
		item->subpath = subpath;
		item->val = val;
		item->parent_val = parent_val;
		item->priv = priv;
		item->per_port = per_port;
		item->tdport = tdport;
		list_add_tail(&ctx->state_val_list, &item->list);
	}
	return 0;
errout:
	free(subpath);
	return err;
}

int teamd_state_val_register_ex(struct teamd_context *ctx,
				const struct teamd_state_val *val,
				void *priv, struct teamd_port *tdport,
				const char *fmt, ...)
{
	va_list ap;
	char *val_subpath;
	int ret;
	int err;

	va_start(ap, fmt);
	ret = vasprintf(&val_subpath, fmt, ap);
	va_end(ap);
	if (ret == -1)
		return -ENOMEM;

	err = __reg_val(ctx, val, priv, "", val_subpath, false, tdport, NULL);
	free(val_subpath);
	return err;
}

int teamd_state_val_register(struct teamd_context *ctx,
			     const struct teamd_state_val *val,
			     void *priv)
{
	return __reg_val(ctx, val, priv, "", val->subpath, false, NULL, NULL);
}

void teamd_state_val_unregister(struct teamd_context *ctx,
				const struct teamd_state_val *val,
				void *priv)
{
	__unreg_val(ctx, val, priv, NULL);
}

#define TEAMD_STATE_PER_PORT_PREFIX "ports."

static int teamd_state_build_val_json_subpath(json_t **p_vg_json_obj,
					      json_t *root_json_obj,
					      struct teamd_port *tdport,
					      const char *subpath)
{
	char *path;
	int ret;
	int err;
	char *dot;

	if (tdport)
		ret = asprintf(&path, "$." TEAMD_STATE_PER_PORT_PREFIX "%s%s",
			       tdport->ifname, subpath);
	else
		ret = asprintf(&path, "$%s", subpath);
	if (ret == -1)
		return -ENOMEM;
	dot = strrchr(path, '.');
	TEAMD_BUG_ON(!dot);
	*dot = '\0';
	err = teamd_json_path_lite_build(p_vg_json_obj, root_json_obj, path);
	free(path);
	return err;
}

static int teamd_state_val_dump(struct teamd_context *ctx,
				json_t *root_json_obj,
				struct teamd_port *tdport,
				struct teamd_state_val_item *item)
{
	const struct teamd_state_val *val = item->val;
	char *subpath = item->subpath;
	void *priv = item->priv;
	char *subpath_end;
	struct team_state_gsc gsc;
	json_t *val_json_obj = val_json_obj;
	json_t *vg_json_obj = vg_json_obj;
	int err;
	int ret;

	subpath_end = strrchr(subpath, '.');
	subpath_end++;
	TEAMD_BUG_ON(!subpath_end);
	err = teamd_state_build_val_json_subpath(&vg_json_obj, root_json_obj,
						 tdport, subpath);
	if (err)
		return err;

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
		break;
	case TEAMD_STATE_ITEM_TYPE_NODE:
		TEAMD_BUG();
	}
	if (!val_json_obj)
		return -ENOMEM;
	ret = json_object_set_new(vg_json_obj, subpath_end, val_json_obj);
	if (ret)
		return -EINVAL;
	return 0;
}

static int teamd_state_vals_dump(struct teamd_context *ctx,
				 json_t *root_json_obj)
{
	struct teamd_state_val_item *item;
	int err;

	list_for_each_node_entry(item, &ctx->state_val_list, list) {
		if (item->per_port) {
			struct teamd_port *tdport;

			teamd_for_each_tdport(tdport, ctx) {
				err = teamd_state_val_dump(ctx, root_json_obj,
							   tdport, item);
				if (err)
					return err;
			}
		} else {
			err = teamd_state_val_dump(ctx, root_json_obj,
						   item->tdport, item);
			if (err)
				return err;
		}
	}
	return 0;
}

static int __find_by_item_path(struct teamd_state_val_item **p_item,
			       struct teamd_port **p_tdport,
			       struct teamd_context *ctx, const char *item_path)
{
	struct teamd_state_val_item *item;
	char *subpath;
	struct teamd_port *tdport = NULL;

	if (!strncmp(item_path, TEAMD_STATE_PER_PORT_PREFIX,
		     strlen(TEAMD_STATE_PER_PORT_PREFIX))) {
		struct teamd_port *cur_tdport;
		char *ifname_start = strchr(item_path, '.') + 1;
		char *ifname_end = strchr(ifname_start, '.');
		size_t ifname_len = ifname_end - ifname_start;

		if (!ifname_end)
			return -EINVAL;
		subpath = ifname_end + 1;

		teamd_for_each_tdport(cur_tdport, ctx) {
			if (!strncmp(cur_tdport->ifname, ifname_start,
				     ifname_len)) {
				tdport = cur_tdport;
				break;
			}
		}
		if (!tdport)
			return -ENOENT;
	} else {
		subpath = (char *) item_path;
	}

	list_for_each_node_entry(item, &ctx->state_val_list, list) {
		/* item->subpath[0] == '.' */
		if (!strcmp(item->subpath + 1, subpath) &&
		    (!item->tdport || item->tdport == tdport)) {
			*p_item = item;
			*p_tdport = tdport;
			return 0;
		}
	}
	return -ENOENT;
}

int teamd_state_item_value_get(struct teamd_context *ctx, const char *item_path,
			       char **p_value)
{
	struct teamd_state_val_item *item;
	const struct teamd_state_val *val;
	void *priv;
	struct team_state_gsc gsc;
	int err;
	int ret = ret;

	memset(&gsc, 0, sizeof(gsc));
	err = __find_by_item_path(&item, &gsc.info.tdport, ctx, item_path);
	if (err)
		return err;

	val = item->val;
	priv = item->priv;
	err = val->getter(ctx, &gsc, priv);
	if (err)
		return err;
	switch (val->type) {
	case TEAMD_STATE_ITEM_TYPE_INT:
		ret = asprintf(p_value, "%d", gsc.data.int_val);
		break;
	case TEAMD_STATE_ITEM_TYPE_STRING:
		ret = asprintf(p_value, "%s", gsc.data.str_val.ptr);
		if (gsc.data.str_val.free)
			free((void *) gsc.data.str_val.ptr);
		break;
	case TEAMD_STATE_ITEM_TYPE_BOOL:
		ret = asprintf(p_value, "%s",
			       gsc.data.bool_val ? "true" : "false");
		break;
	case TEAMD_STATE_ITEM_TYPE_NODE:
		TEAMD_BUG();
	}
	if (ret == -1)
		return -ENOMEM;
	return 0;
}

int __set_int_val(struct team_state_gsc *gsc, const char *value)
{
	long val;
	char *endptr;

	errno = 0;
	val = strtol(value, &endptr, 10);
	if (errno)
		return -errno;
	if (strlen(endptr) != 0)
		return -EINVAL;
	if (val < INT_MIN || val > INT_MAX)
		return -ERANGE;
	gsc->data.int_val = val;
	return 0;
}

int __set_bool_val(struct team_state_gsc *gsc, const char *value)
{
	if (!strcasecmp("true", value))
		gsc->data.bool_val = true;
	else if (!strcasecmp("false", value))
		gsc->data.bool_val = false;
	else
		return -EINVAL;
	return 0;
}

int teamd_state_item_value_set(struct teamd_context *ctx, const char *item_path,
			       const char *value)
{
	struct teamd_state_val_item *item;
	const struct teamd_state_val *val;
	void *priv;
	struct team_state_gsc gsc;
	int err;

	err = __find_by_item_path(&item, &gsc.info.tdport, ctx, item_path);
	if (err)
		return err;

	val = item->val;
	priv = item->priv;
	if (!val->setter)
		return -EOPNOTSUPP;
	switch (val->type) {
	case TEAMD_STATE_ITEM_TYPE_INT:
		err = __set_int_val(&gsc, value);
		if (err)
			return err;
		break;
	case TEAMD_STATE_ITEM_TYPE_STRING:
		gsc.data.str_val.ptr = value;
		break;
	case TEAMD_STATE_ITEM_TYPE_BOOL:
		err = __set_bool_val(&gsc, value);
		if (err)
			return err;
		break;
	case TEAMD_STATE_ITEM_TYPE_NODE:
		TEAMD_BUG();
	}
	return val->setter(ctx, &gsc, priv);
}

int teamd_state_init(struct teamd_context *ctx)
{
	list_init(&ctx->state_val_list);
	return 0;
}

void teamd_state_fini(struct teamd_context *ctx)
{
}

int teamd_state_dump(struct teamd_context *ctx, char **p_state_dump)
{
	json_t *state_json;
	char *dump;
	int err;

	state_json = json_object();
	if (!state_json)
		return -ENOMEM;

	err = teamd_state_vals_dump(ctx, state_json);
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

static const struct teamd_state_val state_vgs[] = {
	{
		.subpath = "team_device.ifinfo",
		.vals = ifinfo_state_vals,
		.vals_count = ARRAY_SIZE(ifinfo_state_vals),
	},
	{
		.subpath = "ifinfo",
		.vals = ifinfo_state_vals,
		.vals_count = ARRAY_SIZE(ifinfo_state_vals),
		.per_port = true,
	},
	{
		.subpath = "link",
		.vals = port_link_state_vals,
		.vals_count = ARRAY_SIZE(port_link_state_vals),
		.per_port = true,
	},
	{
		.subpath = "setup",
		.vals = setup_state_vals,
		.vals_count = ARRAY_SIZE(setup_state_vals),
	},
};

static const struct teamd_state_val root_state_vg = {
	.vals = state_vgs,
	.vals_count = ARRAY_SIZE(state_vgs),
};

int teamd_state_basics_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_state_val_register(ctx, &root_state_vg, ctx);
	if (err)
		return err;
	return 0;
}

void teamd_state_basics_fini(struct teamd_context *ctx)
{
	teamd_state_val_unregister(ctx, &root_state_vg, ctx);
}
