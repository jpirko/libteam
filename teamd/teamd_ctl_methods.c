/*
 *   teamd_ctl_methods.c - Teamd control methods
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
#include <team.h>
#include <private/misc.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_state.h"
#include "teamd_ctl_methods.h"

static int teamd_ctl_method_port_config_update(struct teamd_context *ctx,
					       const struct teamd_ctl_method_ops *ops,
					       void *ops_priv)
{
	const char *port_devname;
	const char *port_config;
	uint32_t ifindex;
	int err;

	err = ops->get_args(ops_priv, "ss", &port_devname, &port_config);
	if (err)
		return ops->reply_err(ops_priv, "InvalidArgs", "Did not receive correct message arguments.");
	teamd_log_dbgx(ctx, 2, "port_devname \"%s\", port_config \"%s\"",
		       port_devname, port_config);

	ifindex = team_ifname2ifindex(ctx->th, port_devname);
	if (!ifindex) {
		teamd_log_err("Device \"%s\" does not exist.", port_devname);
		return ops->reply_err(ops_priv, "NoSuchDev", "No such device.");
	}
	err = teamd_config_port_update(ctx, port_devname, port_config);
	if (err) {
		teamd_log_err("Failed to update config for port \"%s\".",
			      port_devname);
		return ops->reply_err(ops_priv, "ConfigUpdateFail", "Failed to update config.");
	}
	return ops->reply_succ(ops_priv, NULL);
}

static int teamd_ctl_method_port_add(struct teamd_context *ctx,
				     const struct teamd_ctl_method_ops *ops,
				     void *ops_priv)
{
	const char *port_devname;
	int err;

	err = ops->get_args(ops_priv, "s", &port_devname);
	if (err)
		return ops->reply_err(ops_priv, "InvalidArgs", "Did not receive correct message arguments.");
	teamd_log_dbgx(ctx, 2, "port_devname \"%s\"", port_devname);

	err = teamd_port_add(ctx, port_devname);
	switch (err) {
	case -ENODEV:
		return ops->reply_err(ops_priv, "NoSuchDev", "No such device.");
	case 0:
		break;
	default:
		return ops->reply_err(ops_priv, "PortAddFail", "Failed to add port.");
	}
	return ops->reply_succ(ops_priv, NULL);
}

static int teamd_ctl_method_port_remove(struct teamd_context *ctx,
					const struct teamd_ctl_method_ops *ops,
					void *ops_priv)
{
	const char *port_devname;
	int err;

	err = ops->get_args(ops_priv, "s", &port_devname);
	if (err)
		return ops->reply_err(ops_priv, "InvalidArgs", "Did not receive correct message arguments.");
	teamd_log_dbgx(ctx, 2, "port_devname \"%s\"", port_devname);

	err = teamd_port_remove(ctx, port_devname);
	switch (err) {
	case -ENODEV:
		return ops->reply_err(ops_priv, "NoSuchDev", "No such device.");
	case 0:
		break;
	default:
		return ops->reply_err(ops_priv, "PortRemoveFail", "Failed to del port.");
	}
	return ops->reply_succ(ops_priv, NULL);
}

static int teamd_ctl_method_config_dump(struct teamd_context *ctx,
					const struct teamd_ctl_method_ops *ops,
					void *ops_priv)
{
	char *cfg;
	int err;

	err = teamd_config_dump(ctx, &cfg);
	if (err) {
		teamd_log_err("Failed to dump config.");
		return ops->reply_err(ops_priv, "ConfigDumpFail", "Failed to dump config.");
	}
	err = ops->reply_succ(ops_priv, cfg);
	free(cfg);
	return err;
}

static int teamd_ctl_method_config_dump_actual(struct teamd_context *ctx,
					       const struct teamd_ctl_method_ops *ops,
					       void *ops_priv)
{
	char *cfg;
	int err;

	err = teamd_config_actual_dump(ctx, &cfg);
	if (err) {
		teamd_log_err("Failed to dump actual config.");
		return ops->reply_err(ops_priv, "ConfigDumpActualFail", "Failed to dump actual config.");
	}
	err = ops->reply_succ(ops_priv, cfg);
	free(cfg);
	return err;
}

static int teamd_ctl_method_state_dump(struct teamd_context *ctx,
				       const struct teamd_ctl_method_ops *ops,
				       void *ops_priv)
{
	char *state;
	int err;

	err = teamd_state_dump(ctx, &state);
	if (err) {
		teamd_log_err("Failed to dump state.");
		return ops->reply_err(ops_priv, "StateDumpFail", "Failed to dump state.");
	}
	err = ops->reply_succ(ops_priv, state);
	free(state);
	return err;
}

typedef int (*teamd_ctl_method_func_t)(struct teamd_context *ctx,
				       const struct teamd_ctl_method_ops *ops,
				       void *ops_priv);
struct teamd_ctl_method {
	const char *name;
	teamd_ctl_method_func_t func;
};

static const struct teamd_ctl_method teamd_ctl_method_list[] = {
	{
		.name = "PortConfigUpdate",
		.func = teamd_ctl_method_port_config_update,

	},
	{
		.name = "PortAdd",
		.func = teamd_ctl_method_port_add,

	},
	{
		.name = "PortRemove",
		.func = teamd_ctl_method_port_remove,

	},
	{
		.name = "ConfigDump",
		.func = teamd_ctl_method_config_dump,

	},
	{
		.name = "ConfigDumpActual",
		.func = teamd_ctl_method_config_dump_actual,

	},
	{
		.name = "StateDump",
		.func = teamd_ctl_method_state_dump,

	},
};

#define TEAMD_CTL_METHOD_LIST_SIZE ARRAY_SIZE(teamd_ctl_method_list)

static teamd_ctl_method_func_t get_func_by_name(const char *method_name)
{
	int i;

	for (i = 0; i < TEAMD_CTL_METHOD_LIST_SIZE; i++) {
		const struct teamd_ctl_method *method;

		method = &teamd_ctl_method_list[i];
		if (!strcmp(method->name, method_name))
			return method->func;
	}
	return NULL;
}

bool teamd_ctl_method_exists(const char *method_name)
{
	return get_func_by_name(method_name);
}

int teamd_ctl_method_call(struct teamd_context *ctx, const char *method_name,
			  const struct teamd_ctl_method_ops *ops,
			  void *ops_priv)
{
	teamd_ctl_method_func_t func;

	func = get_func_by_name(method_name);
	if (!func) {
		teamd_log_err("Failed call non-existent method named \"%s\".",
			      method_name);
		return -EINVAL;
	}
	return func(ctx, ops, ops_priv);
}
