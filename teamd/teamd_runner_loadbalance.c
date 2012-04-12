/*
 *   teamd_runner_loadbalance.c - Load-balancing runners
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

#include <sys/socket.h>
#include <linux/netdevice.h>
#include <jansson.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

static int lb_init(struct teamd_context *ctx)
{
	json_t *tx_hash_obj;
	struct sock_fprog fprog;
	int err;

	err = json_unpack(ctx->config_json, "{s:o}", "tx_hash",
			  &tx_hash_obj);
	if (err) {
		teamd_log_warn("No Tx hash recipe found in config.");
		return 0;
	}
	err = teamd_hash_func_init(&fprog, tx_hash_obj);
	if (err) {
		teamd_log_err("Failed to init hash function.");
		return err;
	}
	err = team_set_bpf_hash_func(ctx->th, &fprog);
	if (err)
		teamd_log_err("Failed to set hash function.");
	teamd_hash_func_fini(&fprog);
	return err;
}

static int lb_port_added(struct teamd_context *ctx, struct teamd_port *tdport)
{
	char tmp_hwaddr[MAX_ADDR_LEN];
	int err;

	err = team_hwaddr_get(ctx->th, ctx->ifindex, tmp_hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to get team device hardware address.");
		return err;
	}

	err = team_hwaddr_set(ctx->th, tdport->ifindex, tmp_hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("Failed to set port \"%s\" hardware address. ",
			      tdport->ifname);
		return err;
	}
	return 0;
}

const struct teamd_runner teamd_runner_loadbalance = {
	.name		= "loadbalance",
	.team_mode_name	= "loadbalance",
	.init		= lb_init,
	.port_added	= lb_port_added,
};
