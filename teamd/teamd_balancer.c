/*
 *   teamd_balancer.h - Load balancer for teamd
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
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

struct tb_stats {
	uint64_t last_bytes;
	uint64_t curr_bytes;
	bool initialized;
};

struct tb_hash_info {
	uint8_t hash;
	struct tb_stats stats;
	struct teamd_port *tdport;
	struct {
		bool processed;
	} rebalance;
};

struct tb_port_info {
	struct list_item list;
	struct tb_stats stats;
	struct teamd_port *tdport;
	struct {
		uint64_t bytes;
		bool unusable;
	} rebalance;
};

#define HASH_COUNT 256

struct teamd_balancer {
	struct teamd_context *ctx;
	bool tx_balancing_enabled;
	uint32_t balancing_interval;
	struct tb_hash_info hash_info[HASH_COUNT];
	struct list_item port_info_list;
};

static struct tb_port_info *get_tb_port_info(struct teamd_balancer *tb,
					     struct teamd_port *tdport)
{
	struct tb_port_info *tbpi;

	list_for_each_node_entry(tbpi, &tb->port_info_list, list) {
		if (tbpi->tdport == tdport)
			return tbpi;
	}
	return NULL;
}

static uint64_t tb_stats_get_delta(struct tb_stats *stats)
{
	return stats->curr_bytes - stats->last_bytes;
}

static void tb_stats_update_last(struct tb_stats *stats)
{
	stats->last_bytes = stats->curr_bytes;
}

static void tb_stats_update(struct tb_stats *stats,
			    uint64_t bytes)
{
	stats->curr_bytes = bytes;
	if (!stats->initialized) {
		tb_stats_update_last(stats);
		stats->initialized = true;
	}
}

static void tb_stats_all_update_last(struct teamd_balancer *tb)
{
	struct tb_port_info *tbpi;
	int i;

	list_for_each_node_entry(tbpi, &tb->port_info_list, list)
		tb_stats_update_last(&tbpi->stats);
	for (i = 0; i < HASH_COUNT; i++)
		tb_stats_update_last(&tb->hash_info[i].stats);
}

static void tb_stats_update_hash(struct teamd_balancer *tb,
				 uint8_t hash, uint64_t bytes)
{
	tb_stats_update(&tb->hash_info[hash].stats, bytes);
}

static void tb_stats_update_port(struct teamd_balancer *tb,
				 struct teamd_port *tdport, uint64_t bytes)
{
	struct tb_port_info *tbpi;

	tbpi = get_tb_port_info(tb, tdport);
	if (tbpi)
		tb_stats_update(&tbpi->stats, bytes);
}

static void tb_hash_to_port_map_update(struct teamd_balancer *tb,
				       uint8_t hash, struct teamd_port *tdport)
{
	tb->hash_info[hash].tdport = tdport;
}

static struct tb_port_info *tb_get_least_loaded_port(struct teamd_balancer *tb)
{
	struct tb_port_info *tbpi;
	struct tb_port_info *best_tbpi = NULL;

	list_for_each_node_entry(tbpi, &tb->port_info_list, list) {
		if (tbpi->rebalance.unusable)
			continue;
		if (!best_tbpi ||
		    tbpi->rebalance.bytes < best_tbpi->rebalance.bytes)
			best_tbpi = tbpi;
	}
	return best_tbpi;
}

static struct tb_hash_info *tb_get_biggest_unprocessed_hash(struct teamd_balancer *tb)
{
	struct tb_hash_info *tbhi;
	struct tb_hash_info *best_tbhi = NULL;
	int i;

	for (i = 0; i < HASH_COUNT; i++) {
		tbhi = &tb->hash_info[i];
		if (tbhi->rebalance.processed)
			continue;
		if (!best_tbhi || tb_stats_get_delta(&tbhi->stats) >
				  tb_stats_get_delta(&best_tbhi->stats))
			best_tbhi = tbhi;
	}
	return best_tbhi;
}

static void tb_clear_rebalance_data(struct teamd_balancer *tb)
{
	struct tb_port_info *tbpi;
	int i;

	list_for_each_node_entry(tbpi, &tb->port_info_list, list) {
		tbpi->rebalance.bytes = 0;
		tbpi->rebalance.unusable = false;
	}
	for (i = 0; i < HASH_COUNT; i++) {
		tb->hash_info[i].rebalance.processed = false;
	}
}

static int tb_hash_to_port_remap(struct team_handle *th,
				 struct tb_hash_info *tbhi,
				 struct tb_port_info *tbpi)
{
	struct team_option *option;
	struct teamd_port *new_tdport = tbpi->tdport;
	uint8_t hash = tbhi->hash;
	int err;

	if (tbhi->tdport == new_tdport)
		return 0;

	option = team_get_option(th, "na", "lb_tx_hash_to_port_mapping", hash);
	if (!option)
		return -ENOENT;
	err = team_set_option_value_u32(th, option, new_tdport->ifindex);
	if (err)
		return err;
	teamd_log_dbg("Remapped hash \"%u\" (delta %" PRIu64 ") to port %s.",
		      hash, tb_stats_get_delta(&tbhi->stats),
		      new_tdport->ifname);
	return 0;
}

static int tb_rebalance(struct teamd_balancer *tb, struct team_handle *th)
{
	int err;
	struct tb_hash_info *tbhi;
	struct tb_port_info *tbpi;

	if (!tb->tx_balancing_enabled)
		return 0;

	tb_clear_rebalance_data(tb);

	while ((tbhi = tb_get_biggest_unprocessed_hash(tb)) &&
	       (tbpi = tb_get_least_loaded_port(tb))) {
		/* Do not remap zero delta hashes */
		if (tbhi->tdport && !tb_stats_get_delta(&tbhi->stats)) {
			tbhi->rebalance.processed = true;
			continue;
		}
		err = tb_hash_to_port_remap(th, tbhi, tbpi);
		if (err) {
			tbpi->rebalance.unusable = true;
			continue;
		}
		tbpi->rebalance.bytes += tb_stats_get_delta(&tbhi->stats);
		tbhi->rebalance.processed = true;
	}

	list_for_each_node_entry(tbpi, &tb->port_info_list, list) {
		if (tbpi->rebalance.unusable)
			continue;
		teamd_log_dbg("Port %s rebalanced, delta: %" PRIu64,
			      tbpi->tdport->ifname, tbpi->rebalance.bytes);
	}
	return 0;
}

struct lb_stats {
	uint64_t tx_bytes;
};

static int tb_option_change_handler_func(struct team_handle *th, void *priv,
					 team_change_type_mask_t type_mask)
{
	struct teamd_balancer *tb = priv;
	struct teamd_context *ctx = tb->ctx;
	struct team_option *option;
	bool rebalance_needed = false;

	team_for_each_option(option, ctx->th) {
		char *name = team_get_option_name(option);
		bool changed = team_is_option_changed(option);

		if (!strcmp(name, "lb_tx_hash_to_port_mapping")) {
			uint32_t array_index;
			uint32_t port_ifindex;
			struct teamd_port *tdport;

			if (team_get_option_type(option) != TEAM_OPTION_TYPE_U32) {
				teamd_log_err("Wrong type of option lb_tx_hash_to_port_mapping.");
				return -EINVAL;
			}
			array_index = team_get_option_array_index(option);
			if (array_index >= HASH_COUNT) {
				teamd_log_err("Wrong array index \"%u\" for option lb_tx_hash_to_port_mapping.",
					      array_index);
				return -EINVAL;
			}
			port_ifindex = team_get_option_value_u32(option);
			tdport = teamd_get_port(ctx, port_ifindex);
			tb_hash_to_port_map_update(tb, array_index, tdport);

		}
		if (!changed)
			continue;
		if (!strcmp(name, "lb_hash_stats") ||
		    !strcmp(name, "lb_port_stats") ||
		    !strcmp(name, "enabled"))
			rebalance_needed = true;
	}

	if (!rebalance_needed)
		return 0;

	tb_stats_all_update_last(tb);

	team_for_each_option(option, ctx->th) {
		char *name = team_get_option_name(option);
		bool changed = team_is_option_changed(option);
		struct lb_stats *lb_stats;

		if (!changed)
			continue;
		if (team_get_option_type(option) != TEAM_OPTION_TYPE_BINARY)
			continue;

		lb_stats = team_get_option_value_binary(option);
		if (!strcmp(name, "lb_hash_stats")) {
			uint32_t array_index;

			array_index = team_get_option_array_index(option);
			if (array_index >= HASH_COUNT) {
				teamd_log_err("Wrong array index \"%u\" for option lb_hash_stats.",
					      array_index);
				return -EINVAL;
			}
			teamd_log_dbg("stats update for hash \"%u\": \"%" PRIu64 "\".",
				      array_index, lb_stats->tx_bytes);
			tb_stats_update_hash(tb, array_index,
					     lb_stats->tx_bytes);
		}
		else if (!strcmp(name, "lb_port_stats")) {
			struct teamd_port *tdport;
			uint32_t port_ifindex;

			port_ifindex = team_get_option_port_ifindex(option);
			tdport = teamd_get_port(ctx, port_ifindex);
			if (!tdport) {
				teamd_log_err("Port with interface index \"%u\" is not part of this device.",
					      port_ifindex);
				return -EINVAL;
			}
			teamd_log_dbg("stats update for port %s: \"%" PRIu64 "\".",
				      tdport->ifname, lb_stats->tx_bytes);
			tb_stats_update_port(tb, tdport,
					     lb_stats->tx_bytes);
		}
	}

	return tb_rebalance(tb, th);
}

static bool tb_get_enable_tx_balancing(struct teamd_context *ctx)
{
	int err;
	char *tx_balancer_name;

	err = json_unpack(ctx->config_json, "{s:{s:{s:s}}}", "runner",
			  "tx_balancer", "name", &tx_balancer_name);
	if (err)
		return false; /* disabled by default */
	if (!strcmp(tx_balancer_name, "basic"))
		return true;
	return false;
}

static uint32_t tb_get_balancing_interval(struct teamd_context *ctx)
{
	int err;
	int balancing_interval;

	err = json_unpack(ctx->config_json, "{s:{s:i}}", "runner",
			  "balancing_interval", &balancing_interval);
	if (err || balancing_interval < 0)
		return 50; /* 5sec is default */
	return balancing_interval;
}

static int tb_set_lb_tx_method(struct team_handle *th,
			       struct teamd_balancer *tb)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "lb_tx_method");
	if (!option)
		return -ENOENT;
	return team_set_option_value_string(th, option,
					    tb->tx_balancing_enabled ?
					    "hash_to_port_mapping" : "hash");
}

static int tb_set_lb_stats_refresh_interval(struct team_handle *th,
					    struct teamd_balancer *tb)
{
	struct team_option *option;

	option = team_get_option(th, "n!", "lb_stats_refresh_interval");
	if (!option)
		return -ENOENT;
	return team_set_option_value_u32(th, option, tb->balancing_interval);
}

static const struct team_change_handler tb_option_change_handler = {
	.func = tb_option_change_handler_func,
	.type_mask = TEAM_OPTION_CHANGE,
};

int teamd_balancer_init(struct teamd_context *ctx, struct teamd_balancer **ptb)
{
	struct teamd_balancer *tb;
	int err;
	int i;

	tb = myzalloc(sizeof(*tb));
	if (!tb)
		return -ENOMEM;

	list_init(&tb->port_info_list);
	for (i = 0; i < HASH_COUNT; i++)
		tb->hash_info[i].hash = i;

	tb->tx_balancing_enabled = tb_get_enable_tx_balancing(ctx);
	tb->balancing_interval = tb_get_balancing_interval(ctx);

	err = tb_set_lb_tx_method(ctx->th, tb);
	if (err) {
		teamd_log_err("Failed to set lb_tx_method.");
		goto err_set_lb_tx_method;
	}

	teamd_log_info("TX balancing %s.", tb->tx_balancing_enabled ?
					   "enabled" : "disabled");
	if (tb->tx_balancing_enabled) {
		err = tb_set_lb_stats_refresh_interval(ctx->th, tb);
		if (err) {
			teamd_log_err("Failed to set lb_stats_refresh_interval.");
			goto err_set_lb_stats_refresh_interval;
		}
		teamd_log_info("Balancing interval %u.", tb->balancing_interval);
	}

	tb->ctx = ctx;
	err = team_change_handler_register(ctx->th,
					   &tb_option_change_handler, tb);
	if (err) {
		teamd_log_err("Failed to register tb option change handler.");
		goto err_change_handler_register;
	}
	*ptb = tb;
	return 0;

err_set_lb_tx_method:
err_set_lb_stats_refresh_interval:
err_change_handler_register:
	free(tb);
	return err;
}

void teamd_balancer_fini(struct teamd_balancer *tb)
{
	team_change_handler_unregister(tb->ctx->th,
				       &tb_option_change_handler, tb);
	free(tb);
}

int teamd_balancer_port_added(struct teamd_balancer *tb,
			      struct teamd_port *tdport)
{
	struct tb_port_info *tbpi;

	tbpi = get_tb_port_info(tb, tdport);
	if (tbpi)
		return -EEXIST;
	tbpi = myzalloc(sizeof(*tbpi));
	if (!tbpi)
		return -ENOMEM;
	tbpi->tdport = tdport;
	list_add(&tb->port_info_list, &tbpi->list);
	return 0;
}

void teamd_balancer_port_removed(struct teamd_balancer *tb,
				 struct teamd_port *tdport)
{
	struct tb_port_info *tbpi;

	tbpi = get_tb_port_info(tb, tdport);
	if (!tbpi)
		return;
	list_del(&tbpi->list);
	free(tbpi);
}
