/*
 *   teamd_runner_lacp.c - Teamd 802.3ad LACP runner implementation
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
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
#include <netinet/in.h>
#include <errno.h>
#include <team.h>
#include <private/misc.h>

#include "teamd.h"

/*
 * Packet format for LACPDU described in
 * IEEE Std 802.3ad-2000 (43.4.2.2)
 */

#define INFO_STATE_LACP_ACTIVITY	0x01
#define INFO_STATE_LACP_TIMEOUT		0x02
#define INFO_STATE_AGGREGATION		0x04
#define INFO_STATE_SYNCHRONIZATION	0x08
#define INFO_STATE_COLLECTING		0x10
#define INFO_STATE_DISTRIBUTING		0x20
#define INFO_STATE_DEFAULTED		0x40
#define INFO_STATE_EXPIRED		0x80

struct lacpdu_info {
	uint16_t		system_priority;
	uint8_t			system[ETH_ALEN]; /* ID */
	uint16_t		key;
	uint16_t		port_priority;
	uint16_t		port; /* ID */
	uint8_t			state;
} __attribute__((__packed__));

struct lacpdu {
	uint8_t			subtype;
	uint8_t			version_number;
	uint8_t			actor_tlv_type;
	uint8_t			actor_info_len;
	struct lacpdu_info	actor;
	uint8_t			__reserved1[3];
	uint8_t			partner_tlv_type;
	uint8_t			partner_info_len;
	struct lacpdu_info	partner;
	uint8_t			__reserved2[3];
	uint8_t			collector_tlv_type;
	uint8_t			collector_info_len;
	uint16_t		collector_max_delay;
	uint8_t			__reserved3[12];
	uint8_t			terminator_tlv_type;
	uint8_t			terminator_info_len;
	uint8_t			__reserved4[50];
} __attribute__((__packed__));

static void lacpdu_init(struct lacpdu *lacpdu)
{
	memset(lacpdu, 0, sizeof(*lacpdu));
	lacpdu->subtype			= 0x01;
	lacpdu->version_number		= 0x01;
	lacpdu->actor_tlv_type		= 0x01;
	lacpdu->actor_info_len		= 0x14;
	lacpdu->partner_tlv_type	= 0x02;
	lacpdu->partner_info_len	= 0x14;
	lacpdu->collector_tlv_type	= 0x03;
	lacpdu->collector_info_len	= 0x10;
}

static bool lacpdu_check(struct lacpdu *lacpdu)
{
	/*
	 * According to 43.4.12 version_number, tlv_type and reserved fields
	 * should not be checked.
	 */

	if (lacpdu->subtype		!= 0x01 ||
	    lacpdu->actor_info_len	!= 0x14 ||
	    lacpdu->partner_info_len	!= 0x14 ||
	    lacpdu->collector_info_len	!= 0x10 ||
	    lacpdu->terminator_info_len	!= 0x00)
		return false;
	return true;
}

enum lacp_agg_select_policy {
	LACP_AGG_SELECT_LACP_PRIO = 0,
	LACP_AGG_SELECT_LACP_PRIO_STABLE = 1,
	LACP_AGG_SELECT_BANDWIDTH = 2,
	LACP_AGG_SELECT_COUNT = 3,
};

static const char *lacp_agg_select_policy_names_list[] = {
	"lacp_prio", "lacp_prio_stable", "bandwidth", "count",
};

#define LACP_AGG_SELECT_POLICY_NAMES_LIST_SIZE \
	ARRAY_SIZE(lacp_agg_select_policy_names_list)

struct lacp {
	struct teamd_context *ctx;
	uint32_t selected_aggregator_id;
	bool carrier_up;
	struct {
		bool active;
#define		LACP_CFG_DFLT_ACTIVE true
		uint16_t sys_prio;
#define		LACP_CFG_DFLT_SYS_PRIO 0xffff
		bool fast_rate;
#define		LACP_CFG_DFLT_FAST_RATE false
		int min_ports;
#define		LACP_CFG_DFLT_MIN_PORTS 1
		enum lacp_agg_select_policy agg_select_policy;
#define		LACP_CFG_DFLT_AGG_SELECT_POLICY LACP_AGG_SELECT_LACP_PRIO
	} cfg;
	struct teamd_balancer *tb;
};

enum lacp_port_state {
	PORT_STATE_DISABLED = 0,
	PORT_STATE_CURRENT = 1,
	PORT_STATE_EXPIRED = 2,
	PORT_STATE_DEFAULTED = 3,
};

static const char *lacp_port_state_name[] = {
	"disabled",
	"current",
	"expired",
	"defaulted",
};

struct lacp_port {
	struct teamd_context *ctx;
	struct teamd_port *tdport;
	struct lacp *lacp;
	int sock;
	struct lacpdu_info actor;
	struct lacpdu_info partner;
	struct lacpdu_info __partner_last; /* last state before update */
	bool selected;
	bool periodic_on;
	uint32_t aggregator_id;
	enum lacp_port_state state;
	struct {
		uint32_t speed;
		uint8_t	duplex;
		bool up;
	} __link_last;
	struct {
		uint16_t prio;
#define		LACP_PORT_CFG_DFLT_PRIO 0xff
		uint16_t key;
#define		LACP_PORT_CFG_DFLT_KEY 0
	} cfg;
};

static struct lacp_port *lacp_port_get(struct lacp *lacp,
				       struct teamd_port *tdport)
{
	/*
	 * When calling this after teamd_event_watch_register() which is in
	 * lacp_init() it is ensured that this will always return valid priv
	 * pointer for an existing port.
	 */
	return teamd_get_first_port_priv_by_creator(tdport, lacp);
}

static const char *lacp_get_agg_select_policy_name(struct lacp *lacp)
{
	return lacp_agg_select_policy_names_list[lacp->cfg.agg_select_policy];
}

static int lacp_assign_agg_select_policy(struct lacp *lacp,
					 char *agg_select_policy_name)
{
	int i = LACP_CFG_DFLT_AGG_SELECT_POLICY;

	if (!agg_select_policy_name)
		goto found;
	for (i = 0; i < LACP_AGG_SELECT_POLICY_NAMES_LIST_SIZE; i++)
		if (!strcmp(lacp_agg_select_policy_names_list[i],
		    agg_select_policy_name))
			goto found;
	return -ENOENT;
found:
	lacp->cfg.agg_select_policy = i;
	return 0;
}

static int lacp_load_config(struct teamd_context *ctx, struct lacp *lacp)
{
	int err;
	int tmp;
	char *agg_select_policy_name;

	err = json_unpack(ctx->config_json, "{s:{s:b}}", "runner", "active",
			  &tmp);
	lacp->cfg.active = err ? LACP_CFG_DFLT_ACTIVE : !!tmp;
	teamd_log_dbg("Using active \"%d\".", lacp->cfg.active);

	err = json_unpack(ctx->config_json, "{s:{s:i}}", "runner", "sys_prio",
			  &tmp);
	if (err) {
		lacp->cfg.sys_prio = LACP_CFG_DFLT_SYS_PRIO;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("\"sys_prio\" value is out of its limits.");
		return -EINVAL;
	} else {
		lacp->cfg.sys_prio = tmp;
	}
	teamd_log_dbg("Using sys_prio \"%d\".", lacp->cfg.sys_prio);

	err = json_unpack(ctx->config_json, "{s:{s:b}}", "runner", "fast_rate",
			  &tmp);
	lacp->cfg.fast_rate = err ? LACP_CFG_DFLT_FAST_RATE : !!tmp;
	teamd_log_dbg("Using fast_rate \"%d\".", lacp->cfg.fast_rate);

	err = json_unpack(ctx->config_json, "{s:{s:i}}", "runner", "min_ports",
			  &tmp);
	if (err) {
		lacp->cfg.min_ports = LACP_CFG_DFLT_MIN_PORTS;
	} else if (tmp < 1 || tmp > UCHAR_MAX) {
		teamd_log_err("\"min_ports\" value is out of its limits.");
		return -EINVAL;
	} else {
		lacp->cfg.min_ports = tmp;
	}
	teamd_log_dbg("Using min_ports \"%d\".", lacp->cfg.min_ports);

	err = json_unpack(ctx->config_json, "{s:{s:s}}", "runner",
			  "agg_select_policy", &agg_select_policy_name);
	if (err)
		agg_select_policy_name = NULL;
	err = lacp_assign_agg_select_policy(lacp, agg_select_policy_name);
	if (err) {
		teamd_log_err("Unknown \"agg_select_policy\" named \"%s\" passed.",
			      agg_select_policy_name);
		return err;
	}
	teamd_log_dbg("Using agg_select_policy \"%s\".",
		      lacp_get_agg_select_policy_name(lacp));
	return 0;
}

static bool lacp_port_selectable(struct lacp_port *lacp_port)
{
	if (lacp_port->selected)
		return false;
	if (!memcmp(lacp_port->actor.system,
		    lacp_port->partner.system, ETH_ALEN)) {
		teamd_log_warn("%s: Port seems to be loopbacked to the same "
			       "team device.", lacp_port->tdport->ifname);
		return false;
	}
	if (lacp_port->state == PORT_STATE_CURRENT ||
	    lacp_port->state == PORT_STATE_EXPIRED)
		return true;
	return false;
}

static int lacp_port_should_be_enabled(struct lacp_port *lacp_port)
{
	struct lacp *lacp = lacp_port->lacp;

	if (lacp_port->selected &&
	    lacp_port->partner.state & INFO_STATE_SYNCHRONIZATION &&
	    lacp_port->aggregator_id == lacp->selected_aggregator_id)
		return true;
	return false;
}

static int lacp_port_should_be_disabled(struct lacp_port *lacp_port)
{
	struct lacp *lacp = lacp_port->lacp;

	if (!lacp_port->selected ||
	    lacp_port->aggregator_id != lacp->selected_aggregator_id)
		return true;
	return false;
}

static int lacp_port_update_enabled(struct lacp_port *lacp_port)
{
	struct teamd_port *tdport = lacp_port->tdport;
	struct teamd_context *ctx = lacp_port->ctx;
	bool new_enabled_state;
	bool curr_enabled_state;
	int err;

	if (!teamd_port_present(ctx, tdport))
		return 0;
	err = teamd_port_enabled(ctx, tdport, &curr_enabled_state);
	if (err)
		return err;

	if (!curr_enabled_state && lacp_port_should_be_enabled(lacp_port))
		new_enabled_state = true;
	else if (curr_enabled_state && lacp_port_should_be_disabled(lacp_port))
		new_enabled_state = false;
	else
		return 0;

	teamd_log_dbg("%s: %s port, aggregator id %d", tdport->ifname,
		      new_enabled_state ? "Enabling": "Disabling",
		      lacp_port->aggregator_id);
	err = team_set_port_enabled(ctx->th, tdport->ifindex,
				    new_enabled_state);
	if (err) {
		teamd_log_err("%s: Failed to %s port.", tdport->ifname,
			      new_enabled_state ? "enable": "disable");
		return err;;
	}
	return 0;
}

static bool lacp_ports_aggregable(struct lacp_port *lacp_port1,
				  struct lacp_port *lacp_port2)
{
	if (lacp_port1->partner.key != lacp_port2->partner.key ||
	    lacp_port1->actor.key != lacp_port2->actor.key)
		return false;
	if (memcmp(lacp_port1->partner.system,
		   lacp_port2->partner.system, ETH_ALEN))
		return false;
	return true;
}

static void get_lacp_port_prio_info(struct lacp_port *lacp_port,
				    struct lacpdu_info *prio_info)
{
	int prio_diff;
	int system_diff;

	prio_diff = ntohs(lacp_port->actor.system_priority) -
		    ntohs(lacp_port->partner.system_priority);
	system_diff = memcmp(lacp_port->actor.system,
			     lacp_port->partner.system, ETH_ALEN);
	if (prio_diff < 0 || (prio_diff == 0 && system_diff < 0))
		*prio_info = lacp_port->actor;
	if (prio_diff > 0 || (prio_diff == 0 && system_diff > 0))
		*prio_info = lacp_port->partner;

	/* adjust values for further memcmp comparison */
	prio_info->system_priority = ntohs(prio_info->system_priority);
	prio_info->key = 0;
	prio_info->port_priority = ntohs(prio_info->port_priority);
	prio_info->port = ntohs(prio_info->port);
	prio_info->state = 0;
}

typedef bool (*lacp_is_port_better_t)(struct lacp_port *lacp_port1,
				      struct lacp_port *lacp_port2);

static bool lacp_is_port_better_by_lacp_prio(struct lacp_port *lacp_port1,
					     struct lacp_port *lacp_port2)
{
	struct lacpdu_info prio_info1;
	struct lacpdu_info prio_info2;

	get_lacp_port_prio_info(lacp_port1, &prio_info1);
	get_lacp_port_prio_info(lacp_port2, &prio_info2);
	return memcmp(&prio_info1, &prio_info2, sizeof(prio_info1)) < 0;
}

static struct lacp_port *lacp_get_best_port(struct lacp *lacp,
					    lacp_is_port_better_t is_port_better_func)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	struct lacp_port *best_lacp_port = NULL;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port_selectable(lacp_port))
			continue;
		if (!best_lacp_port ||
		    is_port_better_func(lacp_port, best_lacp_port))
			best_lacp_port = lacp_port;
	}
	return best_lacp_port;
}

static int lacp_set_carrier(struct lacp *lacp, bool carrier_up)
{
	struct teamd_context *ctx = lacp->ctx;
	int err;

	if (lacp->carrier_up != carrier_up) {
		err = team_carrier_set(ctx->th, carrier_up);
		if (err)
			return err;

		teamd_log_info("carrier changed to %s",
			       carrier_up ? "UP" : "DOWN" );
		lacp->carrier_up = carrier_up;
	}

	return 0;
}

static int lacp_update_carrier(struct lacp *lacp)
{
	struct teamd_port *tdport;
	int ports_enabled;
	bool state;
	int err;

	ports_enabled = 0;
	teamd_for_each_tdport(tdport, lacp->ctx) {
		err = teamd_port_enabled(lacp->ctx, tdport, &state);
		if (err)
			return err;
		if (state && ++ports_enabled >= lacp->cfg.min_ports)
			return lacp_set_carrier(lacp, true);
	}

	return lacp_set_carrier(lacp, false);
}

static bool lacp_agg_has_selected_port(struct lacp *lacp,
				       uint32_t aggregator_id)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (lacp_port->selected &&
		    lacp_port->aggregator_id == aggregator_id)
			return true;
	}
	return false;
}

static uint32_t lacp_get_agg_bandwidth(struct lacp *lacp,
				       uint32_t aggregator_id)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	uint32_t speed = 0;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port->selected ||
		    lacp_port->aggregator_id != aggregator_id)
			continue;
		speed += team_get_port_speed(tdport->team_port);
	}
	return speed;
}

static uint32_t lacp_get_best_agg_by_bandwidth(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	uint32_t speed;
	uint32_t best_speed = 0;
	uint32_t best_aggregator_id = 0;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port->selected)
			continue;
		speed = lacp_get_agg_bandwidth(lacp, lacp_port->aggregator_id);
		if (speed > best_speed) {
			best_speed = speed;
			best_aggregator_id = lacp_port->aggregator_id;
		}
	}
	return best_aggregator_id;
}

static unsigned int lacp_get_agg_port_count(struct lacp *lacp,
					    uint32_t aggregator_id)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	unsigned int port_count = 0;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port->selected ||
		    lacp_port->aggregator_id != aggregator_id)
			continue;
		port_count++;
	}
	return port_count;
}

static uint32_t lacp_get_best_agg_by_port_count(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	unsigned int port_count;
	unsigned int best_port_count = 0;
	uint32_t best_aggregator_id = 0;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port->selected)
			continue;
		port_count = lacp_get_agg_port_count(lacp,
						     lacp_port->aggregator_id);
		if (port_count > best_port_count) {
			best_port_count = port_count;
			best_aggregator_id = lacp_port->aggregator_id;
		}
	}
	return best_aggregator_id;
}

static int lacp_update_selected(struct lacp *lacp)
{
	struct lacp_port *best_lacp_port;
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	uint32_t aggregator_id;
	uint32_t orig_selected_aggregator_id = lacp->selected_aggregator_id;
	uint32_t best_aggregator_id = 0;
	lacp_is_port_better_t is_port_better_func;
	int err;

	/*
	 * First, unselect all so they will be all free to aggrerate with
	 * each other.
	 */
	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		lacp_port->selected = false;
		lacp_port->aggregator_id = 0;
	}

	lacp->selected_aggregator_id = 0;

	is_port_better_func = lacp_is_port_better_by_lacp_prio;

	while ((best_lacp_port = lacp_get_best_port(lacp, is_port_better_func))) {
		/* Use best port ifindex as aggregator id */
		aggregator_id = best_lacp_port->tdport->ifindex;
		if (!best_aggregator_id)
			best_aggregator_id = aggregator_id;
		teamd_for_each_tdport(tdport, lacp->ctx) {
			lacp_port = lacp_port_get(lacp, tdport);
			if (lacp_port_selectable(lacp_port) &&
			    lacp_ports_aggregable(lacp_port, best_lacp_port)) {
				lacp_port->selected = true;
				lacp_port->aggregator_id = aggregator_id;
			}
		}
	}

	switch (lacp->cfg.agg_select_policy) {
	case LACP_AGG_SELECT_LACP_PRIO:
		lacp->selected_aggregator_id = best_aggregator_id;
		break;
	case LACP_AGG_SELECT_LACP_PRIO_STABLE:
		if (best_aggregator_id &&
		    !lacp_agg_has_selected_port(lacp,
						orig_selected_aggregator_id))
			lacp->selected_aggregator_id = best_aggregator_id;
		break;
	case LACP_AGG_SELECT_BANDWIDTH:
		lacp->selected_aggregator_id =
			lacp_get_best_agg_by_bandwidth(lacp);
		break;
	case LACP_AGG_SELECT_COUNT:
		lacp->selected_aggregator_id =
			lacp_get_best_agg_by_port_count(lacp);
		break;
	}

	/*
	 * At last, do port enabling/disabling.
	 */
	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		err = lacp_port_update_enabled(lacp_port);
		if (err)
			return err;
	}

	err = lacp_update_carrier(lacp);
	if (err)
		return err;

	return 0;
}

static const char slow_addr[ETH_ALEN] = { 0x01, 0x80, 0xC2, 0x00, 0x00, 0x02 };

static int __slow_addr_add_del(struct lacp_port *lacp_port, bool add)
{
	struct ifreq ifr;
	struct sockaddr *sa;
	char *devname = lacp_port->tdport->ifname;
	int ret;

	memset(&ifr, 0, sizeof(struct ifreq));
	sa = (struct sockaddr *) &ifr.ifr_addr;
	sa->sa_family = AF_UNSPEC;
	memcpy(sa->sa_data, slow_addr, sizeof(slow_addr));
	memcpy(ifr.ifr_name, devname, strlen(devname));
	ret = ioctl(lacp_port->sock, add ? SIOCADDMULTI : SIOCDELMULTI, &ifr);
	if (ret == -1) {
		teamd_log_err("ioctl %s failed.",
			      add ? "SIOCADDMULTI" : "SIOCDELMULTI");
		return -errno;
	}
	return 0;
}

static int slow_addr_add(struct lacp_port *lacp_port)
{
	return __slow_addr_add_del(lacp_port, true);
}

static int slow_addr_del(struct lacp_port *lacp_port)
{
	return __slow_addr_add_del(lacp_port, false);
}

/* Values are in ms */
#define LACP_PERIODIC_SHORT 1000
#define LACP_PERIODIC_LONG 30000

/* time = periodic_interval * LACP_PERIODIC_MUL */
#define LACP_PERIODIC_MUL 3

#define LACP_SOCKET_CB_NAME "lacp_socket"
#define LACP_PERIODIC_CB_NAME "lacp_periodic"
#define LACP_TIMEOUT_CB_NAME "lacp_timeout"

static int lacp_port_timeout_set(struct lacp_port *lacp_port, bool fast_forced)
{
	int err;
	struct timespec ts;
	int ms;

	ms = fast_forced || lacp_port->lacp->cfg.fast_rate ?
					LACP_PERIODIC_SHORT: LACP_PERIODIC_LONG;
	ms *= LACP_PERIODIC_MUL;
	ms_to_timespec(&ts, ms);
	err = teamd_loop_callback_timer_set(lacp_port->ctx,
					    LACP_TIMEOUT_CB_NAME,
					    lacp_port, NULL, &ts);
	if (err) {
		teamd_log_err("Failed to set timeout timer.");
		return err;
	}
	return 0;
}

static int lacp_port_periodic_set(struct lacp_port *lacp_port)
{
	int err;
	struct timespec ts;
	int ms;
	int fast_on;

	fast_on = lacp_port->partner.state & INFO_STATE_LACP_TIMEOUT;
	teamd_log_dbg("%s: Setting periodic timer to \"%s\".",
		      lacp_port->tdport->ifname, fast_on ? "fast": "slow");
	ms = fast_on ? LACP_PERIODIC_SHORT: LACP_PERIODIC_LONG;
	ms_to_timespec(&ts, ms);
	err = teamd_loop_callback_timer_set(lacp_port->ctx,
					    LACP_PERIODIC_CB_NAME,
					    lacp_port, &ts, NULL);
	if (err) {
		teamd_log_err("Failed to set periodic timer.");
		return err;
	}
	return 0;
}

static bool lacp_port_should_be_active(struct lacp_port *lacp_port)
{
	return (lacp_port->partner.state & INFO_STATE_LACP_ACTIVITY) ||
	       (lacp_port->lacp->cfg.active);
}

static void lacp_port_periodic_cb_change_enabled(struct lacp_port *lacp_port)
{
	if (lacp_port_should_be_active(lacp_port) && lacp_port->periodic_on)
		teamd_loop_callback_enable(lacp_port->ctx,
					   LACP_PERIODIC_CB_NAME, lacp_port);
	else
		teamd_loop_callback_disable(lacp_port->ctx,
					    LACP_PERIODIC_CB_NAME, lacp_port);
}

static void lacp_port_periodic_on(struct lacp_port *lacp_port)
{
	lacp_port->periodic_on = true;
	lacp_port_periodic_cb_change_enabled(lacp_port);
}

static void lacp_port_periodic_off(struct lacp_port *lacp_port)
{
	lacp_port->periodic_on = false;
	lacp_port_periodic_cb_change_enabled(lacp_port);
}

static int lacp_port_partner_update(struct lacp_port *lacp_port)
{
	uint8_t state_changed;
	int err;

	state_changed = lacp_port->partner.state ^
			lacp_port->__partner_last.state;

	if (state_changed & INFO_STATE_LACP_TIMEOUT) {
		err = lacp_port_periodic_set(lacp_port);
		if (err)
			return err;
	}
	if (state_changed & INFO_STATE_LACP_ACTIVITY)
		lacp_port_periodic_cb_change_enabled(lacp_port);

	lacp_port->__partner_last = lacp_port->partner;
	return lacp_update_selected(lacp_port->lacp);
}

static void lacp_port_actor_init(struct lacp_port *lacp_port)
{
	struct lacpdu_info *actor = &lacp_port->actor;

	actor->system_priority = htons(lacp_port->lacp->cfg.sys_prio);
	memcpy(actor->system, lacp_port->ctx->hwaddr, ETH_ALEN);
        actor->key = htons(lacp_port->cfg.key);
        actor->port_priority = htons(lacp_port->cfg.prio);
	actor->port = htons(lacp_port->tdport->ifindex);
}

static int lacpdu_send(struct lacp_port *lacp_port);

static int lacp_port_actor_update(struct lacp_port *lacp_port)
{
	int err;
	uint8_t state = 0;

	err = lacp_update_selected(lacp_port->lacp);
	if (err)
		return err;

	if (lacp_port->lacp->cfg.active)
		state |= INFO_STATE_LACP_ACTIVITY;
	if (lacp_port->lacp->cfg.fast_rate)
		state |= INFO_STATE_LACP_TIMEOUT;
	if (lacp_port->selected)
		state |= INFO_STATE_SYNCHRONIZATION;
	state |= INFO_STATE_COLLECTING | INFO_STATE_DISTRIBUTING;
	if (lacp_port->state == PORT_STATE_EXPIRED)
		state |= INFO_STATE_EXPIRED;
	if (lacp_port->state == PORT_STATE_DEFAULTED)
		state |= INFO_STATE_DEFAULTED;
	if (teamd_port_count(lacp_port->ctx) > 1)
		state |= INFO_STATE_AGGREGATION;
	teamd_log_dbg("%s: lacp info state: 0x%02X.", lacp_port->tdport->ifname,
						      state);
	lacp_port->actor.state = state;
	return lacpdu_send(lacp_port);
}

static int lacp_port_set_state(struct lacp_port *lacp_port,
			       enum lacp_port_state new_state)
{
	int err;

	if (new_state == lacp_port->state)
		return 0;
	if (new_state == PORT_STATE_DISABLED)
		lacp_port_periodic_off(lacp_port);
	else
		lacp_port_periodic_on(lacp_port);

	switch(new_state) {
	case PORT_STATE_CURRENT:
		break;
	case PORT_STATE_EXPIRED:
		teamd_loop_callback_enable(lacp_port->ctx,
					   LACP_PERIODIC_CB_NAME, lacp_port);
		/*
		 * This is a transient state; the LACP_Timeout settings allow
		 * the Actor to transmit LACPDUs rapidly in an attempt to
		 * re-establish communication with the Partner.
		 */
		lacp_port->partner.state |= INFO_STATE_LACP_TIMEOUT;
		lacp_port->partner.state &= ~INFO_STATE_SYNCHRONIZATION;
		err = lacp_port_partner_update(lacp_port);
		if (err)
			return err;
		lacp_port_timeout_set(lacp_port, true);
		teamd_loop_callback_enable(lacp_port->ctx,
					   LACP_TIMEOUT_CB_NAME, lacp_port);
		break;
	case PORT_STATE_DEFAULTED:
		teamd_loop_callback_disable(lacp_port->ctx,
					    LACP_TIMEOUT_CB_NAME, lacp_port);
		/* fall through */
	case PORT_STATE_DISABLED:
		memset(&lacp_port->partner, 0, sizeof(lacp_port->partner));
		err = lacp_port_partner_update(lacp_port);
		if (err)
			return err;
		break;
	}

	teamd_log_info("%s: Changed port state: \"%s\" -> \"%s\"",
		       lacp_port->tdport->ifname,
		       lacp_port_state_name[lacp_port->state],
		       lacp_port_state_name[new_state]);
	lacp_port->state = new_state;
	return lacp_port_actor_update(lacp_port);
}

static enum lacp_port_state lacp_port_get_state(struct lacp_port *lacp_port)
{
	return lacp_port->state;
}

/* Called when ethtool port link state is changed and when port is added*/
static int lacp_port_link_update(struct lacp_port *lacp_port)
{
	struct team_port *team_port = lacp_port->tdport->team_port;
	bool linkup = team_is_port_link_up(team_port);
	uint32_t speed = team_get_port_speed(team_port);
	uint8_t duplex = team_get_port_duplex(team_port);
	int err;

	if (duplex != lacp_port->__link_last.duplex) {
		if (duplex)
			err = lacp_port_set_state(lacp_port, PORT_STATE_EXPIRED);
		else
			err = lacp_port_set_state(lacp_port, PORT_STATE_DISABLED);
		if (err)
			return err;
	}
	lacp_port->__link_last.up = linkup;
	lacp_port->__link_last.speed = speed;
	lacp_port->__link_last.duplex = duplex;
	return 0;
}

static int lacpdu_send(struct lacp_port *lacp_port)
{
	struct lacpdu lacpdu;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_slow;
	int err;

	err = teamd_getsockname_hwaddr(lacp_port->sock, &ll_my, 0);
	if (err)
		return err;
	ll_slow = ll_my;
	memcpy(ll_slow.sll_addr, slow_addr, ll_slow.sll_halen);

	lacpdu_init(&lacpdu);
	lacpdu.actor = lacp_port->actor;
	lacpdu.partner = lacp_port->partner;

	err = teamd_sendto(lacp_port->sock, &lacpdu, sizeof(lacpdu), 0,
			   (struct sockaddr *) &ll_slow, sizeof(ll_slow));
	return err;
}

static int lacpdu_recv(struct lacp_port *lacp_port)
{
	struct lacpdu lacpdu;
	struct sockaddr_ll ll_from;
	int err;

	err = teamd_recvfrom(lacp_port->sock, &lacpdu, sizeof(lacpdu), 0,
			     (struct sockaddr *) &ll_from, sizeof(ll_from));
	if (err <= 0)
		return err;

	if (!lacpdu_check(&lacpdu)) {
		teamd_log_warn("malformed LACP PDU came.");
		return 0;
	}

	err = lacp_port_set_state(lacp_port, PORT_STATE_CURRENT);
	if (err)
		return err;

	/* Check if we have correct info about the other side */
	if (memcmp(&lacpdu.actor, &lacp_port->partner,
		   sizeof(struct lacpdu_info))) {
		lacp_port->partner = lacpdu.actor;
		err = lacp_port_partner_update(lacp_port);
		if (err)
			return err;
	}

	/* Check if the other side has correct info about us */
	if (memcmp(&lacpdu.partner, &lacp_port->actor,
		   sizeof(struct lacpdu_info))) {
		err = lacpdu_send(lacp_port);
		if (err)
			return err;
	}
	err = lacp_port_timeout_set(lacp_port, false);
	if (err) {
		return err;
	}
	teamd_loop_callback_enable(lacp_port->ctx,
				   LACP_TIMEOUT_CB_NAME, lacp_port);
	return 0;
}

static int lacp_callback_timeout(struct teamd_context *ctx, int events,
				 void *priv)
{
	struct lacp_port *lacp_port = priv;
	int err = 0;

	switch (lacp_port_get_state(lacp_port)) {
	case PORT_STATE_CURRENT:
		err = lacp_port_set_state(lacp_port, PORT_STATE_EXPIRED);
		break;
	case PORT_STATE_EXPIRED:
		err = lacp_port_set_state(lacp_port, PORT_STATE_DEFAULTED);
		break;
	case PORT_STATE_DEFAULTED:
	case PORT_STATE_DISABLED:
		/* This can't happen */
		break;
	}
	return err;
}

static int lacp_callback_periodic(struct teamd_context *ctx, int events,
				  void *priv)
{
	struct lacp_port *lacp_port = priv;

	return lacpdu_send(lacp_port);
}

static int lacp_callback_socket(struct teamd_context *ctx, int events,
				void *priv)
{
	struct lacp_port *lacp_port = priv;

	return lacpdu_recv(lacp_port);
}

static int lacp_port_set_mac(struct teamd_context *ctx,
			     struct teamd_port *tdport)
{
	int err;

	err = team_hwaddr_set(ctx->th, tdport->ifindex, ctx->hwaddr,
			      ctx->hwaddr_len);
	if (err) {
		teamd_log_err("%s: Failed to set hardware address. ",
			      tdport->ifname);
		return err;
	}
	return 0;
}

static int lacp_port_load_config(struct teamd_context *ctx,
				 struct lacp_port *lacp_port)
{
	const char *port_name = lacp_port->tdport->ifname;
	int err;
	int tmp;

	err = json_unpack(ctx->config_json, "{s:{s:{s:i}}}", "ports", port_name,
							     "lacp_prio", &tmp);
	if (err) {
		lacp_port->cfg.prio = LACP_PORT_CFG_DFLT_PRIO;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("%s: \"lacp_prio\" value is out of its limits.",
			      port_name);
		return -EINVAL;
	} else {
		lacp_port->cfg.prio = tmp;
	}
	teamd_log_dbg("%s: Using lacp_prio \"%d\".", port_name,
		      lacp_port->cfg.prio);

	err = json_unpack(ctx->config_json, "{s:{s:{s:i}}}", "ports", port_name,
							     "lacp_key", &tmp);
	if (err) {
		lacp_port->cfg.key = LACP_PORT_CFG_DFLT_KEY;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("%s: \"lacp_key\" value is out of its limits.",
			      port_name);
		return -EINVAL;
	} else {
		lacp_port->cfg.key = tmp;
	}
	teamd_log_dbg("%s: Using lacp_key \"%d\".", port_name,
		      lacp_port->cfg.key);
	return 0;
}

static int lacp_port_added(struct teamd_context *ctx,
			   struct teamd_port *tdport,
			   void *priv, void *creator_priv)
{
	struct lacp_port *lacp_port = priv;
	struct lacp *lacp = creator_priv;
	int err;

	lacp_port->ctx = ctx;
	lacp_port->tdport = tdport;
	lacp_port->lacp = lacp;

	err = lacp_port_load_config(ctx, lacp_port);
	if (err) {
		teamd_log_err("Failed to load port config.");
		return err;
	}

	err = teamd_packet_sock_open(&lacp_port->sock,
				     tdport->ifindex,
				     htons(ETH_P_SLOW), NULL, NULL);
	if (err)
		return err;

	err = slow_addr_add(lacp_port);
	if (err)
		goto close_sock;

	err = teamd_loop_callback_fd_add(ctx, LACP_SOCKET_CB_NAME, lacp_port,
					 lacp_callback_socket,
					 lacp_port->sock,
					 TEAMD_LOOP_FD_EVENT_READ);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto slow_addr_del;
	}

	err = teamd_loop_callback_timer_add(ctx, LACP_PERIODIC_CB_NAME,
					    lacp_port, lacp_callback_periodic);
	if (err) {
		teamd_log_err("Failed add periodic callback timer");
		goto socket_callback_del;
	}
	err = lacp_port_periodic_set(lacp_port);
	if (err)
		goto periodic_callback_del;

	err = teamd_loop_callback_timer_add(ctx, LACP_TIMEOUT_CB_NAME,
					    lacp_port, lacp_callback_timeout);
	if (err) {
		teamd_log_err("Failed add timeout callback timer");
		goto periodic_callback_del;
	}

	/* Newly added ports are enabled */
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		goto timeout_callback_del;
	}

	err = lacp_port_set_mac(ctx, tdport);
	if (err)
		goto timeout_callback_del;

	lacp_port_actor_init(lacp_port);
	lacp_port_link_update(lacp_port);

	teamd_loop_callback_enable(ctx, LACP_SOCKET_CB_NAME, lacp_port);
	return 0;

timeout_callback_del:
	teamd_loop_callback_del(ctx, LACP_TIMEOUT_CB_NAME, lacp_port);
periodic_callback_del:
	teamd_loop_callback_del(ctx, LACP_PERIODIC_CB_NAME, lacp_port);
socket_callback_del:
	teamd_loop_callback_del(ctx, LACP_SOCKET_CB_NAME, lacp_port);
slow_addr_del:
	slow_addr_del(lacp_port);
close_sock:
	close(lacp_port->sock);
	return err;
}

static void lacp_port_removed(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      void *priv, void *creator_priv)
{
	struct lacp_port *lacp_port = priv;

	lacp_port_set_state(lacp_port, PORT_STATE_DISABLED);
	teamd_loop_callback_del(ctx, LACP_TIMEOUT_CB_NAME, lacp_port);
	teamd_loop_callback_del(ctx, LACP_PERIODIC_CB_NAME, lacp_port);
	teamd_loop_callback_del(ctx, LACP_SOCKET_CB_NAME, lacp_port);
	slow_addr_del(lacp_port);
	close(lacp_port->sock);
}

static const struct teamd_port_priv lacp_port_priv = {
	.init = lacp_port_added,
	.fini = lacp_port_removed,
	.priv_size = sizeof(struct lacp_port),
};

static int lacp_event_watch_port_added(struct teamd_context *ctx,
				       struct teamd_port *tdport, void *priv)
{
	struct lacp *lacp = priv;
	int err;

	err = teamd_port_priv_create(tdport, &lacp_port_priv, lacp);
	if (err)
		return err;
	return teamd_balancer_port_added(lacp->tb, tdport);
}

static void lacp_event_watch_port_removed(struct teamd_context *ctx,
					  struct teamd_port *tdport, void *priv)
{
	struct lacp *lacp = priv;

	teamd_balancer_port_removed(lacp->tb, tdport);
}

static int lacp_event_watch_port_changed(struct teamd_context *ctx,
					 struct teamd_port *tdport, void *priv)
{
	struct lacp *lacp = priv;
	struct lacp_port *lacp_port = lacp_port_get(lacp, tdport);

	return lacp_port_link_update(lacp_port);
}

static const struct teamd_event_watch_ops lacp_port_watch_ops = {
	.port_added = lacp_event_watch_port_added,
	.port_removed = lacp_event_watch_port_removed,
	.port_changed = lacp_event_watch_port_changed,
};

static int lacp_carrier_init(struct teamd_context *ctx, struct lacp *lacp)
{
	int err;

	/* initialize carrier control */
	err = team_carrier_set(ctx->th, false);
	if (err) {
		teamd_log_err("Failed to set carrier down.");
		return err;
	}

	lacp->carrier_up = false;

	return 0;
}

static int lacp_carrier_fini(struct teamd_context *ctx, struct lacp *lacp)
{
	int err;

	err = team_carrier_set(ctx->th, false);
	if (err) {
		teamd_log_err("Failed to set carrier down.");
		return err;
	}

	lacp->carrier_up = false;

	return 0;
}

static int lacp_init(struct teamd_context *ctx, void *priv)
{
	struct lacp *lacp = priv;
	int err;

	if (ctx->hwaddr_len != ETH_ALEN) {
		teamd_log_err("Unsupported device type.");
		return -EINVAL;
	}

	lacp->ctx = ctx;
	err = teamd_hash_func_set(ctx);
	if (err)
		return err;
	err = lacp_load_config(ctx, lacp);
	if (err) {
		teamd_log_err("Failed to load config values.");
		return err;
	}
	err = lacp_carrier_init(ctx, lacp);
	if (err) {
		teamd_log_err("Failed to initialize carrier.");
		return err;
	}
	err = teamd_event_watch_register(ctx, &lacp_port_watch_ops, lacp);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_balancer_init(ctx, &lacp->tb);
	if (err) {
		teamd_log_err("Failed to init balanced.");
		goto event_watch_unregister;
	}
	return 0;
event_watch_unregister:
	teamd_event_watch_unregister(ctx, &lacp_port_watch_ops, lacp);
	return err;
}

static void lacp_fini(struct teamd_context *ctx, void *priv)
{
	struct lacp *lacp = priv;

	teamd_balancer_fini(lacp->tb);
	teamd_event_watch_unregister(ctx, &lacp_port_watch_ops, lacp);
	lacp_carrier_fini(ctx, lacp);
}

static json_t *__fill_lacpdu_info(struct lacpdu_info *lacpdu_info)
{
	char addr_str[hwaddr_str_len(ETH_ALEN)];

	hwaddr_str(addr_str, (char *) lacpdu_info->system, ETH_ALEN);
	return json_pack("{s:i, s:s, s:i, s:i, s:i, s:i}",
			 "system_priority", lacpdu_info->system_priority,
			 "system", addr_str,
			 "key", lacpdu_info->key,
			 "port_priority", lacpdu_info->port_priority,
			 "port", lacpdu_info->port,
			 "state", lacpdu_info->state);
}

static json_t *__fill_lacp_port(struct lacp_port *lacp_port)
{
	json_t *s_json;
	json_t *actor_json;
	json_t *partner_json;

	actor_json = __fill_lacpdu_info(&lacp_port->actor);
	if (!actor_json)
		return NULL;

	partner_json = __fill_lacpdu_info(&lacp_port->partner);
	if (!partner_json) {
		json_decref(actor_json);
		return NULL;
	}

	s_json = json_pack("{s:b, s:i, s:s, s:i, s:i, s:o, s:o}",
			   "selected", lacp_port->selected,
			   "aggregator_id", lacp_port->aggregator_id,
			   "state", lacp_port_state_name[lacp_port->state],
			   "key", lacp_port->cfg.key,
			   "prio", lacp_port->cfg.prio,
			   "actor_lacpdu_info", actor_json,
			   "partner_lacpdu_info", partner_json);
	if (!s_json) {
		json_decref(actor_json);
		json_decref(partner_json);
		return NULL;
	}
	return s_json;
}

static int lacp_state_json_per_port_dump(struct teamd_context *ctx,
					 struct teamd_port *tdport,
					 json_t **pstate_json, void *priv)
{
	struct lacp *lacp = priv;
	json_t *state_json;

	state_json = __fill_lacp_port(lacp_port_get(lacp, tdport));
	if (!state_json)
		return -ENOMEM;
	*pstate_json = state_json;
	return 0;
}

static int lacp_state_json_dump(struct teamd_context *ctx,
				json_t **pstate_json, void *priv)
{
	struct lacp *lacp = priv;
	json_t *state_json;

	state_json = json_pack("{s:i, s:b, s:i, s:b}",
			       "selected_aggregator_id",
			       lacp->selected_aggregator_id,
			       "active", lacp->cfg.active,
			       "sys_prio", lacp->cfg.sys_prio,
			       "fast_rate", lacp->cfg.fast_rate);
	if (!state_json)
		return -ENOMEM;
	*pstate_json = state_json;
	return 0;
}

static const struct teamd_state_json_ops lacp_state_ops = {
	.dump			= lacp_state_json_dump,
	.per_port_dump		= lacp_state_json_per_port_dump,
	.name			= TEAMD_RUNNER_STATE_JSON_NAME,
};

const struct teamd_runner teamd_runner_lacp = {
	.name			= "lacp",
	.team_mode_name		= "loadbalance",
	.priv_size		= sizeof(struct lacp),
	.init			= lacp_init,
	.fini			= lacp_fini,
	.state_json_ops		= &lacp_state_ops,
};
