/*
 *   teamd_runner_lacp.c - Teamd 802.3ad LACP runner implementation
 *   Copyright (C) 2012-2015 Jiri Pirko <jiri@resnulli.us>
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
#include <net/ethernet.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_state.h"
#include "teamd_workq.h"

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
	struct ether_header	hdr;
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
	LACP_AGG_SELECT_PORT_CONFIG = 4,
};

static const char *lacp_agg_select_policy_names_list[] = {
	"lacp_prio", "lacp_prio_stable", "bandwidth", "count", "port_config",
};

#define LACP_AGG_SELECT_POLICY_NAMES_LIST_SIZE \
	ARRAY_SIZE(lacp_agg_select_policy_names_list)

struct lacp_port;

struct lacp {
	struct teamd_context *ctx;
	struct lacp_port *selected_agg_lead; /* leading port of selected aggregator */
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
	bool periodic_on;
	struct lacp_port *agg_lead; /* leading port of aggregator.
				     * NULL in case this port is not selected */
	enum lacp_port_state state;
	struct {
		uint32_t speed;
		uint8_t	duplex;
		bool up;
	} __link_last;
	struct {
		uint16_t lacp_prio;
#define		LACP_PORT_CFG_DFLT_LACP_PRIO 0xff
		uint16_t lacp_key;
#define		LACP_PORT_CFG_DFLT_LACP_KEY 0
		bool sticky;
#define		LACP_PORT_CFG_DFLT_STICKY false
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

static uint32_t lacp_agg_id(struct lacp_port *agg_lead)
{
	return agg_lead ? agg_lead->tdport->ifindex : 0;
}

static bool lacp_agg_selected(struct lacp_port *agg_lead)
{
	return agg_lead ? agg_lead == agg_lead->lacp->selected_agg_lead : false;
}

static uint32_t lacp_port_agg_id(struct lacp_port *lacp_port)
{
	return lacp_agg_id(lacp_port->agg_lead);
}

static uint32_t lacp_port_agg_selected(struct lacp_port *lacp_port)
{
	return lacp_agg_selected(lacp_port->agg_lead);
}

static bool lacp_port_is_agg_lead(struct lacp_port *lacp_port)
{
	return lacp_port->agg_lead == lacp_port;
}

static const char *lacp_get_agg_select_policy_name(struct lacp *lacp)
{
	return lacp_agg_select_policy_names_list[lacp->cfg.agg_select_policy];
}

static int lacp_assign_agg_select_policy(struct lacp *lacp,
					 const char *agg_select_policy_name)
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
	const char *agg_select_policy_name;

	err = teamd_config_bool_get(ctx, &lacp->cfg.active, "$.runner.active");
	if (err)
		lacp->cfg.active =  LACP_CFG_DFLT_ACTIVE;
	teamd_log_dbg("Using active \"%d\".", lacp->cfg.active);

	err = teamd_config_int_get(ctx, &tmp, "$.runner.sys_prio");
	if (err) {
		lacp->cfg.sys_prio = LACP_CFG_DFLT_SYS_PRIO;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("\"sys_prio\" value is out of its limits.");
		return -EINVAL;
	} else {
		lacp->cfg.sys_prio = tmp;
	}
	teamd_log_dbg("Using sys_prio \"%d\".", lacp->cfg.sys_prio);

	err = teamd_config_bool_get(ctx, &lacp->cfg.fast_rate, "$.runner.fast_rate");
	if (err)
		lacp->cfg.fast_rate = LACP_CFG_DFLT_FAST_RATE;
	teamd_log_dbg("Using fast_rate \"%d\".", lacp->cfg.fast_rate);

	err = teamd_config_int_get(ctx, &tmp, "$.runner.min_ports");
	if (err) {
		lacp->cfg.min_ports = LACP_CFG_DFLT_MIN_PORTS;
	} else if (tmp < 1 || tmp > UCHAR_MAX) {
		teamd_log_err("\"min_ports\" value is out of its limits.");
		return -EINVAL;
	} else {
		lacp->cfg.min_ports = tmp;
	}
	teamd_log_dbg("Using min_ports \"%d\".", lacp->cfg.min_ports);

	err = teamd_config_string_get(ctx, &agg_select_policy_name, "$.runner.agg_select_policy");
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

static bool lacp_port_loopback_free(struct lacp_port *lacp_port)
{
	if (!memcmp(lacp_port->actor.system,
		    lacp_port->partner.system, ETH_ALEN)) {
		teamd_log_warn("%s: Port seems to be loopbacked to the same "
			       "team device.", lacp_port->tdport->ifname);
		return false;
	}
	return true;
}

static bool lacp_port_selectable_state(struct lacp_port *lacp_port)
{
	if (lacp_port->state == PORT_STATE_CURRENT)
		return true;
	return false;
}

static bool lacp_port_unselectable_state(struct lacp_port *lacp_port)
{
	if (lacp_port->state == PORT_STATE_CURRENT ||
	    lacp_port->state == PORT_STATE_EXPIRED)
		return false;
	return true;
}

static bool lacp_port_selected(struct lacp_port *lacp_port)
{
	return lacp_port->agg_lead;
}

static int lacp_port_should_be_enabled(struct lacp_port *lacp_port)
{
	struct lacp *lacp = lacp_port->lacp;

	if (lacp_port_selected(lacp_port) &&
	    lacp_port->agg_lead == lacp->selected_agg_lead &&
	    lacp_port->partner.state & INFO_STATE_SYNCHRONIZATION)
		return true;
	return false;
}

static int lacp_port_should_be_disabled(struct lacp_port *lacp_port)
{
	struct lacp *lacp = lacp_port->lacp;

	if (!lacp_port_selected(lacp_port) ||
	    lacp_port->agg_lead != lacp->selected_agg_lead ||
	    !(lacp_port->partner.state & INFO_STATE_SYNCHRONIZATION))
		return true;
	return false;
}

static int lacp_port_update_enabled(struct lacp_port *lacp_port)
{
	return teamd_port_check_enable(lacp_port->ctx, lacp_port->tdport,
				       lacp_port_should_be_enabled(lacp_port),
				       lacp_port_should_be_disabled(lacp_port));
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

static bool lacp_port_correct_aggregation(struct lacp_port *checked_lacp_port)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	/* Find first port in same aggregator and see if checked port is
	 * aggregable with that. That's enough because all of the ports
	 * in aggregator besides the checked one are aggregable with each other.
	 */

	teamd_for_each_tdport(tdport, checked_lacp_port->ctx) {
		lacp_port = lacp_port_get(checked_lacp_port->lacp, tdport);
		if (!lacp_port_selected(lacp_port) ||
		    lacp_port->agg_lead != checked_lacp_port->agg_lead ||
		    lacp_port == checked_lacp_port)
			continue;
		return lacp_ports_aggregable(lacp_port, checked_lacp_port);
	}
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
	if (prio_diff > 0 || (prio_diff == 0 && system_diff >= 0))
		*prio_info = lacp_port->partner;

	/* adjust values for further memcmp comparison */
	prio_info->system_priority = ntohs(prio_info->system_priority);
	prio_info->key = 0;
	prio_info->port_priority = ntohs(prio_info->port_priority);
	prio_info->port = ntohs(prio_info->port);
	prio_info->state = 0;
}

static bool lacp_port_better_by_lacp_prio(struct lacp_port *lacp_port1,
					  struct lacp_port *lacp_port2)
{
	struct lacpdu_info prio_info1;
	struct lacpdu_info prio_info2;

	get_lacp_port_prio_info(lacp_port1, &prio_info1);
	get_lacp_port_prio_info(lacp_port2, &prio_info2);
	return memcmp(&prio_info1, &prio_info2, sizeof(prio_info1)) < 0;
}

static bool lacp_port_better_by_port_config(struct lacp_port *lacp_port1,
					    struct lacp_port *lacp_port2)
{
	int prio1 = teamd_port_prio(lacp_port1->ctx, lacp_port1->tdport);
	int prio2 = teamd_port_prio(lacp_port2->ctx, lacp_port2->tdport);

	return prio1 > prio2;
}

static bool lacp_port_better(struct lacp_port *lacp_port1,
			     struct lacp_port *lacp_port2)
{
	if (!lacp_port2)
		return true;
	switch (lacp_port1->lacp->cfg.agg_select_policy) {
	case LACP_AGG_SELECT_PORT_CONFIG:
		return lacp_port_better_by_port_config(lacp_port1, lacp_port2);
	default:
		return lacp_port_better_by_lacp_prio(lacp_port1, lacp_port2);
	}
}

static int lacp_set_carrier(struct lacp *lacp, bool carrier_up)
{
	struct teamd_context *ctx = lacp->ctx;
	int err;

	if (lacp->carrier_up != carrier_up) {
		lacp->carrier_up = carrier_up;
		err = team_carrier_set(ctx->th, carrier_up);
		if (err)
			return err == -EOPNOTSUPP ? 0 : err;
		teamd_log_info("carrier changed to %s",
			       carrier_up ? "UP" : "DOWN" );
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

static uint32_t lacp_get_agg_bandwidth(struct lacp_port *agg_lead)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	uint32_t speed = 0;

	teamd_for_each_tdport(tdport, agg_lead->ctx) {
		lacp_port = lacp_port_get(agg_lead->lacp, tdport);
		if (lacp_port->agg_lead == agg_lead)
			speed += team_get_port_speed(tdport->team_port);
	}
	return speed;
}

static struct lacp_port *lacp_get_best_agg_by_bandwidth(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	uint32_t speed;
	uint32_t best_speed = 0;
	struct lacp_port *best_agg_lead = NULL;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port_selected(lacp_port))
			continue;
		speed = lacp_get_agg_bandwidth(lacp_port->agg_lead);
		if (speed > best_speed) {
			best_speed = speed;
			best_agg_lead = lacp_port->agg_lead;
		}
	}
	return best_agg_lead;
}

static unsigned int lacp_get_agg_port_count(struct lacp_port *agg_lead)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	unsigned int port_count = 0;

	teamd_for_each_tdport(tdport, agg_lead->ctx) {
		lacp_port = lacp_port_get(agg_lead->lacp, tdport);
		if (lacp_port->agg_lead == agg_lead)
			port_count++;
	}
	return port_count;
}

static struct lacp_port *lacp_get_best_agg_by_port_count(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	unsigned int port_count;
	unsigned int best_port_count = 0;
	struct lacp_port *best_agg_lead = NULL;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port_selected(lacp_port))
			continue;
		port_count = lacp_get_agg_port_count(lacp_port->agg_lead);
		if (port_count > best_port_count) {
			best_port_count = port_count;
			best_agg_lead = lacp_port->agg_lead;
		}
	}
	return best_agg_lead;
}

static struct lacp_port *lacp_get_best_agg_by_best_port(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	struct lacp_port *best_agg_lead = NULL;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port_selected(lacp_port))
			continue;
		if (lacp_port_better(lacp_port->agg_lead, best_agg_lead))
			best_agg_lead = lacp_port->agg_lead;
	}
	return best_agg_lead;
}

static bool lacp_agg_sticky(struct lacp_port *agg_lead)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	teamd_for_each_tdport(tdport, agg_lead->ctx) {
		lacp_port = lacp_port_get(agg_lead->lacp, tdport);
		if (lacp_port->agg_lead == agg_lead &&
		    lacp_port->cfg.sticky)
			return true;
	}
	return false;
}

static struct lacp_port *lacp_get_next_agg(struct lacp *lacp)
{
	struct lacp_port *next_agg_lead = lacp->selected_agg_lead;

	switch (lacp->cfg.agg_select_policy) {
	case LACP_AGG_SELECT_LACP_PRIO:
		next_agg_lead = lacp_get_best_agg_by_best_port(lacp);
		break;
	case LACP_AGG_SELECT_LACP_PRIO_STABLE:
		if (!lacp->selected_agg_lead)
			next_agg_lead = lacp_get_best_agg_by_best_port(lacp);
		break;
	case LACP_AGG_SELECT_BANDWIDTH:
		next_agg_lead = lacp_get_best_agg_by_bandwidth(lacp);
		break;
	case LACP_AGG_SELECT_COUNT:
		next_agg_lead = lacp_get_best_agg_by_port_count(lacp);
		break;
	case LACP_AGG_SELECT_PORT_CONFIG:
		if (!lacp->selected_agg_lead ||
		    !lacp_agg_sticky(lacp->selected_agg_lead))
			next_agg_lead = lacp_get_best_agg_by_best_port(lacp);
		break;
	}
	return next_agg_lead;
}

static struct lacp_port *lacp_get_agg_lead(struct lacp_port *for_lacp_port)
{
	struct lacp *lacp = for_lacp_port->lacp;
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (!lacp_port_selected(lacp_port) ||
		    lacp_port == for_lacp_port)
			continue;
		if (lacp_ports_aggregable(lacp_port, for_lacp_port))
			return lacp_port->agg_lead;
	}
	/* If no suitable aggregator found, the port is self-lead. */
	return for_lacp_port;
}

static void lacp_switch_agg_lead(struct lacp_port *agg_lead,
				 struct lacp_port *new_agg_lead)
{
	struct lacp *lacp = agg_lead->lacp;
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	teamd_log_dbg("Renaming aggregator %u to %u",
		      lacp_agg_id(agg_lead), lacp_agg_id(new_agg_lead));
	if (lacp->selected_agg_lead == agg_lead)
		lacp->selected_agg_lead = new_agg_lead;
	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		if (lacp_port->agg_lead == agg_lead)
			lacp_port->agg_lead = new_agg_lead;
	}
}

static void lacp_port_agg_select(struct lacp_port *lacp_port)
{
	struct lacp_port *agg_lead;

	teamd_log_dbg("%s: Selecting LACP port", lacp_port->tdport->ifname);
	agg_lead = lacp_get_agg_lead(lacp_port);
	lacp_port->agg_lead = agg_lead;
	if (lacp_port_better(lacp_port, agg_lead))
		lacp_switch_agg_lead(agg_lead, lacp_port);
	teamd_log_dbg("%s: LACP port selected into aggregator %u",
		      lacp_port->tdport->ifname, lacp_port_agg_id(lacp_port));
}

static struct lacp_port *lacp_find_new_agg_lead(struct lacp_port *old_agg_lead)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	struct lacp_port *new_agg_lead = NULL;

	teamd_for_each_tdport(tdport, old_agg_lead->ctx) {
		lacp_port = lacp_port_get(old_agg_lead->lacp, tdport);
		if (lacp_port->agg_lead == old_agg_lead &&
		    lacp_port_better(lacp_port, new_agg_lead))
			new_agg_lead = lacp_port;
	}
	return new_agg_lead;
}

static void lacp_port_agg_unselect(struct lacp_port *lacp_port)
{
	struct lacp_port *agg_lead = lacp_port->agg_lead;

	teamd_log_dbg("%s: Unselecting LACP port", lacp_port->tdport->ifname);
	teamd_log_dbg("%s: LACP port unselected from aggregator %u",
		      lacp_port->tdport->ifname, lacp_port_agg_id(lacp_port));
	lacp_port->agg_lead = NULL;
	if (lacp_port == agg_lead) {
		/* In case currently unselected port is aggregator lead lead,
		 * find new one.
		 */
		struct lacp_port *new_agg_lead;

		new_agg_lead = lacp_find_new_agg_lead(agg_lead);
		lacp_switch_agg_lead(agg_lead, new_agg_lead);
	}
}

static int lacp_ports_update_enabled(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	int err;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = lacp_port_get(lacp, tdport);
		err = lacp_port_update_enabled(lacp_port);
		if (err)
			return err;
	}
	return 0;
}

static int lacp_selected_agg_update(struct lacp *lacp,
				    struct lacp_port *next_agg_lead)
{
	int err;

	if (!next_agg_lead)
		next_agg_lead = lacp_get_next_agg(lacp);
	if (lacp->selected_agg_lead != next_agg_lead)
		teamd_log_dbg("Selecting aggregator %u",
			      lacp_agg_id(next_agg_lead));
	lacp->selected_agg_lead = next_agg_lead;

	err = lacp_ports_update_enabled(lacp);
	if (err)
		return err;
	err = lacp_update_carrier(lacp);
	if (err)
		return err;
	return 0;
}

static bool lacp_port_mergeable(struct lacp_port *lacp_port)
{
	/* Port can be merged with other aggregator only in case it is
	 * alone in aggragator and is aggregable with some other port.
	 */
	return lacp_port_is_agg_lead(lacp_port) &&
	       lacp_get_agg_port_count(lacp_port) == 1 &&
	       lacp_get_agg_lead(lacp_port) != lacp_port;
}

static int lacp_port_agg_update(struct lacp_port *lacp_port)
{
	if (lacp_port_selected(lacp_port) &&
	    (lacp_port_unselectable_state(lacp_port) ||
	     !lacp_port_loopback_free(lacp_port) ||
	     !lacp_port_correct_aggregation(lacp_port) ||
	     lacp_port_mergeable(lacp_port)))
		lacp_port_agg_unselect(lacp_port);

	if (!lacp_port_selected(lacp_port) &&
	    (lacp_port_selectable_state(lacp_port) &&
	     lacp_port_loopback_free(lacp_port)))
		lacp_port_agg_select(lacp_port);

	return lacp_selected_agg_update(lacp_port->lacp, NULL);
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
	return 0;
}

static void lacp_port_actor_system_update(struct lacp_port *lacp_port)
{
	struct lacpdu_info *actor = &lacp_port->actor;

	memcpy(actor->system, lacp_port->ctx->hwaddr, ETH_ALEN);
}

static void lacp_port_actor_init(struct lacp_port *lacp_port)
{
	struct lacpdu_info *actor = &lacp_port->actor;

	actor->system_priority = htons(lacp_port->lacp->cfg.sys_prio);
	actor->key = htons(lacp_port->cfg.lacp_key);
	actor->port_priority = htons(lacp_port->cfg.lacp_prio);
	actor->port = htons(lacp_port->tdport->ifindex);
	lacp_port_actor_system_update(lacp_port);
}

static void lacp_port_actor_update(struct lacp_port *lacp_port)
{
	uint8_t state = 0;

	if (lacp_port->lacp->cfg.active)
		state |= INFO_STATE_LACP_ACTIVITY;
	if (lacp_port->lacp->cfg.fast_rate)
		state |= INFO_STATE_LACP_TIMEOUT;
	if (lacp_port_selected(lacp_port) &&
	    lacp_port_agg_selected(lacp_port)) {
		state |= INFO_STATE_SYNCHRONIZATION;
		state &= ~(INFO_STATE_COLLECTING | INFO_STATE_DISTRIBUTING);
		if (lacp_port->partner.state & INFO_STATE_SYNCHRONIZATION)
			state |= INFO_STATE_COLLECTING |
				 INFO_STATE_DISTRIBUTING;
	}
	if (lacp_port->state == PORT_STATE_EXPIRED)
		state |= INFO_STATE_EXPIRED;
	if (lacp_port->state == PORT_STATE_DEFAULTED)
		state |= INFO_STATE_DEFAULTED;
	if (teamd_port_count(lacp_port->ctx) > 0)
		state |= INFO_STATE_AGGREGATION;
	teamd_log_dbg("%s: lacp info state: 0x%02X.", lacp_port->tdport->ifname,
						      state);
	lacp_port->actor.state = state;
}

static int lacpdu_send(struct lacp_port *lacp_port);

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
		memset(&lacp_port->partner, 0, sizeof(lacp_port->partner));
		lacp_port->partner.state |= INFO_STATE_LACP_TIMEOUT;
		err = lacp_port_partner_update(lacp_port);
		if (err)
			return err;
		break;
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

	err = lacp_port_agg_update(lacp_port);
	if (err)
		return err;

	lacp_port_actor_update(lacp_port);
	if (lacp_port->periodic_on)
		return 0;
	return lacpdu_send(lacp_port);
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

	if (linkup != lacp_port->__link_last.up ||
	    duplex != lacp_port->__link_last.duplex) {
		/* If duplex is 0, meaning half-duplex, it should be set
		 * to disabled state. However some drivers, like virtio_net
		 * does not report speed and duplex. In that case, kernel
		 * will provide speed == 0 and duplex == 0. If that is the
		 * case now, do not set disabled state and allow such devices
		 * to work properly.
		 */
		if (linkup && (!duplex == !speed))
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
	char *hwaddr;
	unsigned char hwaddr_len;
	int err;
	bool admin_state;

	admin_state = team_get_ifinfo_admin_state(lacp_port->ctx->ifinfo);
	if (!admin_state)
		return 0;

	err = teamd_getsockname_hwaddr(lacp_port->sock, &ll_my, 0);
	if (err)
		return err;
	ll_slow = ll_my;
	memcpy(ll_slow.sll_addr, slow_addr, ll_slow.sll_halen);

	memcpy(lacp_port->actor.system, lacp_port->ctx->hwaddr, ETH_ALEN);

	hwaddr = team_get_ifinfo_orig_hwaddr(lacp_port->tdport->team_ifinfo);
	hwaddr_len = team_get_ifinfo_orig_hwaddr_len(lacp_port->tdport->team_ifinfo);
	if (hwaddr_len != ETH_ALEN)
		return 0;

	lacpdu_init(&lacpdu);
	lacpdu.actor = lacp_port->actor;
	lacpdu.partner = lacp_port->partner;
	memcpy(lacpdu.hdr.ether_shost, hwaddr, hwaddr_len);
	memcpy(lacpdu.hdr.ether_dhost, ll_slow.sll_addr, ll_slow.sll_halen);
	lacpdu.hdr.ether_type = htons(ETH_P_SLOW);

	err = teamd_send(lacp_port->sock, &lacpdu, sizeof(lacpdu), 0);
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

	if (!teamd_port_present(lacp_port->ctx, lacp_port->tdport))
		return 0;

	if (!lacpdu_check(&lacpdu)) {
		teamd_log_warn("malformed LACP PDU came.");
		return 0;
	}

	/* Check if we have correct info about the other side */
	if (memcmp(&lacpdu.actor, &lacp_port->partner,
		   sizeof(struct lacpdu_info))) {
		lacp_port->partner = lacpdu.actor;
		err = lacp_port_partner_update(lacp_port);
		if (err)
			return err;
		err = lacp_port_agg_update(lacp_port);
		if (err)
			return err;
	}

	if (lacp_port->partner.state & INFO_STATE_SYNCHRONIZATION)
		err = lacp_port_set_state(lacp_port, PORT_STATE_CURRENT);
	else
		err = lacp_port_set_state(lacp_port, PORT_STATE_EXPIRED);
	if (err)
		return err;

	/* Check if the other side has correct info about us */
	if (!lacp_port->periodic_on &&
	    memcmp(&lacpdu.partner, &lacp_port->actor,
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

	lacp_port_actor_update(lacp_port);
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

	err = teamd_config_int_get(ctx, &tmp,
				   "$.ports.%s.lacp_prio", port_name);
	if (err) {
		lacp_port->cfg.lacp_prio = LACP_PORT_CFG_DFLT_LACP_PRIO;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("%s: \"lacp_prio\" value is out of its limits.",
			      port_name);
		return -EINVAL;
	} else {
		lacp_port->cfg.lacp_prio = tmp;
	}
	teamd_log_dbg("%s: Using lacp_prio \"%d\".", port_name,
		      lacp_port->cfg.lacp_prio);

	err = teamd_config_int_get(ctx, &tmp,
				   "$.ports.%s.lacp_key", port_name);
	if (err) {
		lacp_port->cfg.lacp_key = LACP_PORT_CFG_DFLT_LACP_KEY;
	} else if (tmp < 0 || tmp > USHRT_MAX) {
		teamd_log_err("%s: \"lacp_key\" value is out of its limits.",
			      port_name);
		return -EINVAL;
	} else {
		lacp_port->cfg.lacp_key = tmp;
	}
	teamd_log_dbg("%s: Using lacp_key \"%d\".", port_name,
		      lacp_port->cfg.lacp_key);

	err = teamd_config_bool_get(ctx, &lacp_port->cfg.sticky,
				    "$.ports.%s.sticky", port_name);
	if (err)
		lacp_port->cfg.sticky = LACP_PORT_CFG_DFLT_STICKY;
	teamd_log_dbg("%s: Using sticky \"%d\".", port_name,
		      lacp_port->cfg.sticky);
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

	err = teamd_packet_sock_open_type(SOCK_RAW, &lacp_port->sock,
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

	/* Newly added ports are disabled */
	err = team_set_port_enabled(ctx->th, tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		if (!TEAMD_ENOENT(err))
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

static int lacp_event_watch_hwaddr_changed(struct teamd_context *ctx,
					   void *priv)
{
	struct lacp *lacp = priv;
	struct teamd_port *tdport;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		struct lacp_port *lacp_port = lacp_port_get(lacp, tdport);

		err = lacp_port_set_mac(ctx, tdport);
		if (err)
			return err;
		lacp_port_actor_system_update(lacp_port);
	}
	return 0;
}

static int lacp_event_watch_port_hwaddr_changed(struct teamd_context *ctx,
						struct teamd_port *tdport,
						void *priv)
{
	struct lacp_port *lacp_port;
	struct lacp *lacp = priv;
	int err;

	if (!teamd_port_present(ctx, tdport))
		return 0;

	if (!memcmp(team_get_ifinfo_hwaddr(tdport->team_ifinfo),
		    ctx->hwaddr, ctx->hwaddr_len))
		return 0;

	err = lacp_port_set_mac(ctx, tdport);
	if (err)
		return err;

	lacp_port = lacp_port_get(lacp, tdport);
	lacp_port_actor_system_update(lacp_port);

	return 0;
}

static int lacp_event_watch_admin_state_changed(struct teamd_context *ctx,
					        void *priv)
{
	struct lacp *lacp = priv;
	struct teamd_port *tdport;
	bool admin_state;
	int err;

	admin_state = team_get_ifinfo_admin_state(ctx->ifinfo);

	teamd_for_each_tdport(tdport, ctx) {
		struct lacp_port *lacp_port = lacp_port_get(lacp, tdport);

		err = lacp_port_set_state(lacp_port,
					  admin_state?PORT_STATE_EXPIRED:PORT_STATE_DISABLED);
		if (err)
			return err;
	}
	return 0;
}


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

static const struct teamd_event_watch_ops lacp_event_watch_ops = {
	.hwaddr_changed = lacp_event_watch_hwaddr_changed,
	.port_hwaddr_changed = lacp_event_watch_port_hwaddr_changed,
	.port_added = lacp_event_watch_port_added,
	.port_removed = lacp_event_watch_port_removed,
	.port_changed = lacp_event_watch_port_changed,
	.admin_state_changed = lacp_event_watch_admin_state_changed,
};

static int lacp_carrier_init(struct teamd_context *ctx, struct lacp *lacp)
{
	int err;

	/* initialize carrier control */
	err = team_carrier_set(ctx->th, false);
	if (err && err != -EOPNOTSUPP) {
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
	if (err && err != -EOPNOTSUPP) {
		teamd_log_err("Failed to set carrier down.");
		return err;
	}

	lacp->carrier_up = false;

	return 0;
}

static int lacp_state_active_get(struct teamd_context *ctx,
				 struct team_state_gsc *gsc,
				 void *priv)
{
	struct lacp *lacp = priv;

	gsc->data.bool_val = lacp->cfg.active;
	return 0;
}

static int lacp_state_sys_prio_get(struct teamd_context *ctx,
				   struct team_state_gsc *gsc,
				   void *priv)
{
	struct lacp *lacp = priv;

	gsc->data.int_val = lacp->cfg.sys_prio;
	return 0;
}

static int lacp_state_fast_rate_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	struct lacp *lacp = priv;

	gsc->data.bool_val = lacp->cfg.fast_rate;
	return 0;
}

static int lacp_state_select_policy_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void *priv)
{
	struct lacp *lacp = priv;

	gsc->data.str_val.ptr = lacp_get_agg_select_policy_name(lacp);
	return 0;
}

static const struct teamd_state_val lacp_state_vals[] = {
	{
		.subpath = "active",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lacp_state_active_get,
	},
	{
		.subpath = "sys_prio",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_state_sys_prio_get,
	},
	{
		.subpath = "fast_rate",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lacp_state_fast_rate_get,
	},
	{
		.subpath = "select_policy",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lacp_state_select_policy_get,
	},
};

static struct lacp_port *lacp_port_gsc(struct team_state_gsc *gsc,
				       void *priv)
{
	struct lacp *lacp = priv;

	return lacp_port_get(lacp, gsc->info.tdport);
}

static struct lacpdu_info *lacp_port_actor_gsc(struct team_state_gsc *gsc,
					       void *priv)
{
	return &lacp_port_gsc(gsc, priv)->actor;
}

static int lacp_port_actor_state_system_priority_get(struct teamd_context *ctx,
						     struct team_state_gsc *gsc,
						     void *priv)
{
	gsc->data.int_val =
		ntohs(lacp_port_actor_gsc(gsc, priv)->system_priority);
	return 0;
}

static int lacp_port_actor_state_system_get(struct teamd_context *ctx,
					    struct team_state_gsc *gsc,
					    void *priv)
{
	char *addr = (char *) lacp_port_actor_gsc(gsc, priv)->system;
	char *addr_str;

	addr_str = a_hwaddr_str(addr, ETH_ALEN);
	if (!addr_str)
		return -ENOMEM;
	gsc->data.str_val.ptr = addr_str;
	gsc->data.str_val.free = true;
	return 0;
}

static int lacp_port_actor_state_key_get(struct teamd_context *ctx,
					 struct team_state_gsc *gsc,
					 void *priv)
{
	gsc->data.int_val = ntohs(lacp_port_actor_gsc(gsc, priv)->key);
	return 0;
}

static int lacp_port_actor_state_port_priority_get(struct teamd_context *ctx,
						   struct team_state_gsc *gsc,
						   void *priv)
{
	gsc->data.int_val =
		ntohs(lacp_port_actor_gsc(gsc, priv)->port_priority);
	return 0;
}

static int lacp_port_actor_state_port_get(struct teamd_context *ctx,
					  struct team_state_gsc *gsc,
					  void *priv)
{
	gsc->data.int_val = ntohs(lacp_port_actor_gsc(gsc, priv)->port);
	return 0;
}

static int lacp_port_actor_state_state_get(struct teamd_context *ctx,
					   struct team_state_gsc *gsc,
					   void *priv)
{
	gsc->data.int_val = lacp_port_actor_gsc(gsc, priv)->state;
	return 0;
}

static const struct teamd_state_val lacp_port_actor_state_vals[] = {
	{
		.subpath = "system_priority",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_actor_state_system_priority_get,
	},
	{
		.subpath = "system",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lacp_port_actor_state_system_get,
	},
	{
		.subpath = "key",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_actor_state_key_get,
	},
	{
		.subpath = "port_priority",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_actor_state_port_priority_get,
	},
	{
		.subpath = "port",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_actor_state_port_get,
	},
	{
		.subpath = "state",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_actor_state_state_get,
	},
};

static struct lacpdu_info *lacp_port_partner_gsc(struct team_state_gsc *gsc,
						 void *priv)
{
	return &lacp_port_gsc(gsc, priv)->partner;
}

static int lacp_port_partner_state_system_priority_get(struct teamd_context *ctx,
						       struct team_state_gsc *gsc,
						       void *priv)
{
	gsc->data.int_val =
		ntohs(lacp_port_partner_gsc(gsc, priv)->system_priority);
	return 0;
}

static int lacp_port_partner_state_system_get(struct teamd_context *ctx,
					      struct team_state_gsc *gsc,
					      void *priv)
{
	char *addr = (char *) lacp_port_partner_gsc(gsc, priv)->system;
	char *addr_str;

	addr_str = a_hwaddr_str(addr, ETH_ALEN);
	if (!addr_str)
		return -ENOMEM;
	gsc->data.str_val.ptr = addr_str;
	gsc->data.str_val.free = true;
	return 0;
}

static int lacp_port_partner_state_key_get(struct teamd_context *ctx,
					   struct team_state_gsc *gsc,
					   void *priv)
{
	gsc->data.int_val = ntohs(lacp_port_partner_gsc(gsc, priv)->key);
	return 0;
}

static int lacp_port_partner_state_port_priority_get(struct teamd_context *ctx,
						     struct team_state_gsc *gsc,
						     void *priv)
{
	gsc->data.int_val =
		ntohs(lacp_port_partner_gsc(gsc, priv)->port_priority);
	return 0;
}

static int lacp_port_partner_state_port_get(struct teamd_context *ctx,
					    struct team_state_gsc *gsc,
					    void *priv)
{
	gsc->data.int_val = ntohs(lacp_port_partner_gsc(gsc, priv)->port);
	return 0;
}

static int lacp_port_partner_state_state_get(struct teamd_context *ctx,
					     struct team_state_gsc *gsc,
					     void *priv)
{
	gsc->data.int_val = lacp_port_partner_gsc(gsc, priv)->state;
	return 0;
}

static const struct teamd_state_val lacp_port_partner_state_vals[] = {
	{
		.subpath = "system_priority",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_partner_state_system_priority_get,
	},
	{
		.subpath = "system",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lacp_port_partner_state_system_get,
	},
	{
		.subpath = "key",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_partner_state_key_get,
	},
	{
		.subpath = "port_priority",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_partner_state_port_priority_get,
	},
	{
		.subpath = "port",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_partner_state_port_get,
	},
	{
		.subpath = "state",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_partner_state_state_get,
	},
};

static int lacp_port_state_selected_get(struct teamd_context *ctx,
					struct team_state_gsc *gsc,
					void *priv)
{
	gsc->data.bool_val = lacp_port_selected(lacp_port_gsc(gsc, priv));
	return 0;
}

static int lacp_port_state_aggregator_id_get(struct teamd_context *ctx,
					     struct team_state_gsc *gsc,
					     void *priv)
{
	gsc->data.int_val = lacp_port_agg_id(lacp_port_gsc(gsc, priv));
	return 0;
}

static int lacp_port_state_aggregator_selected_get(struct teamd_context *ctx,
						   struct team_state_gsc *gsc,
						   void *priv)
{
	gsc->data.bool_val = lacp_port_agg_selected(lacp_port_gsc(gsc, priv));
	return 0;
}

struct lacp_port_selected_set_info {
	struct teamd_workq workq;
	struct lacp *lacp;
	uint32_t ifindex;
};

static int lacp_port_aggregator_select_work(struct teamd_context *ctx,
					    struct teamd_workq *workq)
{
	struct lacp_port_selected_set_info *info;
	struct teamd_port *tdport;
	struct lacp *lacp;
	struct lacp_port *lacp_port;

	info = get_container(workq, struct lacp_port_selected_set_info, workq);
	lacp = info->lacp;
	tdport = teamd_get_port(ctx, info->ifindex);
	free(info);
	if (!tdport)
		/* Port disapeared in between, ignore */
		return 0;
	lacp_port = lacp_port_get(lacp, tdport);
	if (!lacp_port_selected(lacp_port))
		return 0;
	return lacp_selected_agg_update(lacp_port->lacp, lacp_port->agg_lead);
}

static int lacp_port_state_aggregator_selected_set(struct teamd_context *ctx,
						   struct team_state_gsc *gsc,
						   void *priv)
{
	struct lacp_port_selected_set_info *info;
	struct lacp *lacp = priv;

	if (!gsc->data.bool_val)
		return -EOPNOTSUPP;
	if (!lacp_port_selected(lacp_port_gsc(gsc, priv)))
		return -EINVAL;
	info = malloc(sizeof(*info));
	if (!info)
		return -ENOMEM;
	teamd_workq_init_work(&info->workq, lacp_port_aggregator_select_work);
	info->lacp = lacp;
	info->ifindex = gsc->info.tdport->ifindex;
	teamd_workq_schedule_work(ctx, &info->workq);
	return 0;
}

static int lacp_port_state_state_get(struct teamd_context *ctx,
				     struct team_state_gsc *gsc,
				     void *priv)
{
	gsc->data.str_val.ptr =
		lacp_port_state_name[lacp_port_gsc(gsc, priv)->state];
	return 0;
}

static int lacp_port_state_key_get(struct teamd_context *ctx,
				   struct team_state_gsc *gsc,
				   void *priv)
{
	gsc->data.int_val = lacp_port_gsc(gsc, priv)->cfg.lacp_key;
	return 0;
}

static int lacp_port_state_prio_get(struct teamd_context *ctx,
				    struct team_state_gsc *gsc,
				    void *priv)
{
	gsc->data.int_val = lacp_port_gsc(gsc, priv)->cfg.lacp_prio;
	return 0;
}

static const struct teamd_state_val lacp_port_state_vals[] = {
	{
		.subpath = "selected",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lacp_port_state_selected_get,
	},
	{
		.subpath = "aggregator.id",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_state_aggregator_id_get,
	},
	{
		.subpath = "aggregator.selected",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lacp_port_state_aggregator_selected_get,
		.setter = lacp_port_state_aggregator_selected_set,
	},
	{
		.subpath = "state",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lacp_port_state_state_get,
	},
	{
		.subpath = "key",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_state_key_get,
	},
	{
		.subpath = "prio",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lacp_port_state_prio_get,
	},
	{
		.subpath = "actor_lacpdu_info",
		.vals = lacp_port_actor_state_vals,
		.vals_count = ARRAY_SIZE(lacp_port_actor_state_vals),
	},
	{
		.subpath = "partner_lacpdu_info",
		.vals = lacp_port_partner_state_vals,
		.vals_count = ARRAY_SIZE(lacp_port_partner_state_vals),
	},
};

static const struct teamd_state_val lacp_state_vgs[] = {
	{
		.subpath = "runner",
		.vals = lacp_state_vals,
		.vals_count = ARRAY_SIZE(lacp_state_vals),
	},
	{
		.subpath = "runner",
		.vals = lacp_port_state_vals,
		.vals_count = ARRAY_SIZE(lacp_port_state_vals),
		.per_port = true,
	},
};

static const struct teamd_state_val lacp_state_vg = {
	.vals = lacp_state_vgs,
	.vals_count = ARRAY_SIZE(lacp_state_vgs),
};

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
	err = teamd_event_watch_register(ctx, &lacp_event_watch_ops, lacp);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	err = teamd_balancer_init(ctx, &lacp->tb);
	if (err) {
		teamd_log_err("Failed to init balanced.");
		goto event_watch_unregister;
	}
	err = teamd_state_val_register(ctx, &lacp_state_vg, lacp);
	if (err) {
		teamd_log_err("Failed to register state groups.");
		goto balancer_fini;
	}
	return 0;

balancer_fini:
	teamd_balancer_fini(lacp->tb);
event_watch_unregister:
	teamd_event_watch_unregister(ctx, &lacp_event_watch_ops, lacp);
	return err;
}

static void lacp_fini(struct teamd_context *ctx, void *priv)
{
	struct lacp *lacp = priv;

	teamd_state_val_unregister(ctx, &lacp_state_vg, lacp);
	teamd_balancer_fini(lacp->tb);
	teamd_event_watch_unregister(ctx, &lacp_event_watch_ops, lacp);
	lacp_carrier_fini(ctx, lacp);
}

const struct teamd_runner teamd_runner_lacp = {
	.name			= "lacp",
	.team_mode_name		= "loadbalance",
	.priv_size		= sizeof(struct lacp),
	.init			= lacp_init,
	.fini			= lacp_fini,
};
