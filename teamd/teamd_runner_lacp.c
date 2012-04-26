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

struct lacp {
	struct teamd_context *ctx;
	struct {
		bool active;
#define		LACP_CFG_DFLT_ACTIVE true
		uint16_t sys_prio;
#define		LACP_CFG_DFLT_SYS_PRIO 0xffff
		bool fast_rate;
#define		LACP_CFG_DFLT_FAST_RATE false
	} cfg;
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
	char *cb_name_socket;
	char *cb_name_periodic;
	char *cb_name_timeout;
	struct lacpdu_info actor;
	struct lacpdu_info partner;
	struct lacpdu_info __partner_last; /* last state before update */
	bool selected;
	bool __selected_last;
	enum lacp_port_state state;
	struct {
		uint32_t speed;
		uint8_t	duplex;
		bool up;
	} __link_last;
};

static int lacp_load_config(struct teamd_context *ctx, struct lacp *lacp)
{
	int err;
	int tmp;

	err = json_unpack(ctx->config_json, "{s:{s:i}}", "runner", "active",
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

	err = json_unpack(ctx->config_json, "{s:{s:i}}", "runner", "fast_rate",
			  &tmp);
	lacp->cfg.fast_rate = err ? LACP_CFG_DFLT_FAST_RATE : !!tmp;
	teamd_log_dbg("Using fast_rate \"%d\".", lacp->cfg.fast_rate);
	return 0;
}

static int lacp_port_link_update(struct lacp_port *lacp_port);

static int lacp_port_change_handler_func(struct team_handle *th, void *arg,
					 team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = team_get_user_priv(th);
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	int err;

	teamd_for_each_tdport(tdport, ctx) {
		if (team_is_port_changed(tdport->team_port)) {
			lacp_port = teamd_get_runner_port_priv(tdport);
			err = lacp_port_link_update(lacp_port);
			if (err)
				return err;
		}
	}
	return 0;
}

static struct team_change_handler lacp_port_change_handler = {
	.func = lacp_port_change_handler_func,
	.type_mask = TEAM_PORT_CHANGE,
};

static int lacp_init(struct teamd_context *ctx)
{
	struct lacp *lacp = ctx->runner_priv;
	int err;

	lacp->ctx = ctx;
	err = teamd_hash_func_set(ctx);
	if (err)
		return err;
	err = lacp_load_config(ctx, lacp);
	if (err) {
		teamd_log_err("Failed to load config values.");
		return err;
	}
	err = team_change_handler_register(ctx->th, &lacp_port_change_handler);
	if (err) {
		teamd_log_err("Failed to register change handler.");
		return err;
	}
	return 0;
}

static void lacp_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th, &lacp_port_change_handler);
}

static bool lacp_port_selectable(struct lacp_port *lacp_port)
{
	if (lacp_port->selected)
		return false;
	if (lacp_port->state == PORT_STATE_CURRENT ||
	    lacp_port->state == PORT_STATE_EXPIRED)
		return true;
	return false;
}

static int lacp_port_update_selected(struct lacp_port *lacp_port)
{
	struct teamd_port *tdport = lacp_port->tdport;
	int err;

	if (lacp_port->selected == lacp_port->__selected_last)
		return 0;

	teamd_log_dbg("%s: %s port.", tdport->ifname,
		      lacp_port->selected ? "Enabling": "Disabling");
	err = team_set_port_option_value_by_name_bool(lacp_port->ctx->th,
						      "enabled",
						      tdport->ifindex,
						      lacp_port->selected);
	if (err) {
		teamd_log_err("%s: Failed to %s port.", tdport->ifname,
			      lacp_port->selected ? "enable": "disable");
		return err;;
	}
	lacp_port->__selected_last = lacp_port->selected;
	return 0;
}

static bool lacp_ports_aggregable(struct lacp_port *lacp_port1,
				  struct lacp_port *lacp_port2)
{
	if (lacp_port1->partner.key != lacp_port2->partner.key)
		return false;
	if (memcmp(lacp_port1->partner.system,
		   lacp_port2->partner.system, ETH_ALEN))
		return false;
	return true;
}

static struct lacp_port *lacp_get_best_port(struct lacp *lacp)
{
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;

	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = teamd_get_runner_port_priv(tdport);
		if (!lacp_port_selectable(lacp_port))
			continue;
		/*
		 * Take the first which has partner for now. This needs
		 * to be improved!!!
		 */
		return lacp_port;
	}
	return NULL;
}

static int lacp_update_selected(struct lacp *lacp)
{
	struct lacp_port *best_lacp_port;
	struct teamd_port *tdport;
	struct lacp_port *lacp_port;
	int err;

	/*
	 * First, unselect all so they will be all free to aggrerate with
	 * each other.
	 */
	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = teamd_get_runner_port_priv(tdport);
		lacp_port->__selected_last = lacp_port->selected;
		lacp_port->selected = false;
	}

	best_lacp_port = lacp_get_best_port(lacp);
	teamd_for_each_tdport(tdport, lacp->ctx) {
		lacp_port = teamd_get_runner_port_priv(tdport);
		if (lacp_port_selectable(lacp_port) &&
		    best_lacp_port &&
		    lacp_ports_aggregable(lacp_port, best_lacp_port)) {
			lacp_port->selected = true;
		}
		err = lacp_port_update_selected(lacp_port);
		if (err)
			return err;
	}
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
					    lacp_port->cb_name_timeout,
					    NULL, &ts);
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
					    lacp_port->cb_name_periodic,
					    &ts, NULL);
	if (err) {
		teamd_log_err("Failed to set periodic timer.");
		return err;
	}
	return 0;
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
	lacp_port->__partner_last = lacp_port->partner;
	return lacp_update_selected(lacp_port->lacp);
}

static void lacp_port_actor_init(struct lacp_port *lacp_port)
{
	struct lacpdu_info *actor = &lacp_port->actor;

	actor->system_priority = htons(lacp_port->lacp->cfg.sys_prio);
        actor->key = htons(0x00);
        actor->port_priority = htons(0xff);
	actor->port = htons(lacp_port->tdport->ifindex);
}

static int lacpdu_send(struct lacp_port *lacp_port);

static int lacp_port_actor_update(struct lacp_port *lacp_port)
{
	struct lacpdu_info *actor = &lacp_port->actor;
	int err;
	uint8_t state = 0;

	memcpy(actor->system, lacp_port->ctx->hwaddr, ETH_ALEN);
	if (lacp_port->lacp->cfg.active)
		state |= INFO_STATE_LACP_ACTIVITY;
	if (lacp_port->lacp->cfg.fast_rate)
		state |= INFO_STATE_LACP_TIMEOUT;
	if (lacp_port->selected) {
		state |= INFO_STATE_SYNCHRONIZATION;
		state |= INFO_STATE_COLLECTING | INFO_STATE_DISTRIBUTING;
	}
	if (lacp_port->state == PORT_STATE_EXPIRED)
		state |= INFO_STATE_EXPIRED;
	if (lacp_port->state == PORT_STATE_DEFAULTED)
		state |= INFO_STATE_DEFAULTED;
	if (1) /* !!!!!!!!!!!!!!!!!!!!!!!!!!!!!*/
		state |= INFO_STATE_AGGREGATION;
	teamd_log_dbg("%s: lacp info state: 0x%02X.", lacp_port->tdport->ifname,
						      state);
	actor->state = state;
	err = lacp_update_selected(lacp_port->lacp);
	if (err)
		return err;
	return lacpdu_send(lacp_port);
}

static int lacp_port_set_state(struct lacp_port *lacp_port,
			       enum lacp_port_state new_state)
{
	int err;

	if (new_state == lacp_port->state)
		return 0;
	if (new_state == PORT_STATE_DISABLED)
		teamd_loop_callback_disable(lacp_port->ctx,
					    lacp_port->cb_name_periodic);
	else
		teamd_loop_callback_enable(lacp_port->ctx,
					   lacp_port->cb_name_periodic);

	switch(new_state) {
	case PORT_STATE_CURRENT:
		break;
	case PORT_STATE_EXPIRED:
		teamd_loop_callback_enable(lacp_port->ctx,
					   lacp_port->cb_name_periodic);
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
		break;
	case PORT_STATE_DEFAULTED:
		teamd_loop_callback_disable(lacp_port->ctx,
					    lacp_port->cb_name_timeout);
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
	int ret;

	err = teamd_getsockname_hwaddr(lacp_port->sock, &ll_my, 0);
	if (err)
		return err;
	ll_slow = ll_my;
	memcpy(ll_slow.sll_addr, slow_addr, ll_slow.sll_halen);

	lacpdu_init(&lacpdu);
	lacpdu.actor = lacp_port->actor;
	lacpdu.partner = lacp_port->partner;

	ret = sendto(lacp_port->sock, &lacpdu, sizeof(lacpdu), 0,
		     (struct sockaddr *) &ll_slow, sizeof(ll_slow));
	if (ret == -1) {
		teamd_log_warn("sendto failed. %s", strerror(errno));
		return 0;
	}
	return 0;
}

static int lacpdu_recv(struct lacp_port *lacp_port)
{
	struct lacpdu lacpdu;
	socklen_t addr_len;
	struct sockaddr_ll ll_from;
	int err;
	int ret;

	ret = recvfrom(lacp_port->sock, &lacpdu, sizeof(lacpdu), 0,
		       (struct sockaddr *) &ll_from, &addr_len);
	if (ret == -1) {
		teamd_log_warn("recvfrom failed. %s", strerror(errno));
		return 0;
	}

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
	teamd_loop_callback_enable(lacp_port->ctx, lacp_port->cb_name_timeout);
	return 0;
}

static int lacp_callback_timeout(struct teamd_context *ctx, int events,
				 void *func_priv)
{
	struct lacp_port *lacp_port = func_priv;
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
				  void *func_priv)
{
	struct lacp_port *lacp_port = func_priv;

	return lacpdu_send(lacp_port);
}

static int lacp_callback_socket(struct teamd_context *ctx, int events,
				void *func_priv)
{
	struct lacp_port *lacp_port = func_priv;

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

static int lacp_port_added(struct teamd_context *ctx,
			   struct teamd_port *tdport)
{
	struct lacp_port *lacp_port = teamd_get_runner_port_priv(tdport);
	struct lacp *lacp = ctx->runner_priv;
	int err;

	lacp_port->ctx = ctx;
	lacp_port->tdport = tdport;
	lacp_port->lacp = lacp;

	err = teamd_packet_sock_open(&lacp_port->sock,
				     tdport->ifindex,
				     htons(ETH_P_SLOW), NULL);
	if (err)
		return err;

	err = slow_addr_add(lacp_port);
	if (err)
		goto close_sock;

	err = asprintf(&lacp_port->cb_name_socket, "lacp_socket_if%d",
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate socket callback name.");
		err = -ENOMEM;
		goto slow_addr_del;
	}
	err = teamd_loop_callback_fd_add(ctx, lacp_port->cb_name_socket,
					 lacp_port->sock,
					 TEAMD_LOOP_FD_EVENT_READ,
					 lacp_callback_socket, lacp_port);
	if (err) {
		teamd_log_err("Failed add socket callback.");
		goto free_cb_name_socket;
	}

	err = asprintf(&lacp_port->cb_name_periodic, "lacp_periodic_if%d",
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate periodic callback name.");
		err = -ENOMEM;
		goto socket_callback_del;
	}
	err = teamd_loop_callback_timer_add(ctx, lacp_port->cb_name_periodic,
					    lacp_callback_periodic,
					    lacp_port);
	if (err) {
		teamd_log_err("Failed add periodic callback timer");
		goto free_periodic_cb_name;
	}
	err = lacp_port_periodic_set(lacp_port);
	if (err)
		goto periodic_callback_del;

	err = asprintf(&lacp_port->cb_name_timeout, "lacp_timeout_if%d",
		       tdport->ifindex);
	if (err == -1) {
		teamd_log_err("Failed generate timeout callback name.");
		err = -ENOMEM;
		goto periodic_callback_del;
	}
	err = teamd_loop_callback_timer_add(ctx, lacp_port->cb_name_timeout,
					    lacp_callback_timeout,
					    lacp_port);
	if (err) {
		teamd_log_err("Failed add timeout callback timer");
		goto free_timeout_cb_name;
	}

	/* Newly added ports are disabled */
	err = team_set_port_option_value_by_name_bool(ctx->th, "enabled",
						      tdport->ifindex, false);
	if (err) {
		teamd_log_err("%s: Failed to disable port.", tdport->ifname);
		goto timeout_callback_del;
	}

	err = lacp_port_set_mac(ctx, tdport);
	if (err)
		goto timeout_callback_del;

	lacp_port_actor_init(lacp_port);
	lacp_port_link_update(lacp_port);

	teamd_loop_callback_enable(ctx, lacp_port->cb_name_socket);
	return 0;

timeout_callback_del:
	teamd_loop_callback_del(ctx, lacp_port->cb_name_timeout);
free_timeout_cb_name:
	free(lacp_port->cb_name_timeout);
periodic_callback_del:
	teamd_loop_callback_del(ctx, lacp_port->cb_name_periodic);
free_periodic_cb_name:
	free(lacp_port->cb_name_periodic);
socket_callback_del:
	teamd_loop_callback_del(ctx, lacp_port->cb_name_socket);
free_cb_name_socket:
	free(lacp_port->cb_name_socket);
slow_addr_del:
	slow_addr_del(lacp_port);
close_sock:
	close(lacp_port->sock);
	return 0;
}

static void lacp_port_removed(struct teamd_context *ctx,
			      struct teamd_port *tdport)
{
	struct lacp_port *lacp_port = teamd_get_runner_port_priv(tdport);

	lacp_port_set_state(lacp_port, PORT_STATE_DISABLED);
	teamd_loop_callback_del(ctx, lacp_port->cb_name_periodic);
	free(lacp_port->cb_name_periodic);
	teamd_loop_callback_del(ctx, lacp_port->cb_name_socket);
	free(lacp_port->cb_name_socket);
	slow_addr_del(lacp_port);
	close(lacp_port->sock);
}

const struct teamd_runner teamd_runner_lacp = {
	.name		= "lacp",
	.team_mode_name	= "loadbalance",
	.init		= lacp_init,
	.fini		= lacp_fini,
	.priv_size	= sizeof(struct lacp),
	.port_added	= lacp_port_added,
	.port_removed	= lacp_port_removed,
	.port_priv_size = sizeof(struct lacp_port),
};
