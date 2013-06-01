/*
 *   ports.c - Wrapper for team generic netlink port-related communication
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
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <linux/netdevice.h>
#include <linux/if_team.h>
#include <linux/types.h>
#include <team.h>
#include <private/list.h>
#include <private/misc.h>
#include "team_private.h"

struct team_port {
	struct list_item	list;
	uint32_t		ifindex;
	uint32_t		speed;
	uint8_t			duplex;
	bool			linkup;
	bool			changed;
	bool			removed;
	unsigned char		orig_hwaddr_len;
	char			orig_hwaddr[MAX_ADDR_LEN];
	struct team_ifinfo *	ifinfo;
};

static struct team_port *port_create(struct team_handle *th,
				     uint32_t ifindex)
{
	struct team_port *port;
	int err;

	port = myzalloc(sizeof(struct team_port));
	if (!port) {
		err(th, "Malloc failed.");
		return NULL;
	}
	err = ifinfo_create(th, ifindex, port, &port->ifinfo);
	if (err) {
		err(th, "Failed to create ifinfo.");
		free(port);
		return NULL;
	}
	port->ifindex = ifindex;
	list_add(&th->port_list, &port->list);
	return port;
}

static void port_destroy(struct team_handle *th,
			 struct team_port *port)
{
	ifinfo_destroy(th, port->ifindex);
	list_del(&port->list);
	free(port);
}

static void flush_port_list(struct team_handle *th)
{
	struct team_port *port, *tmp;

	list_for_each_node_entry_safe(port, tmp, &th->port_list, list)
		port_destroy(th, port);
}

static void port_list_cleanup_last_state(struct team_handle *th)
{
	struct team_port *port;

	list_for_each_node_entry(port, &th->port_list, list) {
		port->changed = false;
		if (port->removed)
			port_destroy(th, port);
	}
}

static struct team_port *find_port(struct team_handle *th, uint32_t ifindex)
{
	struct team_port *port;

	list_for_each_node_entry(port, &th->port_list, list)
		if (port->ifindex == ifindex)
			return port;
	return NULL;
}

int get_port_list_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct team_handle *th = arg;
	struct nlattr *attrs[TEAM_ATTR_MAX + 1];
	struct nlattr *nl_port;
	struct nlattr *port_attrs[TEAM_ATTR_PORT_MAX + 1];
	int i;
	uint32_t team_ifindex = 0;

	genlmsg_parse(nlh, 0, attrs, TEAM_ATTR_MAX, NULL);
	if (attrs[TEAM_ATTR_TEAM_IFINDEX])
		team_ifindex = nla_get_u32(attrs[TEAM_ATTR_TEAM_IFINDEX]);

	if (team_ifindex != th->ifindex)
		return NL_SKIP;

	if (!attrs[TEAM_ATTR_LIST_PORT])
		return NL_SKIP;

	if (!th->msg_recv_started) {
		port_list_cleanup_last_state(th);
		th->msg_recv_started = true;
	}
	nla_for_each_nested(nl_port, attrs[TEAM_ATTR_LIST_PORT], i) {
		struct team_port *port;
		uint32_t ifindex;

		if (nla_parse_nested(port_attrs, TEAM_ATTR_PORT_MAX,
				     nl_port, NULL)) {
			err(th, "Failed to parse nested attributes.");
			return NL_SKIP;
		}

		if (!port_attrs[TEAM_ATTR_PORT_IFINDEX]) {
			err(th, "ifindex port attribute not found.");
			return NL_SKIP;
		}

		ifindex = nla_get_u32(port_attrs[TEAM_ATTR_PORT_IFINDEX]);
		port = find_port(th, ifindex);
		if (!port) {
			port = port_create(th, ifindex);
			if (!port)
				return NL_SKIP;
		}
		port->changed = port_attrs[TEAM_ATTR_PORT_CHANGED] ? true : false;
		port->linkup = port_attrs[TEAM_ATTR_PORT_LINKUP] ? true : false;
		port->removed = port_attrs[TEAM_ATTR_PORT_REMOVED] ? true : false;
		if (port_attrs[TEAM_ATTR_PORT_SPEED])
			port->speed = nla_get_u32(port_attrs[TEAM_ATTR_PORT_SPEED]);
		if (port_attrs[TEAM_ATTR_PORT_DUPLEX])
			port->duplex = nla_get_u8(port_attrs[TEAM_ATTR_PORT_DUPLEX]);
		if (port_attrs[TEAM_ATTR_PORT_ORIG_ADDR] &&
		    port_attrs[TEAM_ATTR_PORT_ORIG_ADDR_LEN]) {
			port->orig_hwaddr_len = nla_get_u8(port_attrs[TEAM_ATTR_PORT_ORIG_ADDR_LEN]);
			memcpy(port->orig_hwaddr,
			       nla_data(port_attrs[TEAM_ATTR_PORT_ORIG_ADDR]),
			       port->orig_hwaddr_len);
		}
	}

	set_call_change_handlers(th, TEAM_PORT_CHANGE);
	return NL_SKIP;
}

static int get_port_list(struct team_handle *th)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, th->family, 0, 0,
			 TEAM_CMD_PORT_LIST_GET, 0);
	NLA_PUT_U32(msg, TEAM_ATTR_TEAM_IFINDEX, th->ifindex);

	err = send_and_recv(th, msg, get_port_list_handler, th);
	if (err)
		return err;

	return check_call_change_handlers(th, TEAM_PORT_CHANGE);

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

int port_list_alloc(struct team_handle *th)
{
	list_init(&th->port_list);

	return 0;
}

int port_list_init(struct team_handle *th)
{
	int err;

	err = get_port_list(th);
	if (err) {
		err(th, "Failed to get port list.");
		return err;
	}
	return 0;
}

void port_list_free(struct team_handle *th)
{
	flush_port_list(th);
}

/**
 * team_get_next_port:
 * @th: libteam library context
 * @port: port structure
 *
 * Get next port in list.
 *
 * Returns: port next to @port passed.
 **/
TEAM_EXPORT
struct team_port *team_get_next_port(struct team_handle *th,
				     struct team_port *port)
{
	return list_get_next_node_entry(&th->port_list, port, list);
}

/**
 * team_get_port_ifindex:
 * @port: port structure
 *
 * Get port interface index.
 *
 * Returns: port interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
uint32_t team_get_port_ifindex(struct team_port *port)
{
	return port->ifindex;
}

/**
 * team_get_port_speed:
 * @port: port structure
 *
 * Get port speed.
 *
 * Returns: port speed in Mbits/s.
 **/
TEAM_EXPORT
uint32_t team_get_port_speed(struct team_port *port)
{
	return port->speed;
}

/**
 * team_get_port_duplex:
 * @port: port structure
 *
 * Get port duplex.
 *
 * Returns: 0 = half-duplex, 1 = full-duplex
 **/
TEAM_EXPORT
uint8_t team_get_port_duplex(struct team_port *port)
{
	return port->duplex;
}

/**
 * team_is_port_link_up:
 * @port: port structure
 *
 * See if port link is up.
 *
 * Returns: true if port link is up.
 **/
TEAM_EXPORT
bool team_is_port_link_up(struct team_port *port)
{
	return port->linkup;
}

/**
 * team_is_port_changed:
 * @port: port structure
 *
 * See if port values got changed.
 *
 * Returns: true if port got changed.
 **/
TEAM_EXPORT
bool team_is_port_changed(struct team_port *port)
{
	return port->changed;
}

/**
 * team_is_port_removed:
 * @port: port structure
 *
 * See if port was removed.
 *
 * Returns: true if port was removed.
 **/
TEAM_EXPORT
bool team_is_port_removed(struct team_port *port)
{
	return port->removed;
}

/**
 * team_get_port_ifinfo:
 * @port: port structure
 *
 * Get port rtnetlink interface info.
 *
 * Returns: pointer to appropriate team_ifinfo structure.
 **/
TEAM_EXPORT
struct team_ifinfo *team_get_port_ifinfo(struct team_port *port)
{
	return port->ifinfo;
}

/**
 * team_is_port_present:
 * @th: libteam library context
 * @port: port structure
 *
 * See if port is actually present in this team.
 *
 * Returns: true if port is present at a moment.
 **/
TEAM_EXPORT
bool team_is_port_present(struct team_handle *th, struct team_port *port)
{
	struct team_ifinfo *ifinfo = team_get_port_ifinfo(port);

	return team_get_ifinfo_master_ifindex(ifinfo) == th->ifindex &&
	       !team_is_port_removed(port);
}

/**
 * team_get_port_orig_hwaddr:
 * @port: port structure
 *
 * Get port original hardware address.
 *
 * Returns: pointer to address.
 **/
TEAM_EXPORT
const char *team_get_port_orig_hwaddr(struct team_port *port)
{
	return port->orig_hwaddr;
}

/**
 * team_get_port_orig_hwaddr_len:
 * @port: port structure
 *
 * Get port length original hardware address.
 *
 * Returns: address length.
 **/
TEAM_EXPORT
uint8_t team_get_port_orig_hwaddr_len(struct team_port *port)
{
	return port->orig_hwaddr_len;
}
