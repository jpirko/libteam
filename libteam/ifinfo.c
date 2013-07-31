/*
 *   ifinfo.c - Wrapper for rtnetlink interface info
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
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <team.h>
#include <private/list.h>
#include <private/misc.h>
#include "team_private.h"

struct team_ifinfo {
	struct list_item	list;
	bool			linked;
	uint32_t		ifindex;
	struct team_port *	port; /* NULL if device is not team port */
	char			hwaddr[MAX_ADDR_LEN];
	size_t			hwaddr_len;
	char			orig_hwaddr[MAX_ADDR_LEN];
	size_t			orig_hwaddr_len;
	char			ifname[IFNAMSIZ];
	uint32_t		master_ifindex;
	int			changed;
};

#define CHANGED_HWADDR		(1 << 0)
#define CHANGED_HWADDR_LEN	(1 << 1)
#define CHANGED_IFNAME		(1 << 2)
#define CHANGED_MASTER_IFINDEX	(1 << 3)
#define CHANGED_ANY		(CHANGED_HWADDR | CHANGED_HWADDR_LEN |	\
				 CHANGED_IFNAME | CHANGED_MASTER_IFINDEX)

static void set_changed(struct team_ifinfo *ifinfo, int bit)
{
	ifinfo->changed |= bit;
}

static bool is_changed(struct team_ifinfo *ifinfo, int bit)
{
	return ifinfo->changed & bit ? true: false;
}

static void clear_changed(struct team_ifinfo *ifinfo)
{
	ifinfo->changed = 0;
}

static void update_hwaddr(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	struct nl_addr *nl_addr;
	char *hwaddr;
	size_t hwaddr_len;

	nl_addr = rtnl_link_get_addr(link);
	if (!nl_addr)
		return;

	hwaddr_len = nl_addr_get_len(nl_addr);
	if (ifinfo->hwaddr_len != hwaddr_len) {
		ifinfo->hwaddr_len = hwaddr_len;
		if (!ifinfo->master_ifindex)
			ifinfo->orig_hwaddr_len = hwaddr_len;
		set_changed(ifinfo, CHANGED_HWADDR_LEN);
	}
	hwaddr = nl_addr_get_binary_addr(nl_addr);
	if (memcmp(ifinfo->hwaddr, hwaddr, hwaddr_len)) {
		memcpy(ifinfo->hwaddr, hwaddr, hwaddr_len);
		if (!ifinfo->master_ifindex)
			memcpy(ifinfo->orig_hwaddr, hwaddr, hwaddr_len);
		set_changed(ifinfo, CHANGED_HWADDR);
	}
}

static void update_ifname(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	char *ifname;

	ifname = rtnl_link_get_name(link);
	if (ifname && strcmp(ifinfo->ifname, ifname)) {
		mystrlcpy(ifinfo->ifname, ifname, sizeof(ifinfo->ifname));
		set_changed(ifinfo, CHANGED_IFNAME);
	}
}

static void update_master(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	uint32_t master_ifindex;

	master_ifindex = rtnl_link_get_master(link);
	if (ifinfo->master_ifindex != master_ifindex) {
		ifinfo->master_ifindex = master_ifindex;
		set_changed(ifinfo, CHANGED_MASTER_IFINDEX);
	}
}

static void ifinfo_update(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	update_ifname(ifinfo, link);
	update_master(ifinfo, link);
	update_hwaddr(ifinfo, link);
}

static struct team_ifinfo *ifinfo_find(struct team_handle *th, uint32_t ifindex)
{
	struct team_ifinfo *ifinfo;

	list_for_each_node_entry(ifinfo, &th->ifinfo_list, list) {
		if (ifinfo->ifindex == ifindex)
			return ifinfo;
	}
	return NULL;
}

static void clear_last_changed(struct team_handle *th)
{
	struct team_ifinfo *ifinfo;

	list_for_each_node_entry(ifinfo, &th->ifinfo_list, list)
		clear_changed(ifinfo);
}

static struct team_ifinfo *ifinfo_find_create(struct team_handle *th,
					      uint32_t ifindex)
{
	struct team_ifinfo *ifinfo;

	ifinfo = ifinfo_find(th, ifindex);
	if (ifinfo)
		return ifinfo;

	ifinfo = myzalloc(sizeof(*ifinfo));
	if (!ifinfo)
		return NULL;

	ifinfo->ifindex = ifindex;
	list_add(&th->ifinfo_list, &ifinfo->list);
	return ifinfo;
}

static void obj_input(struct nl_object *obj, void *arg, bool getlink)
{
	struct team_handle *th = arg;
	struct rtnl_link *link;
	struct team_ifinfo *ifinfo;
	uint32_t ifindex;
	int err;

	if (nl_object_get_msgtype(obj) != RTM_NEWLINK)
		return;
	link = (struct rtnl_link *) obj;

	ifindex = rtnl_link_get_ifindex(link);
	ifinfo = ifinfo_find_create(th, ifindex);
	if (!ifinfo)
		return;

	if (getlink) {
		err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
		if (err)
			return;
	}

	clear_last_changed(th);
	ifinfo_update(ifinfo, link);

	if (getlink)
		rtnl_link_put(link);

	if (ifinfo->changed)
		set_call_change_handlers(th, TEAM_IFINFO_CHANGE);
}

static void event_handler_obj_input(struct nl_object *obj, void *arg)
{
	return obj_input(obj, arg, true);
}

int ifinfo_event_handler(struct nl_msg *msg, void *arg)
{
	struct team_handle *th = arg;

	if (nl_msg_parse(msg, &event_handler_obj_input, th) < 0)
		err(th, "Unknown message type.");
	return NL_STOP;
}

int ifinfo_list_alloc(struct team_handle *th)
{
	list_init(&th->ifinfo_list);
	return 0;
}

static void valid_handler_obj_input(struct nl_object *obj, void *arg)
{
	return obj_input(obj, arg, false);
}

static int valid_handler(struct nl_msg *msg, void *arg)
{
	struct team_handle *th = arg;

	if (nl_msg_parse(msg, &valid_handler_obj_input, th) < 0)
		err(th, "Unknown message type.");
	return NL_OK;
}

int get_ifinfo_list(struct team_handle *th)
{
	struct nl_cb *cb;
	struct nl_cb *orig_cb;
	struct rtgenmsg rt_hdr = {
		.rtgen_family = AF_UNSPEC,
	};
	int ret;

	ret = nl_send_simple(th->nl_cli.sock, RTM_GETLINK, NLM_F_DUMP,
			     &rt_hdr, sizeof(rt_hdr));
	if (ret < 0)
		return -nl2syserr(ret);
	orig_cb = nl_socket_get_cb(th->nl_cli.sock);
	cb = nl_cb_clone(orig_cb);
	nl_cb_put(orig_cb);
	if (!cb)
		return -ENOMEM;

	nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, th);

	ret = nl_recvmsgs(th->nl_cli.sock, cb);
	nl_cb_put(cb);
	if (ret < 0)
		return -nl2syserr(ret);
	return 0;
}

int ifinfo_list_init(struct team_handle *th)
{
	int err;

	err = get_ifinfo_list(th);
	if (err) {
		err(th, "Failed to get interface information list.");
		return err;
	}
	return 0;
}

static void ifinfo_destroy(struct team_ifinfo *ifinfo)
{
	list_del(&ifinfo->list);
	free(ifinfo);
}

static void flush_port_list(struct team_handle *th)
{
	struct team_ifinfo *ifinfo, *tmp;

	list_for_each_node_entry_safe(ifinfo, tmp, &th->ifinfo_list, list)
		ifinfo_destroy(ifinfo);
}

void ifinfo_list_free(struct team_handle *th)
{
	flush_port_list(th);
}

int ifinfo_link_with_port(struct team_handle *th, uint32_t ifindex,
			  struct team_port *port, struct team_ifinfo **p_ifinfo)
{
	struct team_ifinfo *ifinfo;

	ifinfo = ifinfo_find(th, ifindex);
	if (!ifinfo)
		return -ENOENT;
	if (ifinfo->linked)
		return -EBUSY;
	ifinfo->port = port;
	ifinfo->linked = true;
	if (p_ifinfo)
		*p_ifinfo = ifinfo;
	return 0;
}

int ifinfo_link(struct team_handle *th, uint32_t ifindex,
		struct team_ifinfo **p_ifinfo)
{
	return ifinfo_link_with_port(th, ifindex, NULL, p_ifinfo);
}

void ifinfo_unlink(struct team_ifinfo *ifinfo)
{
	ifinfo->port = NULL;
	ifinfo->linked = false;
}

/**
 * team_get_next_ifinfo:
 * @th: libteam library context
 * @ifinfo: ifinfo structure
 *
 * Get next ifinfo in list.
 *
 * Returns: ifinfo next to @ifinfo passed.
 **/
TEAM_EXPORT
struct team_ifinfo *team_get_next_ifinfo(struct team_handle *th,
					 struct team_ifinfo *ifinfo)
{
	do {
		ifinfo = list_get_next_node_entry(&th->ifinfo_list, ifinfo, list);
		if (ifinfo && ifinfo->linked)
			return ifinfo;
	} while (ifinfo);
	return NULL;
}

/**
 * team_get_ifinfo_ifindex:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo interface index.
 *
 * Returns: ifinfo interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
uint32_t team_get_ifinfo_ifindex(struct team_ifinfo *ifinfo)
{
	return ifinfo->ifindex;
}

/**
 * team_get_ifinfo_port:
 * @ifinfo: ifinfo structure
 *
 * Get port associated to rtnetlink interface info.
 *
 * Returns: pointer to appropriate team_port structure
 *	    or NULL if not associated.
 **/
TEAM_EXPORT
struct team_port *team_get_ifinfo_port(struct team_ifinfo *ifinfo)
{
	return ifinfo->port;
}

/**
 * team_get_ifinfo_hwaddr:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo hardware address.
 *
 * Returns: pointer to memory place where hwaddr is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_hwaddr(struct team_ifinfo *ifinfo)
{
	return ifinfo->hwaddr;
}

/**
 * team_is_ifinfo_hwaddr_changed:
 * @ifinfo: ifinfo structure
 *
 * See if ifinfo hardware address got changed.
 *
 * Returns: true if hardware address got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_hwaddr_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_HWADDR);
}

/**
 * team_get_ifinfo_hwaddr_len:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo hardware address length.
 *
 * Returns: hardware address length.
 **/
TEAM_EXPORT
size_t team_get_ifinfo_hwaddr_len(struct team_ifinfo *ifinfo)
{
	return ifinfo->hwaddr_len;
}

/**
 * team_is_ifinfo_hwaddr_len_changed:
 * @ifinfo: ifinfo structure
 *
 * See if ifinfo hardware address length got changed.
 *
 * Returns: true if ifinfo hardware address length changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_hwaddr_len_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_HWADDR_LEN);
}

/**
 * team_get_ifinfo_orig_hwaddr:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo original hardware address.
 *
 * Returns: pointer to memory place where hwaddr is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_orig_hwaddr(struct team_ifinfo *ifinfo)
{
	return ifinfo->orig_hwaddr;
}

/**
 * team_get_ifinfo_orig_hwaddr_len:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo original hardware address length.
 *
 * Returns: hardware address length.
 **/
TEAM_EXPORT
uint8_t team_get_ifinfo_orig_hwaddr_len(struct team_ifinfo *ifinfo)
{
	return ifinfo->orig_hwaddr_len;
}

/**
 * team_get_ifinfo_ifname:
 * @ifinfo: ifinfo structure
 *
 * Get ifinfo interface name.
 *
 * Returns: pointer to memory place where interface name is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_ifname(struct team_ifinfo *ifinfo)
{
	return ifinfo->ifname;
}

/**
 * team_is_ifinfo_ifname_changed:
 * @ifinfo: ifinfo structure
 *
 * See if ifinfo interface name got changed.
 *
 * Returns: true if ifinfo interface name got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_ifname_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_IFNAME);
}

/**
 * team_get_ifinfo_master_ifindex:
 * @ifinfo: ifinfo structure
 *
 * Get interface index of master interface.
 *
 * Returns: master interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
uint32_t team_get_ifinfo_master_ifindex(struct team_ifinfo *ifinfo)
{
	return ifinfo->master_ifindex;
}

/**
 * team_is_ifinfo_master_ifindex_changed:
 * @ifinfo: ifinfo structure
 *
 * See if interface index of master interface got changed.
 *
 * Returns: true if interface index of master interface got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_master_ifindex_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_MASTER_IFINDEX);
}


/**
 * team_is_ifinfo_changed:
 * @ifinfo: ifinfo structure
 *
 * See if ifinfo got changed.
 *
 * Returns: true if ifinfo changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_ANY);
}
