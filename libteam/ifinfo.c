/*
 *   ifinfo.c - Wrapper for rtnetlink interface info
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

/**
 * @ingroup libteam
 * @defgroup ifinfo Interface information functions
 * Wrapper for rtnetlink interface info
 *
 * @{
 *
 * Header
 * ------
 * ~~~~{.c}
 * #include <team.h>
 * ~~~~
 */

#include <stdbool.h>
#include <stdlib.h>
#include <netlink/netlink.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <netlink/data.h>
#include <linux/netdevice.h>
#include <linux/types.h>
#include <team.h>
#include <private/list.h>
#include <private/misc.h>
#include "team_private.h"

/* \cond HIDDEN_SYMBOLS */

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
	bool			admin_state;
#define MAX_PHYS_PORT_ID_LEN 32
	char			phys_port_id[MAX_PHYS_PORT_ID_LEN];
	size_t			phys_port_id_len;
	int			changed;
};

#define CHANGED_REMOVED			(1 << 0)
#define CHANGED_HWADDR			(1 << 1)
#define CHANGED_HWADDR_LEN		(1 << 2)
#define CHANGED_IFNAME			(1 << 3)
#define CHANGED_MASTER_IFINDEX		(1 << 4)
#define CHANGED_PHYS_PORT_ID		(1 << 5)
#define CHANGED_PHYS_PORT_ID_LEN	(1 << 6)
#define CHANGED_ADMIN_STATE		(1 << 7)
/* This is only used when tagging interfaces for finding
 * removed, and thus not included to CHANGED_ANY.
 */
#define CHANGED_REFRESHING		(1 << 8)
#define CHANGED_ANY	(CHANGED_REMOVED | CHANGED_HWADDR | \
			 CHANGED_HWADDR_LEN | CHANGED_IFNAME | \
			 CHANGED_MASTER_IFINDEX | CHANGED_PHYS_PORT_ID | \
			 CHANGED_PHYS_PORT_ID_LEN | CHANGED_ADMIN_STATE)

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

static void update_admin_state(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	unsigned int flags;
	bool admin_state;

	flags = rtnl_link_get_flags(link);
	admin_state = ((flags & IFF_UP) == IFF_UP);

	if (admin_state != ifinfo->admin_state) {
		ifinfo->admin_state = admin_state;
		set_changed(ifinfo, CHANGED_ADMIN_STATE);
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

static void update_phys_port_id(struct team_ifinfo *ifinfo,
				struct rtnl_link *link)
{
#ifdef HAVE_RTNL_LINK_GET_PHYS_ID
	struct nl_data *nl_data;
	char *phys_port_id = NULL;
	size_t phys_port_id_len = 0;

	nl_data = rtnl_link_get_phys_port_id(link);
	if (nl_data) {
		phys_port_id_len = nl_data_get_size(nl_data);
		if (phys_port_id_len > MAX_PHYS_PORT_ID_LEN)
			phys_port_id_len = 0;
		phys_port_id = nl_data_get(nl_data);
	}

	if (ifinfo->phys_port_id_len != phys_port_id_len) {
		ifinfo->phys_port_id_len = phys_port_id_len;
		set_changed(ifinfo, CHANGED_PHYS_PORT_ID_LEN);
	}
	if (phys_port_id_len &&
	    memcmp(ifinfo->phys_port_id, phys_port_id, phys_port_id_len)) {
		memcpy(ifinfo->phys_port_id, phys_port_id, phys_port_id_len);
		set_changed(ifinfo, CHANGED_PHYS_PORT_ID);
	}
#endif
}

static void ifinfo_update(struct team_ifinfo *ifinfo, struct rtnl_link *link)
{
	update_ifname(ifinfo, link);
	update_master(ifinfo, link);
	update_hwaddr(ifinfo, link);
	update_phys_port_id(ifinfo, link);
	update_admin_state(ifinfo, link);
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

void ifinfo_clear_changed(struct team_handle *th)
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

static void ifinfo_destroy(struct team_ifinfo *ifinfo)
{
	if (ifinfo->linked && ifinfo->port)
		port_unlink(ifinfo->port);
	list_del(&ifinfo->list);
	free(ifinfo);
}

void ifinfo_destroy_removed(struct team_handle *th)
{
	struct team_ifinfo *ifinfo, *tmp;

	list_for_each_node_entry_safe(ifinfo, tmp, &th->ifinfo_list, list) {
		if (is_changed(ifinfo, CHANGED_REMOVED))
			ifinfo_destroy(ifinfo);
	}
}

static void obj_input_newlink(struct nl_object *obj, void *arg, bool event)
{
	struct team_handle *th = arg;
	struct rtnl_link *link;
	struct team_ifinfo *ifinfo;
	uint32_t ifindex;
	int err;

	ifinfo_destroy_removed(th);

	link = (struct rtnl_link *) obj;

	ifindex = rtnl_link_get_ifindex(link);
	ifinfo = ifinfo_find_create(th, ifindex);
	if (!ifinfo)
		return;

	if (event) {
		err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
		if (err)
			return;
	}

	clear_changed(ifinfo);
	ifinfo_update(ifinfo, link);

	if (event)
		rtnl_link_put(link);

	if (ifinfo->changed || !event)
		set_call_change_handlers(th, TEAM_IFINFO_CHANGE);
}

static void event_handler_obj_input_newlink(struct nl_object *obj, void *arg)
{
	return obj_input_newlink(obj, arg, true);
}

static void event_handler_obj_input_dellink(struct nl_object *obj, void *arg)
{
	struct team_handle *th = arg;
	struct rtnl_link *link;
	struct team_ifinfo *ifinfo;
	uint32_t ifindex;
	int err;

	ifinfo_destroy_removed(th);

	link = (struct rtnl_link *) obj;

	ifindex = rtnl_link_get_ifindex(link);
	ifinfo = ifinfo_find_create(th, ifindex);
	if (!ifinfo)
		return;

	/* It might happen that dellink message comes even in case the device
	 * is not actually removed. For example in case of bridge port removal.
	 * So better to check actual state before taking actions
	 */
	err = rtnl_link_get_kernel(th->nl_cli.sock, ifindex, NULL, &link);
	if (!err) {
		rtnl_link_put(link);
		return;
	}

	clear_changed(ifinfo);
	set_changed(ifinfo, CHANGED_REMOVED);
	set_call_change_handlers(th, TEAM_IFINFO_CHANGE);
}

int ifinfo_event_handler(struct nl_msg *msg, void *arg)
{
	struct team_handle *th = arg;

	switch (nlmsg_hdr(msg)->nlmsg_type) {
	case RTM_NEWLINK:
		if (nl_msg_parse(msg, &event_handler_obj_input_newlink, th) < 0)
			err(th, "Unknown message type.");
		break;
	case RTM_DELLINK:
		if (nl_msg_parse(msg, &event_handler_obj_input_dellink, th) < 0)
			err(th, "Unknown message type.");
		break;
	default:
		return NL_OK;
	}
	return NL_STOP;
}

int ifinfo_list_alloc(struct team_handle *th)
{
	list_init(&th->ifinfo_list);
	return 0;
}

static void valid_handler_obj_input_newlink(struct nl_object *obj, void *arg)
{
	return obj_input_newlink(obj, arg, false);
}

static int valid_handler(struct nl_msg *msg, void *arg)
{
	struct team_handle *th = arg;

	if (nlmsg_hdr(msg)->nlmsg_type != RTM_NEWLINK)
		return NL_OK;

	if (nl_msg_parse(msg, &valid_handler_obj_input_newlink, th) < 0)
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
	int retry = 1;
	struct team_ifinfo *ifinfo;

	/* Tag all ifinfo, this is cleared in newlink handler.
	 * Any interface that has this after dump is processed
	 * has been removed.
	 */
	list_for_each_node_entry(ifinfo, &th->ifinfo_list, list)
		set_changed(ifinfo, CHANGED_REFRESHING);

	while (retry) {
		retry = 0;
		ret = nl_send_simple(th->nl_cli.sock, RTM_GETLINK, NLM_F_DUMP,
				     &rt_hdr, sizeof(rt_hdr));
		if (ret < 0) {
			err(th, "get_ifinfo_list: nl_send_simple failed");
			return -nl2syserr(ret);
		}
		orig_cb = nl_socket_get_cb(th->nl_cli.sock);
		cb = nl_cb_clone(orig_cb);
		nl_cb_put(orig_cb);
		if (!cb) {
			err(th, "get_ifinfo_list: nl_cb_clone failed");
			return -ENOMEM;
		}

		nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, valid_handler, th);

		ret = nl_recvmsgs(th->nl_cli.sock, cb);
		nl_cb_put(cb);
		if (ret < 0) {
			err(th, "get_ifinfo_list: nl_recvmsgs failed");
			if (ret != -NLE_DUMP_INTR)
				return -nl2syserr(ret);
			retry = 1;
		}
	}

	list_for_each_node_entry(ifinfo, &th->ifinfo_list, list) {
		if (is_changed(ifinfo, CHANGED_REFRESHING)) {
			clear_changed(ifinfo);
			set_changed(ifinfo, CHANGED_REMOVED);
			set_call_change_handlers(th, TEAM_IFINFO_CHANGE);
		}
	}

	ret = check_call_change_handlers(th, TEAM_IFINFO_CHANGE |
					     TEAM_IFINFO_REFRESH);
	if (ret < 0)
		err(th, "get_ifinfo_list: check_call_change_handers failed");
	return ret;
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

/* \endcond */

/**
 * @param th		libteam library context
 * @param ifinfo	ifinfo structure
 *
 * @details Get next ifinfo in list.
 *
 * @return Ifinfo next to ifinfo passed.
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
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo got removed. This means that the interface
 *	    got removed.
 *
 * @return True if ifinfo got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_removed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_REMOVED);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo interface index.
 *
 * @return Ifinfo interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
uint32_t team_get_ifinfo_ifindex(struct team_ifinfo *ifinfo)
{
	return ifinfo->ifindex;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo admin state.
 *
 * @return Ifinfo interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
bool team_get_ifinfo_admin_state(struct team_ifinfo *ifinfo)
{
	return ifinfo->admin_state;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get port associated to rtnetlink interface info.
 *
 * @return Pointer to appropriate team_port structure
 *	    or NULL if not associated.
 **/
TEAM_EXPORT
struct team_port *team_get_ifinfo_port(struct team_ifinfo *ifinfo)
{
	return ifinfo->port;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo hardware address.
 *
 * @return Pointer to memory place where hwaddr is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_hwaddr(struct team_ifinfo *ifinfo)
{
	return ifinfo->hwaddr;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo hardware address got changed.
 *
 * @return True if hardware address got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_hwaddr_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_HWADDR);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo hardware address length.
 *
 * @return Hardware address length.
 **/
TEAM_EXPORT
size_t team_get_ifinfo_hwaddr_len(struct team_ifinfo *ifinfo)
{
	return ifinfo->hwaddr_len;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo hardware address length got changed.
 *
 * @return True if ifinfo hardware address length changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_hwaddr_len_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_HWADDR_LEN);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo original hardware address.
 *
 * @return Pointer to memory place where hwaddr is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_orig_hwaddr(struct team_ifinfo *ifinfo)
{
	return ifinfo->orig_hwaddr;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo original hardware address length.
 *
 * @return Hardware address length.
 **/
TEAM_EXPORT
uint8_t team_get_ifinfo_orig_hwaddr_len(struct team_ifinfo *ifinfo)
{
	return ifinfo->orig_hwaddr_len;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo interface name.
 *
 * @return Pointer to memory place where interface name is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_ifname(struct team_ifinfo *ifinfo)
{
	return ifinfo->ifname;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo interface name got changed.
 *
 * @return True if ifinfo interface name got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_ifname_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_IFNAME);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get interface index of master interface.
 *
 * @return Master interface index as idenfified by in kernel.
 **/
TEAM_EXPORT
uint32_t team_get_ifinfo_master_ifindex(struct team_ifinfo *ifinfo)
{
	return ifinfo->master_ifindex;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if interface index of master interface got changed.
 *
 * @return True if interface index of master interface got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_master_ifindex_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_MASTER_IFINDEX);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if admin state of interface got changed.
 *
 * @return True if admin state of interface got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_admin_state_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_ADMIN_STATE);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details Get ifinfo physical port ID.
 *
 * @return Pointer to memory place where physical por ID is.
 **/
TEAM_EXPORT
char *team_get_ifinfo_phys_port_id(struct team_ifinfo *ifinfo)
{
	return ifinfo->phys_port_id;
}

/**
 * team_is_ifinfo_phys_port_id_changed:
 *
 * @details See if ifinfo physical port ID got changed.
 *
 * @return True if physical port ID. got changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_phys_port_id_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_PHYS_PORT_ID);
}

/**
 * team_get_ifinfo_phys_port_id_len:
 *
 * @details Get ifinfo physical port ID length.
 *
 * @return Physical port ID length.
 **/
TEAM_EXPORT
size_t team_get_ifinfo_phys_port_id_len(struct team_ifinfo *ifinfo)
{
	return ifinfo->phys_port_id_len;
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo physical port ID length got changed.
 *
 * @return True if ifinfo physical port ID length changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_phys_port_id_len_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_PHYS_PORT_ID_LEN);
}

/**
 * @param ifinfo	ifinfo structure
 *
 * @details See if ifinfo got changed.
 *
 * @return True if ifinfo changed.
 **/
TEAM_EXPORT
bool team_is_ifinfo_changed(struct team_ifinfo *ifinfo)
{
	return is_changed(ifinfo, CHANGED_ANY);
}

/**
 * @}
 */
