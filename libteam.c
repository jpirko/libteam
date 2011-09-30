/*
 * libteam.c - Network team device driver library
 * Copyright (c) 2011 Jiri Pirko <jpirko@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <linux/if_team.h>
#include "team.h"

/* Linked list section taken from kernel <linux/list.h> */

#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define container_of(ptr, type, member) ({			\
	const typeof( ((type *)0)->member ) *__mptr = (ptr);	\
	(type *)( (char *)__mptr - offsetof(type,member) );})

#define LIST_POISON1  ((void *) 0x00100100)
#define LIST_POISON2  ((void *) 0x00200200)

#define LIST_HEAD_INIT(name) { &(name), &(name) }

#define LIST_HEAD(name) \
	struct list_head name = LIST_HEAD_INIT(name)

static inline void INIT_LIST_HEAD(struct list_head *list)
{
	list->next = list;
	list->prev = list;
}

static inline void __list_add(struct list_head *new,
			      struct list_head *prev,
			      struct list_head *next)
{
	next->prev = new;
	new->next = next;
	new->prev = prev;
	prev->next = new;
}

static inline void list_add(struct list_head *new, struct list_head *head)
{
	__list_add(new, head, head->next);
}

static inline void list_add_tail(struct list_head *new, struct list_head *head)
{
	__list_add(new, head->prev, head);
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	prev->next = next;
}

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline int list_empty(const struct list_head *head)
{
	return head->next == head;
}

static inline void __list_splice(const struct list_head *list,
				 struct list_head *prev,
				 struct list_head *next)
{
	struct list_head *first = list->next;
	struct list_head *last = list->prev;

	first->prev = prev;
	prev->next = first;

	last->next = next;
	next->prev = last;
}

static inline void list_splice(const struct list_head *list,
				struct list_head *head)
{
	if (!list_empty(list))
		__list_splice(list, head, head->next);
}

#define list_entry(ptr, type, member) \
	container_of(ptr, type, member)

#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head);					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

/* list extension */
#define list_get_next_entry(entry, head, member) ({				\
	struct list_head *next = (entry ? &entry->member : head)->next;		\
	(next == head) ? NULL :	list_entry(next, typeof(*entry), member);})


/* Route netlink helper function */

static uint32_t get_ifindex(const char *ifname)
{
	struct nl_sock *sock;
	struct nl_cache *link_cache;
	uint32_t ifindex;

	sock = nl_cli_alloc_socket();
	nl_cli_connect(sock, NETLINK_ROUTE);
	link_cache = nl_cli_link_alloc_cache(sock);
	ifindex = rtnl_link_name2i(link_cache, ifname);
	nl_cache_free(link_cache);
	nl_socket_free(sock);

	return ifindex;
}

static void set_call_change_handlers(struct team_handle *th,
				     enum team_change_type type)
{
	struct team_change_handler *handler;

	list_for_each_entry(handler, &th->change_handler_list, list) {
		if (type == TEAM_ALL_CHANGE || handler->type == type)
			handler->call_this = 1;
	}
}

static void check_call_change_handlers(struct team_handle *th,
				       enum team_change_type type)
{
	struct team_change_handler *handler;

	list_for_each_entry(handler, &th->change_handler_list, list) {
		if ((type == TEAM_ALL_CHANGE || handler->type == type) &&
		    handler->call_this) {
			handler->func(th, handler->data);
			handler->call_this = 0;
		}
	}
}

static void flush_mode_list(struct team_handle *th)
{
	struct team_mode *mode, *tmp;

	list_for_each_entry_safe(mode, tmp, &th->mode_list, list) {
		list_del(&mode->list);
		free(mode);
	}
}

static void flush_port_list(struct team_handle *th)
{
	struct team_port *port, *tmp;

	list_for_each_entry_safe(port, tmp, &th->port_list, list) {
		list_del(&port->list);
		free(port);
	}
}

static struct team_option *create_option(char *name, int nla_type, void *data,
					 int data_size, int changed)
{
	struct team_option *option;

	option = malloc(sizeof(struct team_option));
	if (!option)
		return NULL;

	option->name = malloc(sizeof(char) * (strlen(name) + 1));
	if (!option->name)
		goto err_alloc_name;

	option->data = malloc(data_size);
	if (!option->data)
		goto err_alloc_data;

	option->nla_type = nla_type;
	option->changed = changed;
	strcpy(option->name, name);
	memcpy(option->data, data, data_size);

	return option;

err_alloc_data:
	free(option->name);

err_alloc_name:
	free(option);

	return NULL;
}

static void flush_option_list(struct team_handle *th)
{
	struct team_option *option, *tmp;

	list_for_each_entry_safe(option, tmp, &th->option_list, list) {
		list_del(&option->list);
		free(option->name);
		free(option->data);
		free(option);
	}
}

static int get_option(struct team_handle *th, char *name, void **data)
{
	struct team_option *option;

	list_for_each_entry(option, &th->option_list, list) {
		if (strcmp(option->name, name) == 0) {
			*data = option->data;
			return 0;
		}
	}
	return -ENOENT;
}

static int get_option_u32(struct team_handle *th, char *name, __u32 *ptr)
{
	int err;
	void *data;

	err = get_option(th, name, &data);
	if (err)
		return err;
	*ptr = *((__u32 *) data);
	return 0;
}

static int get_option_string(struct team_handle *th, char *name, char **ptr)
{
	int err;
	void *data;

	err = get_option(th, name, &data);
	if (err)
		return err;
	*ptr = data;
	return 0;
}

static int send_and_recv(struct team_handle *th, struct nl_msg *msg,
			 int (*valid_handler)(struct nl_msg *, void *),
			 void *valid_data)
{
	struct nl_cb *cb;
	int err = -ENOMEM;

	err = nl_send_auto_complete(th->nl_sock, msg);
	if (err < 0)
		goto out;

	th->nl_sock_err = 1;

	if (valid_handler)
		nl_socket_modify_cb(th->nl_sock, NL_CB_VALID, NL_CB_CUSTOM,
				    valid_handler, valid_data);

	while (th->nl_sock_err > 0)
		nl_recvmsgs_default(th->nl_sock);

	err = th->nl_sock_err;

 out:
	nlmsg_free(msg);
	return err;
}

static int set_option(struct team_handle *th, const char *opt_name,
		      void *data, int nla_type)
{
	struct nl_msg *msg;
	struct nlattr *option_list;
	struct nlattr *option_item;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, th->family, 0, 0,
		    TEAM_CMD_OPTIONS_SET, 0);
	NLA_PUT_U32(msg, TEAM_ATTR_TEAM_IFINDEX, th->ifindex);
	option_list = nla_nest_start(msg, TEAM_ATTR_LIST_OPTION);
	if (!option_list)
		goto nla_put_failure;
	option_item = nla_nest_start(msg, TEAM_ATTR_ITEM_OPTION);
	if (!option_item)
		goto nla_put_failure;
	NLA_PUT_STRING(msg, TEAM_ATTR_OPTION_NAME, opt_name);
	NLA_PUT_U32(msg, TEAM_ATTR_OPTION_TYPE, nla_type);
	switch (nla_type) {
		case NLA_U32:
			NLA_PUT_U32(msg, TEAM_ATTR_OPTION_DATA, *((__u32 *) data));
			break;
		case NLA_STRING:
			NLA_PUT_STRING(msg, TEAM_ATTR_OPTION_DATA, (char *) data);
			break;
		default:
			goto nla_put_failure;
	}
	nla_nest_end(msg, option_item);
	nla_nest_end(msg, option_list);

	return send_and_recv(th, msg, NULL, NULL);

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int set_option_u32(struct team_handle *th, char *opt_name,
			  __u32 val)
{
	return set_option(th, opt_name, &val, NLA_U32);
}

static int set_option_string(struct team_handle *th, char *opt_name,
			     char *str)
{
	return set_option(th, opt_name, str, NLA_STRING);
}

static int get_mode_list_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct team_handle *th = arg;
	struct nlattr *attrs[TEAM_ATTR_MAX + 1];
	struct nlattr *nl_mode;
	struct nlattr *mode_attrs[TEAM_ATTR_MODE_MAX + 1];
	int i;
	char *str;
	LIST_HEAD(tmp_list);

	genlmsg_parse(nlh, 0, attrs, TEAM_ATTR_MAX, NULL);

	if (!attrs[TEAM_ATTR_LIST_MODE]) {
		return NL_SKIP;
	}

	flush_mode_list(th);
	nla_for_each_nested(nl_mode, attrs[TEAM_ATTR_LIST_MODE], i) {
		struct team_mode *mode;

		if (nla_parse_nested(mode_attrs, TEAM_ATTR_MODE_MAX,
				     nl_mode, NULL)) {
			printf("failed to parse nested attributes.\n");
			return NL_SKIP;
		}

		str = nla_get_string(mode_attrs[TEAM_ATTR_MODE_NAME]);
		mode = malloc(sizeof(struct team_mode) +
			      sizeof(char) * (strlen(str) + 1));
		if (!mode) {
			printf("malloc failed\n");
			flush_mode_list(th);
			return NL_SKIP;
		}

		strcpy(mode->name, str);
		list_add_tail(&mode->list, &tmp_list);
	}

	flush_mode_list(th);
	list_splice(&tmp_list, &th->mode_list);
	return NL_SKIP;
}

static int get_mode_list(struct team_handle *th)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, th->family, 0, 0,
			 TEAM_CMD_MODE_LIST_GET, 0);
	NLA_PUT_U32(msg, TEAM_ATTR_TEAM_IFINDEX, th->ifindex);

	return send_and_recv(th, msg, get_mode_list_handler, th);

nla_put_failure:
	return -ENOBUFS;
}

static int get_port_list_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct team_handle *th = arg;
	struct nlattr *attrs[TEAM_ATTR_MAX + 1];
	struct nlattr *nl_port;
	struct nlattr *port_attrs[TEAM_ATTR_PORT_MAX + 1];
	int i;
	uint32_t team_ifindex;
	LIST_HEAD(tmp_list);

	genlmsg_parse(nlh, 0, attrs, TEAM_ATTR_MAX, NULL);
	if (attrs[TEAM_ATTR_TEAM_IFINDEX])
		team_ifindex = nla_get_u32(attrs[TEAM_ATTR_TEAM_IFINDEX]);

	if (team_ifindex != th->ifindex)
		return NL_SKIP;

	if (!attrs[TEAM_ATTR_LIST_PORT])
		return NL_SKIP;

	nla_for_each_nested(nl_port, attrs[TEAM_ATTR_LIST_PORT], i) {
		struct team_port *port;

		if (nla_parse_nested(port_attrs, TEAM_ATTR_PORT_MAX,
				     nl_port, NULL)) {
			printf("failed to parse nested attributes.\n");
			return NL_SKIP;
		}

		if (!port_attrs[TEAM_ATTR_PORT_IFINDEX]) {
			printf("ifindex port attribute not found\n");
			return NL_SKIP;
		}
		port = malloc(sizeof(struct team_port));
		if (!port) {
			printf("malloc failed.\n");
			return NL_SKIP;
		}
		memset(port, 0, sizeof(struct team_port));
		port->ifindex = nla_get_u32(port_attrs[TEAM_ATTR_PORT_IFINDEX]);
		if (port_attrs[TEAM_ATTR_PORT_CHANGED])
			port->changed = 1;
		if (port_attrs[TEAM_ATTR_PORT_LINKUP])
			port->linkup = 1;
		if (port_attrs[TEAM_ATTR_PORT_SPEED])
			port->speed = nla_get_u32(port_attrs[TEAM_ATTR_PORT_SPEED]);
		if (port_attrs[TEAM_ATTR_PORT_DUPLEX])
			port->duplex = nla_get_u8(port_attrs[TEAM_ATTR_PORT_DUPLEX]);

		list_add_tail(&port->list, &tmp_list);
	}

	flush_port_list(th);
	list_splice(&tmp_list, &th->port_list);

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

	check_call_change_handlers(th, TEAM_PORT_CHANGE);
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int get_options_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct team_handle *th = arg;
	struct nlattr *attrs[TEAM_ATTR_MAX + 1];
	struct nlattr *nl_option;
	struct nlattr *option_attrs[TEAM_ATTR_OPTION_MAX + 1];
	int i;
	uint32_t team_ifindex;
	LIST_HEAD(tmp_list);

	genlmsg_parse(nlh, 0, attrs, TEAM_ATTR_MAX, NULL);
	if (attrs[TEAM_ATTR_TEAM_IFINDEX])
		team_ifindex = nla_get_u32(attrs[TEAM_ATTR_TEAM_IFINDEX]);

	if (team_ifindex != th->ifindex)
		return NL_SKIP;

	if (!attrs[TEAM_ATTR_LIST_OPTION])
		return NL_SKIP;

	nla_for_each_nested(nl_option, attrs[TEAM_ATTR_LIST_OPTION], i) {
		struct team_option *option;
		char *name;
		int changed;
		int nla_type;
		__u32 arg;
		void *data;
		int data_size;
		char *str;

		if (nla_parse_nested(option_attrs, TEAM_ATTR_OPTION_MAX,
				     nl_option, NULL)) {
			printf("failed to parse nested attributes.\n");
			return NL_SKIP;
		}

		if (!option_attrs[TEAM_ATTR_OPTION_NAME] ||
		    !option_attrs[TEAM_ATTR_OPTION_TYPE] ||
		    !option_attrs[TEAM_ATTR_OPTION_DATA]) {
			return NL_SKIP;
		}
		name = nla_get_string(option_attrs[TEAM_ATTR_OPTION_NAME]);
		if (option_attrs[TEAM_ATTR_OPTION_CHANGED])
			changed = 1;
		else
			changed = 0;

		nla_type = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_TYPE]);
		switch (nla_type) {
		case NLA_U32:
			arg = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_DATA]);
			data = &arg;
			data_size = sizeof(__u32);
			break;
		case NLA_STRING:
			str = nla_get_string(option_attrs[TEAM_ATTR_OPTION_DATA]);
			data = str;
			data_size = sizeof(char) * (strlen(str) + 1);
			break;
		}

		option = create_option(name, nla_type, data, data_size, changed);
		list_add_tail(&option->list, &tmp_list);
	}

	flush_option_list(th);
	list_splice(&tmp_list, &th->option_list);

	set_call_change_handlers(th, TEAM_OPTION_CHANGE);
	return NL_SKIP;
}

static int get_options(struct team_handle *th)
{
	struct nl_msg *msg;
	int err;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, th->family, 0, 0,
			 TEAM_CMD_OPTIONS_GET, 0);
	NLA_PUT_U32(msg, TEAM_ATTR_TEAM_IFINDEX, th->ifindex);

	err = send_and_recv(th, msg, get_options_handler, th);
	if (err)
		return err;

	check_call_change_handlers(th, TEAM_OPTION_CHANGE);
	return 0;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

static int ack_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;

	*err = 0;
	return NL_STOP;
}

static int finish_handler(struct nl_msg *msg, void *arg)
{
	int *err = arg;

	*err = 0;
	return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *nla, struct nlmsgerr *nl_err,
			 void *arg)
{
	int *err = arg;

	*err = nl_err->error;
	return NL_SKIP;
}

static int event_handler(struct nl_msg *msg, void *arg)
{
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));

	switch (gnlh->cmd) {
	case TEAM_CMD_PORT_LIST_GET:
		return get_port_list_handler(msg, arg);
	case TEAM_CMD_OPTIONS_GET:
		return get_options_handler(msg, arg);
	}
	return NL_SKIP;
}

struct team_handle *team_alloc(void)
{
	struct team_handle *th;

	th = malloc(sizeof(struct team_handle));
	if (!th)
		return NULL;

	memset(th, 0, sizeof(struct team_handle));
	INIT_LIST_HEAD(&th->mode_list);
	INIT_LIST_HEAD(&th->port_list);
	INIT_LIST_HEAD(&th->option_list);
	INIT_LIST_HEAD(&th->change_handler_list);

	th->nl_sock = nl_socket_alloc();
	if (!th->nl_sock)
		goto err_sk_alloc;

	th->nl_sock_event = nl_socket_alloc();
	if (!th->nl_sock_event) {
		goto err_sk_event_alloc;
	}

	return th;

err_sk_event_alloc:
	nl_socket_free(th->nl_sock);

err_sk_alloc:
	free(th);

	return NULL;
}

int team_init(struct team_handle *th, const char *team_ifname)
{
	int err;
	int grp_id;

	th->ifindex = get_ifindex(team_ifname);
	if (!th->ifindex) {
		printf("Interface \"%s\" not found.\n", team_ifname);
		return -ENOENT;
	}

	nl_socket_disable_seq_check(th->nl_sock_event);

	if (genl_connect(th->nl_sock)) {
		printf("Failed to connect to netlink sock.\n");
		return -ENOTSUP;
	}

	if (genl_connect(th->nl_sock_event)) {
		printf("Failed to connect to netlink event sock.\n");
		return -ENOTSUP;
	}

	th->family = genl_ctrl_resolve(th->nl_sock, TEAM_GENL_NAME);
	if (th->family < 0) {
		printf("Failed to resolve netlink family.\n");
		return -ENOENT;
	}

	grp_id = genl_ctrl_resolve_grp(th->nl_sock, TEAM_GENL_NAME,
				       TEAM_GENL_CHANGE_EVENT_MC_GRP_NAME);
	if (grp_id < 0) {
		printf("Failed to resolve netlink multicast groups.\n");
		return -ENOENT;
	}

	err = nl_socket_add_membership(th->nl_sock_event, grp_id);
	if (err < 0) {
		printf("Failed to add netlink membership.\n");
		return -EINVAL;
	}

	nl_socket_modify_err_cb(th->nl_sock,NL_CB_CUSTOM,
				error_handler, &th->nl_sock_err);
	nl_socket_modify_cb(th->nl_sock, NL_CB_FINISH, NL_CB_CUSTOM,
			    finish_handler, &th->nl_sock_err);
	nl_socket_modify_cb(th->nl_sock, NL_CB_ACK, NL_CB_CUSTOM,
			    ack_handler, &th->nl_sock_err);
	nl_socket_modify_cb(th->nl_sock_event, NL_CB_VALID, NL_CB_CUSTOM,
			    event_handler, th);

	err = get_mode_list(th);
	if (err) {
		printf("Failed to get mode list.\n");
		return -EINVAL;
	}

	err = get_port_list(th);
	if (err) {
		printf("Failed to get port list.\n");
		return -EINVAL;
	}

	err = get_options(th);
	if (err) {
		printf("Failed to get options.\n");
		return -EINVAL;
	}

	return 0;
}

void team_free(struct team_handle *th)
{
	flush_port_list(th);
	flush_mode_list(th);
	flush_option_list(th);
	nl_socket_free(th->nl_sock_event);
	nl_socket_free(th->nl_sock);
}

int team_get_event_fd(struct team_handle *th)
{
	return nl_socket_get_fd(th->nl_sock_event);
}

void team_process_event(struct team_handle *th)
{
	nl_recvmsgs_default(th->nl_sock_event);
	check_call_change_handlers(th, TEAM_ALL_CHANGE);
}

struct team_port *team_get_next_port(struct team_handle *th,
				     struct team_port *port)
{
	return list_get_next_entry(port, &th->port_list, list);
}

struct team_mode *team_get_next_mode(struct team_handle *th,
				     struct team_mode *mode)
{
	return list_get_next_entry(mode, &th->mode_list, list);
}

struct team_option *team_get_next_option(struct team_handle *th,
					 struct team_option *option)
{
	return list_get_next_entry(option, &th->option_list, list);
}

void team_change_handler_register(struct team_handle *th,
				  struct team_change_handler *handler)
{
	list_add(&handler->list, &th->change_handler_list);
}

void team_change_handler_unregister(struct team_handle *th,
				    struct team_change_handler *handler)
{
	list_del(&handler->list);
}

int team_get_mode_name(struct team_handle *th, char **mode_name)
{
	return get_option_string(th, "mode", mode_name);
}

int team_set_mode_name(struct team_handle *th, char *mode_name)
{
	return set_option_string(th, "mode", mode_name);
}

int team_get_active_port(struct team_handle *th, uint32_t *ifindex)
{
	return get_option_u32(th, "activeport", ifindex);
}

int team_set_active_port(struct team_handle *th, uint32_t ifindex)
{
	return set_option_u32(th, "activeport", ifindex);
}
