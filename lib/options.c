/*
 *   options.c - Wrapper for team generic netlink option-related communication
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
#include <linux/if_team.h>
#include <linux/types.h>
#include <team.h>
#include "team_private.h"
#include "list.h"

struct team_option {
	struct list_item	list;
	enum team_option_type	type;
	char *			name;
	void *			data;
	bool			changed;
};

static void flush_option_list(struct team_handle *th)
{
	struct team_option *option, *tmp;

	list_for_each_node_entry_safe(option, tmp, &th->option_list, list) {
		list_del(&option->list);
		free(option->name);
		free(option->data);
		free(option);
	}
}

static struct team_option *create_option(char *name, int opt_type,
					 void *data, int data_size,
					 bool changed)
{
	struct team_option *option;

	option = malloc(sizeof(struct team_option));
	if (!option)
		return NULL;

	option->name = strdup(name);
	if (!option->name)
		goto err_alloc_name;

	option->data = malloc(data_size);
	if (!option->data)
		goto err_alloc_data;

	option->type = opt_type;
	option->changed = changed;
	memcpy(option->data, data, data_size);

	return option;

err_alloc_data:
	free(option->name);

err_alloc_name:
	free(option);

	return NULL;
}

static struct team_option *__find_option(struct list_item *opt_head,
					 const char *name)
{
	struct team_option *option;

	list_for_each_node_entry(option, opt_head, list) {
		if (strcmp(option->name, name) == 0)
			return option;
	}
	return NULL;
}

int get_options_handler(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct team_handle *th = arg;
	struct nlattr *attrs[TEAM_ATTR_MAX + 1];
	struct nlattr *nl_option;
	struct nlattr *option_attrs[TEAM_ATTR_OPTION_MAX + 1];
	int i;
	uint32_t team_ifindex = 0;
	struct list_item tmp_list;

	list_init(&tmp_list);
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
		bool changed;
		int nla_type;
		__u32 arg;
		int opt_type;
		void *data;
		int data_size;
		char *str;

		if (nla_parse_nested(option_attrs, TEAM_ATTR_OPTION_MAX,
				     nl_option, NULL)) {
			err(th, "Failed to parse nested attributes.");
			return NL_SKIP;
		}

		if (!option_attrs[TEAM_ATTR_OPTION_NAME] ||
		    !option_attrs[TEAM_ATTR_OPTION_TYPE] ||
		    !option_attrs[TEAM_ATTR_OPTION_DATA]) {
			return NL_SKIP;
		}
		name = nla_get_string(option_attrs[TEAM_ATTR_OPTION_NAME]);
		if (__find_option(&tmp_list, name)) {
			err(th, "Option named \"%s\" is already in list.", name);
			continue;
		}

		if (option_attrs[TEAM_ATTR_OPTION_CHANGED])
			changed = true;
		else
			changed = false;

		nla_type = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_TYPE]);
		switch (nla_type) {
		case NLA_U32:
			arg = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_DATA]);
			data = &arg;
			data_size = sizeof(__u32);
			opt_type = TEAM_OPTION_TYPE_U32;
			break;
		case NLA_STRING:
			str = nla_get_string(option_attrs[TEAM_ATTR_OPTION_DATA]);
			data = str;
			data_size = sizeof(char) * (strlen(str) + 1);
			opt_type = TEAM_OPTION_TYPE_STRING;
			break;
		default:
			err(th, "Unknown nla_type received.");
			continue;
		}

		option = create_option(name, opt_type, data, data_size, changed);
		list_add(&tmp_list, &option->list);
	}

	flush_option_list(th);
	list_move_nodes(&th->option_list, &tmp_list);

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

int option_list_alloc(struct team_handle *th)
{
	list_init(&th->option_list);

	return 0;
}

int option_list_init(struct team_handle *th)
{
	int err;

	err = get_options(th);
	if (err) {
		err(th, "Failed to get options.");
		return err;
	}
	return 0;
}

void option_list_free(struct team_handle *th)
{
	flush_option_list(th);
}


/**
 * team_get_option_by_name:
 * @th: libteam library context
 * @name: option name
 *
 * Get option structure referred by option @name.
 *
 * Returns: pointer to option structure or NULL in case option is not found.
 **/
TEAM_EXPORT
struct team_option *team_get_option_by_name(struct team_handle *th,
					    const char *name)
{
	return __find_option(&th->option_list, name);
}

/**
 * team_get_next_option:
 * @th: libteam library context
 * @option: option structure
 *
 * Get next option in list.
 *
 * Returns: option next to @option passed.
 **/
TEAM_EXPORT
struct team_option *team_get_next_option(struct team_handle *th,
					 struct team_option *option)
{
	return list_get_next_node_entry(&th->option_list, option, list);
}

/**
 * team_get_option_name:
 * @option: option structure
 *
 * Get option name.
 *
 * Returns: pointer to string containing option name.
 **/
TEAM_EXPORT
char *team_get_option_name(struct team_option *option)
{
	return option->name;
}

/**
 * team_get_option_type:
 * @option: option structure
 *
 * Get option type.
 *
 * Returns: number identificating option type.
 **/
TEAM_EXPORT
enum team_option_type team_get_option_type(struct team_option *option)
{
	return option->type;
}

/**
 * team_get_option_value_u32:
 * @option: option structure
 *
 * Get option value as unsigned 32-bit number.
 *
 * Returns: number.
 **/
TEAM_EXPORT
uint32_t team_get_option_value_u32(struct team_option *option)
{
	return *((__u32 *) option->data);
}

/**
 * team_get_option_value_string:
 * @option: option structure
 *
 * Get option value as string.
 *
 * Returns: pointer to string.
 **/
TEAM_EXPORT
char *team_get_option_value_string(struct team_option *option)
{
	return option->data;
}

/**
 * team_is_option_changed:
 * @option: option structure
 *
 * See if option values got changed.
 *
 * Returns: true if option got changed.
 **/
TEAM_EXPORT
bool team_is_option_changed(struct team_option *option)
{
	return option->changed;
}

/**
 * team_get_option_value_by_name_u32:
 * @th: libteam library context
 * @name: option name
 * u32_ptr: where the value will be stored
 *
 * Get option referred by @name and store its value as unsigned 32-bit
 * number into @u32_ptr.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_option_value_by_name_u32(struct team_handle *th,
				      const char *name, uint32_t *u32_ptr)
{
	struct team_option *option;

	option = team_get_option_by_name(th, name);
	if (!option)
		return -ENOENT;
	*u32_ptr = team_get_option_value_u32(option);
	return 0;
}

/**
 * team_get_option_value_by_name_string:
 * @th: libteam library context
 * @name: option name
 * str_ptr: where the value will be stored
 *
 * Get option referred by @name and store its value as pointer to string
 * into @srt_ptr.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_get_option_value_by_name_string(struct team_handle *th,
					 const char *name, char **str_ptr)
{
	struct team_option *option;

	option = team_get_option_by_name(th, name);
	if (!option)
		return -ENOENT;
	*str_ptr = team_get_option_value_string(option);
	return 0;
}

static int set_option_value(struct team_handle *th, const char *opt_name,
			    const void *data, int opt_type)
{
	struct nl_msg *msg;
	struct nlattr *option_list;
	struct nlattr *option_item;
	int nla_type;

	switch (opt_type) {
	case TEAM_OPTION_TYPE_U32:
		nla_type = NLA_U32;
		break;
	case TEAM_OPTION_TYPE_STRING:
		nla_type = NLA_STRING;
		break;
	default:
		return -ENOENT;
	}

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

/**
 * team_set_option_value_by_name_u32:
 * @th: libteam library context
 * @name: option name
 * @val: value to be set
 *
 * Set 32-bit number type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_by_name_u32(struct team_handle *th,
				      const char *name, uint32_t val)
{
	return set_option_value(th, name, &val, TEAM_OPTION_TYPE_U32);
}

/**
 * team_set_option_value_by_name_string:
 * @th: libteam library context
 * @name: option name
 * @str: string to be set
 *
 * Set string type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_by_name_string(struct team_handle *th,
					 const char *name, const char *str)
{
	return set_option_value(th, name, str, TEAM_OPTION_TYPE_STRING);
}
