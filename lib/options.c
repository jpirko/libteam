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

#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/cli/utils.h>
#include <netlink/cli/link.h>
#include <linux/if_team.h>
#include <linux/types.h>
#include <team.h>
#include <private/list.h>
#include <private/misc.h>
#include "team_private.h"
#include "nl_updates.h"

struct team_option_id {
	char *			name;
	uint32_t		port_ifindex;
	bool			port_ifindex_used;
	uint32_t		array_index;
	bool			array_index_used;
};

struct team_option {
	struct list_item	list;
	bool			initialized;
	enum team_option_type	type;
	struct team_option_id	id;
	void *			data;
	int			data_len;
	bool			changed;
	bool			changed_locally;
};

static void free_option(struct team_option *option)
{
	free(option->id.name);
	free(option->data);
	free(option);
}

static void flush_option_list(struct team_handle *th)
{
	struct team_option *option, *tmp;

	list_for_each_node_entry_safe(option, tmp, &th->option_list, list) {
		list_del(&option->list);
		free_option(option);
	}
}

static void option_list_cleanup_last_state(struct team_handle *th)
{
	struct team_option *option;

	list_for_each_node_entry(option, &th->option_list, list)
		option->changed = false;
}

static struct team_option *do_find_option(struct team_handle *th,
					  struct team_option_id *opt_id)
{
	struct team_option *option;

	list_for_each_node_entry(option, &th->option_list, list) {
		if (strcmp(option->id.name, opt_id->name))
			continue;
		if (option->id.port_ifindex_used != opt_id->port_ifindex_used)
			continue;
		if (option->id.port_ifindex_used &&
		    option->id.port_ifindex != opt_id->port_ifindex)
			continue;
		if (option->id.array_index_used != opt_id->array_index_used)
			continue;
		if (option->id.array_index_used &&
		    option->id.array_index != opt_id->array_index)
			continue;
		return option;
	}
	return NULL;
}

static int get_option_data_size_by_type(int opt_type, const void *data,
					int data_len)
{
	switch (opt_type) {
	case TEAM_OPTION_TYPE_U32:
		return sizeof(__u32);
	case TEAM_OPTION_TYPE_STRING:
		return sizeof(char) * (strlen((char *) data) + 1);
	case TEAM_OPTION_TYPE_BINARY:
		return data_len;
	case TEAM_OPTION_TYPE_BOOL:
		return sizeof(bool);
	case TEAM_OPTION_TYPE_S32:
		return sizeof(__s32);
	default:
		return -EINVAL;
	}
}

static int create_option(struct team_option **poption,
			 struct team_option_id *opt_id)
{
	struct team_option *option;
	int err;

	option = myzalloc(sizeof(struct team_option));
	if (!option)
		return -ENOMEM;

	option->id.name = strdup(opt_id->name);
	if (!option->id.name) {
		err = -ENOMEM;
		goto err_alloc_name;
	}
	option->id.port_ifindex = opt_id->port_ifindex;
	option->id.port_ifindex_used = opt_id->port_ifindex_used;
	option->id.array_index = opt_id->array_index;
	option->id.array_index_used = opt_id->array_index_used;

	*poption = option;
	return 0;

err_alloc_name:
	free(option);

	return err;
}

static int do_update_option(struct team_handle *th, struct team_option *option,
			    int opt_type, const void *data, int data_len,
			    bool changed, bool changed_locally)
{
	void *tmp_data;
	int data_size;

	data_size = get_option_data_size_by_type(opt_type, data, data_len);
	if (data_size < 0)
		return data_size;

	if (option->initialized && option->type != opt_type)
		dbg(th, "Updating option \"%s\" with different option type.",
		    option->id.name);

	tmp_data = malloc(data_size);
	if (!tmp_data)
		return -ENOMEM;

	memcpy(tmp_data, data, data_size);
	free(option->data);
	option->data = tmp_data;
	option->data_len = data_size;
	option->type = opt_type;
	option->changed = changed;
	option->changed_locally = changed_locally;
	option->initialized = true;

	return 0;
}

static int update_option(struct team_handle *th, struct team_option **poption,
			 struct team_option_id *opt_id, int opt_type,
			 const void *data, int data_len,
			 bool changed, bool changed_locally)
{
	struct team_option *option;
	bool option_created = false;
	int err;

	option = do_find_option(th, opt_id);
	if (!option) {
		err = create_option(&option, opt_id);
		if (err)
			return err;
		option_created = true;
	}
	err = do_update_option(th, option, opt_type, data, data_len,
			       changed, changed_locally);
	if (err) {
		if (option_created)
			free_option(option);
		return err;
	}
	if (option_created)
		list_add(&th->option_list, &option->list);
	*poption = option;
	return 0;
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

	genlmsg_parse(nlh, 0, attrs, TEAM_ATTR_MAX, NULL);
	if (attrs[TEAM_ATTR_TEAM_IFINDEX])
		team_ifindex = nla_get_u32(attrs[TEAM_ATTR_TEAM_IFINDEX]);

	if (team_ifindex != th->ifindex)
		return NL_SKIP;

	if (!attrs[TEAM_ATTR_LIST_OPTION])
		return NL_SKIP;

	if (!th->msg_recv_started) {
		option_list_cleanup_last_state(th);
		th->msg_recv_started = true;
	}
	nla_for_each_nested(nl_option, attrs[TEAM_ATTR_LIST_OPTION], i) {
		struct team_option *option;
		struct team_option_id opt_id;
		bool changed;
		int nla_type;
		int opt_type;
		long tmp;
		void *data;
		int data_len = 0;
		int err;
		struct nlattr *data_attr;

		if (nla_parse_nested(option_attrs, TEAM_ATTR_OPTION_MAX,
				     nl_option, NULL)) {
			err(th, "Failed to parse nested attributes.");
			return NL_SKIP;
		}

		if (!option_attrs[TEAM_ATTR_OPTION_NAME] ||
		    !option_attrs[TEAM_ATTR_OPTION_TYPE]) {
			return NL_SKIP;
		}
		nla_type = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_TYPE]);
		data_attr = option_attrs[TEAM_ATTR_OPTION_DATA];
		if (nla_type != NLA_FLAG && !data_attr)
			return NL_SKIP;

		memset(&opt_id, 0, sizeof(opt_id));
		opt_id.name = nla_get_string(option_attrs[TEAM_ATTR_OPTION_NAME]);

		if (option_attrs[TEAM_ATTR_OPTION_CHANGED])
			changed = true;
		else
			changed = false;

		if (option_attrs[TEAM_ATTR_OPTION_PORT_IFINDEX]) {
			opt_id.port_ifindex = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_PORT_IFINDEX]);
			opt_id.port_ifindex_used = true;
		} else {
			opt_id.port_ifindex_used = false;
		}

		if (option_attrs[TEAM_ATTR_OPTION_ARRAY_INDEX]) {
			opt_id.array_index = nla_get_u32(option_attrs[TEAM_ATTR_OPTION_ARRAY_INDEX]);
			opt_id.array_index_used = true;
		} else {
			opt_id.array_index_used = false;
		}

		switch (nla_type) {
		case NLA_U32:
			tmp = (long) nla_get_u32(data_attr);
			data = &tmp;
			opt_type = TEAM_OPTION_TYPE_U32;
			break;
		case NLA_STRING:
			data = nla_get_string(data_attr);
			opt_type = TEAM_OPTION_TYPE_STRING;
			break;
		case NLA_BINARY:
			data = nla_data(data_attr);
			data_len = nla_len(data_attr);
			opt_type = TEAM_OPTION_TYPE_BINARY;
			break;
		case NLA_FLAG:
			tmp = (long) (data_attr ? true : false);
			data = &tmp;
			opt_type = TEAM_OPTION_TYPE_BOOL;
			break;
		case NLA_S32:
			tmp = (long) nla_get_s32(data_attr);
			data = &tmp;
			opt_type = TEAM_OPTION_TYPE_S32;
			break;
		default:
			err(th, "Unknown nla_type received.");
			continue;
		}

		err = update_option(th, &option, &opt_id, opt_type,
				    data, data_len, changed, false);
		if (err) {
			err(th, "Failed to update option: %s", strerror(-err));
			continue;
		}
		if (option_attrs[TEAM_ATTR_OPTION_REMOVED]) {
			list_del(&option->list);
			free_option(option);
		}
	}

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

	return check_call_change_handlers(th, TEAM_OPTION_CHANGE);

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

static struct team_option *find_option(struct team_handle *th,
				       struct team_option_id *opt_id,
				       bool must_exist)
{
	struct team_option *option;
	int err;

	option = do_find_option(th, opt_id);
	if (option)
		return option;
	if (must_exist)
		return NULL;
	/*
	 * In case option does not exist, create new uninitialized one
	 * which can be used for option tracking.
	 */
	err = create_option(&option, opt_id);
	if (err)
		return NULL;
	return option;
}

/**
 * team_get_option:
 * @th: libteam library context
 * @fmt: format string
 *
 * Get option structure referred by format sttring.
 *
 * Returns: pointer to option structure or NULL in case of an error.
 **/
TEAM_EXPORT
struct team_option *team_get_option(struct team_handle *th,
				    const char *fmt, ...)
{
	struct team_option_id opt_id = {};
	va_list ap;
	bool must_exist = true;

	va_start(ap, fmt);
	while (*fmt) {
		switch (*fmt++) {
		case 'n': /* name */
			opt_id.name = va_arg(ap, char *);
			break;
		case 'p': /* port_ifindex */
			opt_id.port_ifindex = va_arg(ap, uint32_t);
			opt_id.port_ifindex_used = true;
			break;
		case 'a': /* array index */
			opt_id.array_index = va_arg(ap, uint32_t);
			opt_id.array_index_used = true;
			break;
		case '!': /* option does not have to exist */
			must_exist = false;
			break;
		}
	}
	va_end(ap);

	return find_option(th, &opt_id, must_exist);
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
	struct team_option *next_option;

	next_option = list_get_next_node_entry(&th->option_list, option, list);
	if (next_option && !next_option->initialized)
		return team_get_next_option(th, next_option);
	return next_option;
}

/**
 * team_is_option_initialized:
 * @option: option structure
 *
 * See if option values are initialized.
 *
 * Returns: true if option is initialized.
 **/
TEAM_EXPORT
bool team_is_option_initialized(struct team_option *option)
{
	return option->initialized;
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
	return option->id.name;
}

/**
 * team_get_option_port_ifindex:
 * @option: option structure
 *
 * Get option port ifindex.
 *
 * Returns: port interface index.
 * to any port.
 **/
TEAM_EXPORT
uint32_t team_get_option_port_ifindex(struct team_option *option)
{
	return option->id.port_ifindex;
}

/**
 * team_is_option_per_port:
 * @option: option structure
 *
 * See if option is per-port.
 *
 * Returns: true if option is per-port.
 **/
TEAM_EXPORT
bool team_is_option_per_port(struct team_option *option)
{
	return option->id.port_ifindex_used;
}

/**
 * team_get_option_array_index:
 * @option: option structure
 *
 * Get option array index.
 *
 * Returns: array index.
 * to any port.
 **/
TEAM_EXPORT
uint32_t team_get_option_array_index(struct team_option *option)
{
	return option->id.array_index;
}

/**
 * team_is_option_array:
 * @option: option structure
 *
 * See if option is array.
 *
 * Returns: true if option is array.
 **/
TEAM_EXPORT
bool team_is_option_array(struct team_option *option)
{
	return option->id.array_index_used;
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
 * team_is_option_changed_locally:
 * @option: option structure
 *
 * See if option values got changed locally.
 *
 * Returns: true if option got changed locally.
 **/
TEAM_EXPORT
bool team_is_option_changed_locally(struct team_option *option)
{
	return option->changed_locally;
}

/**
 * team_get_option_value_len:
 * @option: option structure
 *
 * Get option value length.
 **/
TEAM_EXPORT
unsigned int team_get_option_value_len(struct team_option *option)
{
	return option->data_len;
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
 * team_get_option_value_binary:
 * @option: option structure
 *
 * Get option value as void pointer.
 *
 * Returns: pointer to data.
 **/
TEAM_EXPORT
void *team_get_option_value_binary(struct team_option *option)
{
	return option->data;
}

/**
 * team_get_option_value_bool:
 * @option: option structure
 *
 * Get option value as bool.
 *
 * Returns: bool.
 **/
TEAM_EXPORT
bool team_get_option_value_bool(struct team_option *option)
{
	return *((bool *) option->data);
}

/**
 * team_get_option_value_s32:
 * @option: option structure
 *
 * Get option value as signed 32-bit number.
 *
 * Returns: number.
 **/
TEAM_EXPORT
int32_t team_get_option_value_s32(struct team_option *option)
{
	return *((__s32 *) option->data);
}

static int local_set_option_value(struct team_handle *th,
				  struct team_option_id *opt_id, int opt_type,
				  const void *data, int data_len)
{
	struct team_option *option;
	int err;

	err = update_option(th, &option, opt_id, opt_type,
			    data, data_len, true, true);
	if (err)
		return err;
	return 0;
}

static int set_option_value(struct team_handle *th, struct team_option *option,
			    const void *data, int data_len, int opt_type)
{
	struct nl_msg *msg;
	struct nlattr *option_list;
	struct nlattr *option_item;
	int nla_type;
	int err;

	if (option->initialized && option->type != opt_type)
		return -EINVAL;

	switch (opt_type) {
	case TEAM_OPTION_TYPE_U32:
		nla_type = NLA_U32;
		break;
	case TEAM_OPTION_TYPE_STRING:
		nla_type = NLA_STRING;
		break;
	case TEAM_OPTION_TYPE_BINARY:
		nla_type = NLA_BINARY;
		break;
	case TEAM_OPTION_TYPE_BOOL:
		nla_type = NLA_FLAG;
		break;
	case TEAM_OPTION_TYPE_S32:
		nla_type = NLA_S32;
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
	NLA_PUT_STRING(msg, TEAM_ATTR_OPTION_NAME, option->id.name);
	if (option->id.port_ifindex_used)
		NLA_PUT_U32(msg, TEAM_ATTR_OPTION_PORT_IFINDEX,
			    option->id.port_ifindex);
	if (option->id.array_index_used)
		NLA_PUT_U32(msg, TEAM_ATTR_OPTION_ARRAY_INDEX,
			    option->id.array_index);
	NLA_PUT_U32(msg, TEAM_ATTR_OPTION_TYPE, nla_type);
	switch (nla_type) {
		case NLA_U32:
			NLA_PUT_U32(msg, TEAM_ATTR_OPTION_DATA, *((__u32 *) data));
			break;
		case NLA_STRING:
			NLA_PUT_STRING(msg, TEAM_ATTR_OPTION_DATA, (char *) data);
			break;
		case NLA_BINARY:
			NLA_PUT(msg, TEAM_ATTR_OPTION_DATA, data_len, (char *) data);
			break;
		case NLA_FLAG:
			if (*((bool *) data))
				NLA_PUT_FLAG(msg, TEAM_ATTR_OPTION_DATA);
			break;
		case NLA_S32:
			NLA_PUT_S32(msg, TEAM_ATTR_OPTION_DATA, *((__u32 *) data));
			break;
		default:
			goto nla_put_failure;
	}
	nla_nest_end(msg, option_item);
	nla_nest_end(msg, option_list);

	err = send_and_recv(th, msg, NULL, NULL);
	if (err) {
		return err;
	}

	err = local_set_option_value(th, &option->id, opt_type,
				     data, data_len);
	return err;

nla_put_failure:
	nlmsg_free(msg);
	return -ENOBUFS;
}

/**
 * team_set_option_value_u32:
 * @th: libteam library context
 * @option: option structure
 * @val: value to be set
 *
 * Set 32-bit number type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_u32(struct team_handle *th,
			      struct team_option *option, uint32_t val)
{
	return set_option_value(th, option, &val, 0,
				TEAM_OPTION_TYPE_U32);
}

/**
 * team_set_option_value_string:
 * @th: libteam library context
 * @option: option structure
 * @str: string to be set
 *
 * Set string type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_string(struct team_handle *th,
				 struct team_option *option, const char *str)
{
	return set_option_value(th, option, str, 0, TEAM_OPTION_TYPE_STRING);
}

/**
 * team_set_option_value_by_name_binary:
 * @th: libteam library context
 * @option: option structure
 * @data: binary data to be set
 * @data_len: binary data length
 *
 * Set binary type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_binary(struct team_handle *th,
				 struct team_option *option,
				 const void *data, unsigned int data_len)
{
	return set_option_value(th, option, data, data_len,
				TEAM_OPTION_TYPE_BINARY);
}

/**
 * team_set_option_value_by_name_bool:
 * @th: libteam library context
 * @option: option structure
 * @val: value to be set
 *
 * Set bool type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_bool(struct team_handle *th,
			       struct team_option *option, bool val)
{
	return set_option_value(th, option, &val, 0, TEAM_OPTION_TYPE_BOOL);
}

/**
 * team_set_option_value_s32:
 * @th: libteam library context
 * @option: option structure
 * @val: value to be set
 *
 * Set 32-bit signed number type option.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_s32(struct team_handle *th,
			      struct team_option *option, int32_t val)
{
	return set_option_value(th, option, &val, 0,
				TEAM_OPTION_TYPE_S32);
}
