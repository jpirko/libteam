/*
 *   stringify.c - Helpers for conversion team objects to string
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
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

#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <errno.h>
#include <team.h>
#include <private/misc.h>
#include "team_private.h"

static char *__get_port_ifname(struct team_handle *th, uint32_t port_ifindex)
{
	struct team_port *port;

	team_for_each_port(port, th) {
		struct team_ifinfo *ifinfo = team_get_port_ifinfo(port);

		if (port_ifindex == team_get_port_ifindex(port))
			return team_get_ifinfo_ifname(ifinfo);
	}
	return NULL;
}

static bool __buf_append(char **pbuf, size_t *pbufsiz, const char *fmt, ...)
{
	va_list ap;
	size_t n;

	va_start(ap, fmt);
	n = vsnprintf(*pbuf, *pbufsiz, fmt, ap);
	va_end(ap);
	if (n >= *pbufsiz)
		return true;
	*pbuf += n;
	*pbufsiz -= n;
	return false;
}

static bool __team_option_value_str(struct team_option *option,
				    char **pbuf, size_t *pbufsiz, bool plain)
{
	bool trunc;

	switch (team_get_option_type(option)) {
	case TEAM_OPTION_TYPE_U32:
		trunc = __buf_append(pbuf, pbufsiz, "%u",
				     team_get_option_value_u32(option));
		if (trunc)
			return true;
		break;
	case TEAM_OPTION_TYPE_STRING:
		trunc = __buf_append(pbuf, pbufsiz, "%s%s%s",
				     plain ? "" : "\"",
				     team_get_option_value_string(option),
				     plain ? "" : "\"");
		if (trunc)
			return true;
		break;
	case TEAM_OPTION_TYPE_BINARY:
		{
			unsigned int len = team_get_option_value_len(option);
			char *data = team_get_option_value_binary(option);
			int i;
			unsigned char c;

			for (i = 0; i < len; i++) {
				c = data[i];
				trunc = __buf_append(pbuf, pbufsiz,
						     "\\%02x", c);
				if (trunc)
					return true;
			}
		}
		break;
	case TEAM_OPTION_TYPE_BOOL:
		trunc = __buf_append(pbuf, pbufsiz, "%s",
				     team_get_option_value_bool(option) ?
				     "true" : "false");
		if (trunc)
			return true;
		break;
	case TEAM_OPTION_TYPE_S32:
		trunc = __buf_append(pbuf, pbufsiz, "%d",
				     team_get_option_value_s32(option));
		if (trunc)
			return true;
		break;
	default:
		trunc = __buf_append(pbuf, pbufsiz, "<unknown>");
		if (trunc)
			return true;
		break;
	}
	return false;
}

/**
 * team_option_value_str:
 * @option: option structure
 * @buf: buffer where string will be stored
 * @bufsiz: available buffer size
 *
 * Converts option value to string.
 *
 * Returns: true in case buffer is not big enough to contain whole string.
 **/
TEAM_EXPORT
bool team_option_value_str(struct team_option *option, char *buf, size_t bufsiz)
{
	return __team_option_value_str(option, &buf, &bufsiz, true);
}

static int __set_optval_from_str_u32(struct team_handle *th,
				     struct team_option *option,
				     const char *str)
{
	uint32_t val;
	unsigned long int tmp;
	char *endptr;

	tmp = strtoul(str, &endptr, 10);
	if (tmp == ULONG_MAX)
		return -errno;
	if (strlen(endptr) != 0)
		return -EINVAL;
	val = tmp;
	if (tmp != val)
		return -ERANGE;
	return team_set_option_value_u32(th, option, val);
}

static int __set_optval_from_str_s32(struct team_handle *th,
				     struct team_option *option,
				     const char *str)
{
	int32_t val;
	long int tmp;
	char *endptr;

	tmp = strtol(str, &endptr, 10);
	if (tmp == LONG_MIN || tmp == LONG_MAX)
		return -errno;
	if (strlen(endptr) != 0)
		return -EINVAL;
	val = tmp;
	if (tmp != val)
		return -ERANGE;
	return team_set_option_value_s32(th, option, val);
}

static int __one_char_from_str(char *pc, char *byte_str)
{
	unsigned long int tmp;
	char *endptr;
	unsigned char c;

	if (byte_str[0] != '\\')
		return -EINVAL;

	tmp = strtoul(byte_str + 1, &endptr, 16);
	if (tmp == ULONG_MAX)
		return -errno;
	if (strlen(endptr) != 0)
		return -EINVAL;
	c = tmp;
	if (tmp != c)
		return -ERANGE;
	*pc = c;
	return 0;
}

static int __set_optval_from_str_binary(struct team_handle *th,
					struct team_option *option,
					const char *str)
{
	char byte_str[4];
	char *buf;
	size_t i;
	size_t numbytes;
	int err;

	if (strlen(str) % 3)
		return -EINVAL;
	numbytes = strlen(str) / 3;
	buf = malloc(numbytes);
	if (!buf)
		return -ENOMEM;
	byte_str[3] = '\0';
	for (i = 0; i < numbytes; i++) {
		memcpy(byte_str, str, 3);
		err = __one_char_from_str(&buf[i], byte_str);
		if (err)
			goto errout;
		str += 3;
	}

	err = team_set_option_value_binary(th, option, buf, numbytes);
errout:
	free(buf);
	return err;
}

static int __set_optval_from_str_bool(struct team_handle *th,
				      struct team_option *option,
				      const char *str)
{
	bool val;

	if (!strcmp(str, "true"))
		val = true;
	else if (!strcmp(str, "false"))
		val = false;
	else
		return -EINVAL;
	return team_set_option_value_bool(th, option, val);
}

/**
 * team_set_option_value_from_string:
 * @th: libteam library context
 * @option: option structure
 * @str: string containing option value
 *
 * Convert option value from string and set it.
 *
 * Returns: zero on success or negative number in case of an error.
 **/
TEAM_EXPORT
int team_set_option_value_from_string(struct team_handle *th,
				      struct team_option *option,
				      const char *str)
{
	switch (team_get_option_type(option)) {
	case TEAM_OPTION_TYPE_U32:
		return __set_optval_from_str_u32(th, option, str);
	case TEAM_OPTION_TYPE_STRING:
		return team_set_option_value_string(th, option, str);
	case TEAM_OPTION_TYPE_BINARY:
		return __set_optval_from_str_binary(th, option, str);
	case TEAM_OPTION_TYPE_BOOL:
		return __set_optval_from_str_bool(th, option, str);
	case TEAM_OPTION_TYPE_S32:
		return __set_optval_from_str_s32(th, option, str);
	default:
		return -EINVAL;
	}
}

static bool __team_option_str(struct team_handle *th,
			      struct team_option *option,
			      char **pbuf, size_t *pbufsiz)
{
	char *name = team_get_option_name(option);
	bool trunc;

	trunc = __buf_append(pbuf, pbufsiz, "%s%s ",
			     team_is_option_changed(option) ? "*" : " ", name);
	if (trunc)
		return true;

	if (team_is_option_per_port(option)) {
		char *port_ifname;
		uint32_t port_ifindex;

		port_ifindex = team_get_option_port_ifindex(option);
		port_ifname = __get_port_ifname(th, port_ifindex);
		if (!port_ifname)
			port_ifname = "";
		trunc = __buf_append(pbuf, pbufsiz, "(port:%s) ", port_ifname);
		if (trunc)
			return true;
	}

	if (team_is_option_array(option)) {
		trunc = __buf_append(pbuf, pbufsiz, "(arridx:%u) ",
				     team_get_option_array_index(option));
		if (trunc)
			return true;
	}

	trunc = __team_option_value_str(option, pbuf, pbufsiz, true);
	if (trunc)
		return true;

	return false;
}

/**
 * team_option_str:
 * @th: libteam library context
 * @option: option structure
 * @buf: buffer where string will be stored
 * @bufsiz: available buffer size
 *
 * Converts option structure to string.
 *
 * Returns: true in case buffer is not big enough to contain whole string.
 **/
TEAM_EXPORT
bool team_option_str(struct team_handle *th, struct team_option *option,
		     char *buf, size_t bufsiz)
{
	return __team_option_str(th, option, &buf, &bufsiz);
}

static bool __team_port_str(struct team_port *port,
			    char **pbuf, size_t *pbufsiz)
{
	uint32_t ifindex = team_get_port_ifindex(port);
	struct team_ifinfo *ifinfo = team_get_port_ifinfo(port);

	return __buf_append(pbuf, pbufsiz, "%s%d: %s: %s %uMbit %s",
			    team_is_port_removed(port) ? "-" :
				team_is_port_changed(port) ? "*" : " ",
			    ifindex,
			    team_get_ifinfo_ifname(ifinfo),
			    team_is_port_link_up(port) ? "up": "down",
			    team_get_port_speed(port),
			    team_get_port_duplex(port) ? "FD" : "HD");
}

/**
 * team_port_str:
 * @port: port structure
 * @buf: buffer where string will be stored
 * @bufsiz: available buffer size
 *
 * Converts port structure to string.
 *
 * Returns: true in case buffer is not big enough to contain whole string.
 **/
TEAM_EXPORT
bool team_port_str(struct team_port *port, char *buf, size_t bufsiz)
{
	return __team_port_str(port, &buf, &bufsiz);
}

static bool __team_ifinfo_str(struct team_ifinfo *ifinfo,
			      char **pbuf, size_t *pbufsiz)
{
	uint32_t ifindex = team_get_ifinfo_ifindex(ifinfo);
	size_t hwaddr_len = team_get_ifinfo_hwaddr_len(ifinfo);
	char str[hwaddr_str_len(hwaddr_len)];

	hwaddr_str(str, team_get_ifinfo_hwaddr(ifinfo), hwaddr_len);
	return __buf_append(pbuf, pbufsiz, "%s%d: %s%s: %s%s: %s%d",
			    team_is_ifinfo_changed(ifinfo) ? "*" : " ",
			    ifindex,
			    team_is_ifinfo_ifname_changed(ifinfo) ? "*" : "",
			    team_get_ifinfo_ifname(ifinfo),
			    team_is_ifinfo_hwaddr_len_changed(ifinfo) ||
			    team_is_ifinfo_hwaddr_changed(ifinfo) ? "*" : "",
			    str,
			    team_is_ifinfo_master_ifindex_changed(ifinfo) ? "*" : "",
			    team_get_ifinfo_master_ifindex(ifinfo));
}

/**
 * team_ifinfo_str:
 * @ifinfo: ifinfo structure
 * @buf: buffer where string will be stored
 * @bufsiz: available buffer size
 *
 * Converts ifinfo structure to string.
 *
 * Returns: true in case buffer is not big enough to contain whole string.
 **/
TEAM_EXPORT
bool team_ifinfo_str(struct team_ifinfo *ifinfo, char *buf, size_t bufsiz)
{
	return __team_ifinfo_str(ifinfo, &buf, &bufsiz);
}
