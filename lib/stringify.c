/*
 *   stringify.c - Helpers for conversion team objects to string
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <team.h>
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

			for (i = 0; i < len; i++) {
				trunc = __buf_append(pbuf, pbufsiz,
						     "\\%02x", data[i]);
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

static bool __team_option_str(struct team_handle *th,
			      struct team_option *option,
			      char **pbuf, size_t *pbufsiz)
{
	char *name = team_get_option_name(option);
	bool trunc;

	trunc = __buf_append(pbuf, pbufsiz, "%s ", name);
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

	return __buf_append(pbuf, pbufsiz, "%d: %s: %s %u %s%s%s", ifindex,
			    team_get_ifinfo_ifname(ifinfo),
			    team_is_port_link_up(port) ? "up": "down",
			    team_get_port_speed(port),
			    team_get_port_duplex(port) ? "fullduplex" : "halfduplex",
			    team_is_port_changed(port) ? " changed" : "",
			    team_is_port_removed(port) ? " removed" : "");
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
