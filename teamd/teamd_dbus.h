/*
 *   teamd_dbus.h - Teamd dbus api
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

#include "config.h"

#ifndef _TEAMD_DBUS_H_
#define _TEAMD_DBUS_H_

#ifdef ENABLE_DBUS

int teamd_dbus_init(struct teamd_context *ctx);
void teamd_dbus_fini(struct teamd_context *ctx);
int teamd_dbus_expose_name(struct teamd_context *ctx);

#else

static inline int teamd_dbus_init(struct teamd_context *ctx)
{
	return 0;
}

static inline void teamd_dbus_fini(struct teamd_context *ctx)
{
}

static inline int teamd_dbus_expose_name(struct teamd_context *ctx)
{
	return 0;
}

#endif

#endif /* _TEAMD_DBUS_H_ */
