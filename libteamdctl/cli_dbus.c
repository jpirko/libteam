/*
 *   cli_dbus.c - Teamd daemon control library D-Bus client
 *   Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
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

#include <private/misc.h>
#include <teamdctl.h>
#include "teamdctl_private.h"

struct dbus_priv {
};

static int dbus_init(struct teamdctl *tdc, const char *team_name, void *priv)
{
	return 0;
}

void dbus_fini(struct teamdctl *tdc, void *priv)
{

}

const struct teamdctl_cli teamdctl_cli_dbus = {
	.name = "dbus",
	.init = dbus_init,
	.fini = dbus_fini,
	.priv_size = sizeof(struct dbus_priv),
};
