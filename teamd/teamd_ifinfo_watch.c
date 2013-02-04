/*
 *   teamd_ifinfo_watch.c - Infrastructure for watching ifinfo changes
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
#include <string.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <private/list.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"

static int ifinfo_change_handler_func(struct team_handle *th, void *priv,
				      team_change_type_mask_t type_mask)
{
	struct teamd_context *ctx = priv;
	struct team_ifinfo *ifinfo;
	int err;

	team_for_each_ifinfo(ifinfo, th) {
		if (team_is_ifinfo_hwaddr_changed(ifinfo) ||
		    team_is_ifinfo_hwaddr_len_changed(ifinfo)) {
			err = teamd_event_ifinfo_hwaddr_changed(ctx, ifinfo);
			if (err)
				return err;
		}
		if (team_is_ifinfo_ifname_changed(ifinfo)) {
			err = teamd_event_ifinfo_ifname_changed(ctx, ifinfo);
			if (err)
				return err;
		}
	}
	return 0;
}

static struct team_change_handler ifinfo_change_handler = {
	.func = ifinfo_change_handler_func,
	.type_mask = TEAM_IFINFO_CHANGE,
};

int teamd_ifinfo_watch_init(struct teamd_context *ctx)
{
	return team_change_handler_register(ctx->th,
					    &ifinfo_change_handler, ctx);
}

void teamd_ifinfo_watch_fini(struct teamd_context *ctx)
{
	team_change_handler_unregister(ctx->th,
				       &ifinfo_change_handler, ctx);
}
