/*
 *   teamd_usock.h - Teamd unix socket api
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

#ifndef _TEAMD_USOCK_H_
#define _TEAMD_USOCK_H_

#include <stdio.h>
#include <errno.h>

#include "teamd.h"

#define TEAMD_USOCK_ERR_PREFIX	"ERROR\n"
#define TEAMD_USOCK_SUCC_PREFIX	"SUCCESS\n"

static inline void teamd_usock_get_sockpath(char *sockpath, size_t sockpath_len,
					    char *team_devname)
{
	snprintf(sockpath, sockpath_len, TEAMD_RUN_DIR"%s.sock", team_devname);
}

#endif /* _TEAMD_USOCK_H_ */
