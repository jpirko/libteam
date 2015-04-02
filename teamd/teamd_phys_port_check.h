/*
 *   teamd_phys_port_check.h - Physical port checking support for teamd
 *   Copyright (C) 2013-2015 Jiri Pirko <jiri@resnulli.us>
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

#ifndef _TEAMD_PHYS_PORT_CHECK_H_
#define _TEAMD_PHYS_PORT_CHECK_H_

#include <jansson.h>

int teamd_phys_port_check_init(struct teamd_context *ctx);
void teamd_phys_port_check_fini(struct teamd_context *ctx);

#endif /* _TEAMD_PHYS_PORT_CHECK_H_ */
