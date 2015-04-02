/*
 *   teamd_runner_basic_ones.c - Basic team runners
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

#include "teamd.h"

const struct teamd_runner teamd_runner_broadcast = {
	.name		= "broadcast",
	.team_mode_name	= "broadcast",
};

const struct teamd_runner teamd_runner_roundrobin = {
	.name		= "roundrobin",
	.team_mode_name	= "roundrobin",
};

const struct teamd_runner teamd_runner_random = {
	.name		= "random",
	.team_mode_name	= "random",
};
