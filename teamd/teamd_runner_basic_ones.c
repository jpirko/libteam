/*
 * teamd_runner_basic_ones.c - Basic team runners
 * Copyright (c) 2012 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#include "teamd.h"

const struct teamd_runner teamd_runner_dummy = {
	.name = "dummy",
};

const struct teamd_runner teamd_runner_roundrobin = {
	.name		= "roundrobin",
	.team_mode_name	= "roundrobin",
};
