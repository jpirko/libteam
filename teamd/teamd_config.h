/*
 *   teamd_config.h - Teamd configuration frontend
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

#ifndef _TEAMD_CONFIG_H_
#define _TEAMD_CONFIG_H_

#include <stdbool.h>

#include "teamd.h"

int teamd_config_load(struct teamd_context *ctx);
void teamd_config_free(struct teamd_context *ctx);
int teamd_config_dump(struct teamd_context *ctx, char **p_config_dump);
int teamd_config_actual_dump(struct teamd_context *ctx, char **p_config_dump);
int teamd_config_port_update(struct teamd_context *ctx, const char *port_name,
			     const char *json_port_cfg_str);
int teamd_config_string_get(struct teamd_context *ctx, const char **p_str_val,
			    const char *fmt, ...);
int teamd_config_int_get(struct teamd_context *ctx, int *p_int_val,
			 const char *fmt, ...);
int teamd_config_bool_get(struct teamd_context *ctx, bool *p_bool_val,
			  const char *fmt, ...);

#endif /* _TEAMD_CONFIG_H_ */
