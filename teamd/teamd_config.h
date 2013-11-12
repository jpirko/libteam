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
int teamd_config_port_dump(struct teamd_context *ctx, const char *port_name,
			   char **p_config_port_dump);

struct teamd_config_path_cookie;
struct teamd_config_path_cookie *
teamd_config_path_cookie_get(struct teamd_context *ctx, const char *fmt, ...);

bool teamd_config_path_exists(struct teamd_context *ctx, const char *fmt, ...);
bool teamd_config_path_is_arr(struct teamd_context *ctx, const char *fmt, ...);
int teamd_config_string_get(struct teamd_context *ctx, const char **p_str_val,
			    const char *fmt, ...);
int teamd_config_string_set(struct teamd_context *ctx, const char *str_val,
			    const char *fmt, ...);
int teamd_config_int_get(struct teamd_context *ctx, int *p_int_val,
			 const char *fmt, ...);
int teamd_config_int_set(struct teamd_context *ctx, int int_val,
			 const char *fmt, ...);
int teamd_config_bool_get(struct teamd_context *ctx, bool *p_bool_val,
			  const char *fmt, ...);
const char *teamd_config_next_key(struct teamd_context *ctx, const char *key,
				  const char *fmt, ...);

#define teamd_config_for_each_key(key, ctx, args...)			\
	for (key = teamd_config_next_key(ctx, NULL, ##args); key;	\
	     key = teamd_config_next_key(ctx, key, ##args))

size_t teamd_config_arr_size(struct teamd_context *ctx, const char *fmt, ...);

#define teamd_config_for_each_arr_index(index, ctx, args...)	\
	for (index = 0; index < teamd_config_arr_size(ctx, ##args); index++)

size_t teamd_config_arr_string_append(struct teamd_context *ctx,
				      const char *str_val,
				      const char *fmt, ...);

#endif /* _TEAMD_CONFIG_H_ */
