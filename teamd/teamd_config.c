/*
 *   teamd_config.c - Teamd configuration frontend
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

#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <jansson.h>

#include "teamd.h"

static int __json_path_lite(json_t **p_json_obj, json_t *json_root,
			    const char *fmt, va_list ap)
{
	json_t *json_obj = json_root;
	char *ptr;
	char *end;
	char path[128];
	size_t pathlen;
	int ret;

	ret = vsnprintf(path, sizeof(path), fmt, ap);
	if (ret < 0 || ret >= sizeof(path))
		return -EINVAL;

	pathlen = strlen(path);
	ptr = path;

	if (*ptr != '$')
		return -EINVAL;
	ptr++;
	while (ptr - path < pathlen) {
		if (*ptr == '.') {
			ptr++;
			end = strchr(ptr, '.');
			if (end)
				*end = '\0';
			json_obj = json_object_get(json_obj, ptr);
		} else if (*ptr == '[') {
			int i;

			ptr++;
			end = strchr(ptr, ']');
			if (!end)
				return -EINVAL;
			*end = '\0';
			for (i = 0; i < strlen(ptr); i++)
				if (!isdigit(ptr[i]))
					return -EINVAL;
			json_obj = json_array_get(json_obj, atoi(ptr));
		} else {
			return -EINVAL;
		}
		if (!json_obj)
			return -ENOENT;
		ptr = end + 1;
	}
	*p_json_obj = json_obj;
	return 0;
}

static int teamd_config_object_get(struct teamd_context *ctx,
				   json_t **p_json_obj,
				   const char *fmt, va_list ap)
{
	int err;

	err = __json_path_lite(p_json_obj, ctx->config_json, fmt, ap);
	if (err) {
		if (err == -EINVAL)
			teamd_log_err("Failed to get value from config: Wrong path format");
		return err;
	}
	return 0;
}

int teamd_config_string_get(struct teamd_context *ctx, const char **p_str_val,
			    const char *fmt, ...)
{
	va_list ap;
	json_t *json_obj = json_obj;
	int err;

	va_start(ap, fmt);
	err = teamd_config_object_get(ctx, &json_obj, fmt, ap);
	va_end(ap);
	if (err)
		return err;

	if (!json_is_string(json_obj)) {
		teamd_log_err("Failed to get string from non-string object");
		return -ENOENT;
	}
	*p_str_val = json_string_value(json_obj);
	return 0;
}

int teamd_config_int_get(struct teamd_context *ctx, int *p_int_val,
			 const char *fmt, ...)
{
	va_list ap;
	json_t *json_obj = json_obj;
	int err;

	va_start(ap, fmt);
	err = teamd_config_object_get(ctx, &json_obj, fmt, ap);
	va_end(ap);
	if (err)
		return err;

	if (!json_is_integer(json_obj)) {
		teamd_log_err("Failed to get integer from non-integer object");
		return -ENOENT;
	}
	*p_int_val = json_integer_value(json_obj);
	return 0;
}

int teamd_config_bool_get(struct teamd_context *ctx, bool *p_bool_val,
			  const char *fmt, ...)
{
	va_list ap;
	json_t *json_obj = json_obj;
	int err;

	va_start(ap, fmt);
	err = teamd_config_object_get(ctx, &json_obj, fmt, ap);
	va_end(ap);
	if (err)
		return err;

	if (!json_is_boolean(json_obj)) {
		teamd_log_err("Failed to get boolean from non-boolean object");
		return -ENOENT;
	}
	*p_bool_val = json_is_true(json_obj) ? true : false;
	return 0;
}
