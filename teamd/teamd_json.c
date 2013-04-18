/*
 *   teamd_json.c - Teamd common json stuff
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
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <errno.h>
#include <jansson.h>

#include "teamd_json.h"

static char *__strchrs(char *str, char *chars)
{
	char *tmp;

	while (*str != '\0') {
		tmp = chars;
		while (*tmp != '\0') {
			if (*tmp == *str)
				return str;
			tmp++;
		}
		str++;
	}
	return NULL;
}

#define TEAMD_JSON_PATH_MAXLEN 128

int __teamd_json_path_lite_va(json_t **p_json_obj, json_t *json_root,
			      bool build, const char *fmt, va_list ap)
{
	json_t *json_obj = json_root;
	json_t *prev_json_obj;
	char *ptr;
	char *end;
	char path[TEAMD_JSON_PATH_MAXLEN];
	size_t pathlen;
	int ret;

	if (*fmt == '@')
		json_obj = va_arg(ap, void *);
	else if (*fmt != '$')
		return -EINVAL;
	fmt++;

	ret = vsnprintf(path, sizeof(path), fmt, ap);
	if (ret < 0 || ret >= sizeof(path))
		return -EINVAL;

	pathlen = strlen(path);
	ptr = path;

	while (ptr - path < pathlen) {
		if (*ptr == '.') {
			char tmp;

			ptr++;
			end = __strchrs(ptr, ".[");
			if (end) {
				tmp = *end;
				*end = '\0';
			}
			prev_json_obj = json_obj;
			json_obj = json_object_get(prev_json_obj, ptr);
			if (!json_obj && build) {
				json_obj = json_object();
				if (!json_obj)
					return -ENOMEM;
				ret = json_object_set_new(prev_json_obj, ptr,
							  json_obj);
				if (ret)
					return -EINVAL;
			}
			if (end)
				*end = tmp;
			else
				end = ptr + strlen(ptr);
			ptr = end;
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
			ptr = end + 1;
		} else {
			return -EINVAL;
		}
		if (!json_obj)
			return -ENOENT;
	}
	*p_json_obj = json_obj;
	return 0;
}

int teamd_json_path_lite_va(json_t **p_json_obj, json_t *json_root,
			    const char *fmt, va_list ap)
{
	return __teamd_json_path_lite_va(p_json_obj, json_root, false, fmt, ap);
}

int teamd_json_path_lite(json_t **p_json_obj, json_t *json_root,
			 const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = teamd_json_path_lite_va(p_json_obj, json_root, fmt, ap);
	va_end(ap);
	return err;
}

int teamd_json_path_lite_build_va(json_t **p_json_obj, json_t *json_root,
				  const char *fmt, va_list ap)
{
	return __teamd_json_path_lite_va(p_json_obj, json_root, true, fmt, ap);
}

int teamd_json_path_lite_build(json_t **p_json_obj, json_t *json_root,
			       const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = teamd_json_path_lite_build_va(p_json_obj, json_root, fmt, ap);
	va_end(ap);
	return err;
}
