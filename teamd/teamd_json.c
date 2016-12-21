/*
 *   teamd_json.c - Teamd common json stuff
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

typedef json_t *(*obj_constructor_t)(void);

static int __teamd_json_path_lite_va(json_t **p_json_obj, json_t *json_root,
				     obj_constructor_t obj_constructor,
				     const char *fmt, va_list ap)
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
			char tmp = 0; /* gcc needs this initialized */

			ptr++;
			if (*ptr == '\"') {
				ptr++;
				end = strrchr(ptr, '\"');
				if (end) {
					*end = '\0';
					end++;
				}
			} else {
				end = __strchrs(ptr, ".[");
			}
			if (end) {
				tmp = *end;
				*end = '\0';
			}
			prev_json_obj = json_obj;
			json_obj = json_object_get(prev_json_obj, ptr);
			if (!json_obj && obj_constructor) {
				/* In case new object is not supposed to be
				 * leaf, use json_object() as a constructor.
				 */
				json_obj = end ? json_object() : obj_constructor();
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
	return __teamd_json_path_lite_va(p_json_obj, json_root, NULL, fmt, ap);
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
	return __teamd_json_path_lite_va(p_json_obj, json_root,
					 json_object, fmt, ap);
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

static json_t *string_constructor()
{
	return json_string("");
}

static json_t *int_constructor()
{
	return json_integer(0);
}

static json_t *true_constructor()
{
	return json_true();
}

static json_t *false_constructor()
{
	return json_false();
}

static json_t *array_constructor()
{
	return json_array();
}

int teamd_json_path_lite_build_type_va(json_t **p_json_obj, json_t *json_root,
				       json_type obj_type,
				       const char *fmt, va_list ap)
{
	obj_constructor_t obj_constructor;
	int err;

	switch (obj_type) {
	case JSON_STRING:
		obj_constructor = string_constructor;
		break;
	case JSON_INTEGER:
		obj_constructor = int_constructor;
		break;
	case JSON_TRUE:
		obj_constructor = true_constructor;
		break;
	case JSON_FALSE:
		obj_constructor = false_constructor;
		break;
	case JSON_ARRAY:
		obj_constructor = array_constructor;
		break;
	default:
		return -EINVAL;
	}
	err = __teamd_json_path_lite_va(p_json_obj, json_root,
					obj_constructor, fmt, ap);
	if (err)
		return err;
	if (json_typeof(*p_json_obj) != obj_type)
		return -EINVAL;
	return 0;
}

int teamd_json_path_lite_build_type(json_t **p_json_obj, json_t *json_root,
				    json_type obj_type, const char *fmt, ...)
{
	va_list ap;
	int err;

	va_start(ap, fmt);
	err = teamd_json_path_lite_build_type_va(p_json_obj, json_root,
						 obj_type, fmt, ap);
	va_end(ap);
	return err;
}
