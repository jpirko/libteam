/*
 *   teamd_json.h - Teamd common json related things
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

#ifndef _TEAMD_JSON_H_
#define _TEAMD_JSON_H_

#include <jansson.h>

#define TEAMD_JSON_DUMPS_FLAGS (JSON_INDENT(4) | JSON_ENSURE_ASCII | JSON_SORT_KEYS)

int teamd_json_path_lite_va(json_t **p_json_obj, json_t *json_root,
			    const char *fmt, va_list ap);
int teamd_json_path_lite(json_t **p_json_obj, json_t *json_root,
			 const char *fmt, ...);

#endif /* _TEAMD_JSON_H_ */
