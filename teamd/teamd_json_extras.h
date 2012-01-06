/*
 * teamd_json_extras.h - Teamd specific json-c extras
 * Copyright (c) 2012 Jiri Pirko <jpirko@redhat.com>
 *
 * This library is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation version 2.1 of the License.
 */

#ifndef _TEAMD_JSON_EXTRAS_H_
#define _TEAMD_JSON_EXTRAS_H_

#include <json/json.h>

json_object *teamd_json_object_simple_query(json_object *jso,
					    const char *query);

#endif /* _TEAMD_JSON_EXTRAS_H_ */
