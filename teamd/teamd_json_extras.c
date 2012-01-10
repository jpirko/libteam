/*
 *   teamd_json_extras.c - Teamd specific json-c extras
 *   Copyright (C) 2012 Jiri Pirko <jpirko@redhat.com>
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

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <json/json.h>

static int get_string_index(char *in_brackets, char **str_index)
{
	int len = strlen(in_brackets);

	if ((len < 2) ||
	    !((in_brackets[0] == '\"' && in_brackets[len - 1] == '\"') ||
	    (in_brackets[0] == '\'' && in_brackets[len - 1] == '\'')))
		return -1;

	in_brackets[len - 1] = '\0';
	*str_index = in_brackets + 1;

	return 0;
}

static int get_num_index(char *in_brackets, int *num_index)
{
	char *endptr;
	long val;

	errno = 0;
	val = strtol(in_brackets, &endptr, 10);

	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) ||
	    (errno != 0 && val == 0) ||
	    (endptr == in_brackets) ||
	    (*endptr != '\0') ||
	    (val > INT_MAX) ||
	    (val < INT_MIN))
		return -1;

	*num_index = val;
	return 0;
}

static const char *cut_query(const char *query)
{
	while (*query != '\0') {
		if ((*query == ']') && (*(query - 1) != '\\')) {
			query++;
			break;
		}
		query++;
	}
	return query;
}

json_object *teamd_json_object_simple_query(json_object *jso,
					    const char *query)
{
	int err;
	json_object *n_jso = NULL;
	const char *query_next;
	char *in_brackets;
	char *str_index;
	int num_index;

	if (strlen(query) == 0 || !jso)
		return jso;

	query_next = cut_query(query);
	in_brackets = strndup(query + 1, query_next - query - 2);
	if (!in_brackets)
		return NULL;

	err = get_string_index(in_brackets, &str_index);
	if (!err) {
		if (json_object_get_type(jso) != json_type_object)
			goto errout;
		n_jso = json_object_object_get(jso, str_index);
	} else {
		err = get_num_index(in_brackets, &num_index);
		if (!err) {
			if (json_object_get_type(jso) != json_type_array)
				goto errout;
			if (num_index < 0)
				goto errout;
			n_jso = json_object_array_get_idx(jso, num_index);
		} else {
			goto errout;
		}
	}

	n_jso = teamd_json_object_simple_query(n_jso, query_next);

errout:
	free(in_brackets);
	return n_jso;
}
