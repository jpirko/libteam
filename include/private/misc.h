/*
 *   misc.c - Miscellaneous helpers
 *   Copyright (C) 2011 Jiri Pirko <jpirko@redhat.com>
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

#ifndef _T_MISC_H_
#define _T_MISC_H_

#include <stdio.h>
#include <stdlib.h>

static inline void *myzalloc(size_t size)
{
	return calloc(1, size);
}

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static inline void hwaddr_str(char *str, char *hwaddr, size_t len)
{
	int i;

	for (i = 0; i < len; i++) {
		sprintf(str, "%02x:", (unsigned char) hwaddr[i]);
		str += 3;
	}
	*(str - 1) = '\0';
}

static inline size_t hwaddr_str_len(size_t len)
{
	return len * 3 + 1;
}

static inline char *a_hwaddr_str(char *hwaddr, size_t len)
{
	char *str;

	str = malloc(sizeof(char) * hwaddr_str_len(len));
	if (!str)
		return NULL;
	hwaddr_str(str, hwaddr, len);
	return str;
}

#endif /* _T_MISC_H_ */
