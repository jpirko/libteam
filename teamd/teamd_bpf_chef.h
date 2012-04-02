/*
 *   teamd_bpf_chef.h - Cooking BPF functions for teamd
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

#ifndef _TEAMD_BPF_CHEF_H_
#define _TEAMD_BPF_CHEF_H_

#include <stdint.h>
#include <sys/types.h>

struct teamd_bpf_pattern {
	size_t		offset;
	uint8_t		type; /* BPF_B / BPF_H / BPF_W */
	uint32_t	value;
};

struct teamd_bpf_hash_field {
	size_t		offset; /* offset of element in header */
	uint8_t		type; /* BPF_B / BPF_H / BPF_W */
};

/*
 * Description of to-be-compiled BPF function.
 * Pattern will be used to check if packet matches that. If not, nothing is
 * done. If yes, final hash will be computed from given fields.
 */
struct teamd_bpf_desc_frag {
	char *					name;
	const struct teamd_bpf_pattern *	pattern;
	unsigned int				pattern_count;
	const struct teamd_bpf_hash_field *	hash_field;
	unsigned int				hash_field_count;
};

void teamd_bpf_desc_compile_start(struct sock_fprog *fprog);
void teamd_bpf_desc_compile_release(struct sock_fprog *fprog);
int teamd_bpf_desc_compile_finish(struct sock_fprog *fprog);
int teamd_bpf_desc_compile_frag(struct sock_fprog *fprog,
				const struct teamd_bpf_desc_frag *frag);

#endif /* _TEAMD_BPF_CHEF_H_ */
