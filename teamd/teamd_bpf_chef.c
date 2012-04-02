/*
 *   teamd_bpf_chef.c - Cooking BPF functions for teamd
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
#include <errno.h>
#include <linux/filter.h>

#include "teamd_bpf_chef.h"

static int __add_inst(struct sock_fprog *fprog, struct sock_filter *inst)
{
	ssize_t newsize;
	struct sock_filter *newfilter;

	newsize = sizeof(struct sock_filter) * (fprog->len + 1);
	newfilter = realloc(fprog->filter, newsize);
	if (!newfilter)
		return -ENOMEM;
	fprog->filter = newfilter;
	fprog->filter[fprog->len] = *inst;
	fprog->len += 1;
	return 0;
}

#define add_inst(fprog, __inst)				\
	{						\
		struct sock_filter inst = __inst;	\
		err = __add_inst(fprog, &inst);		\
		if (err)				\
			goto err_add_inst;		\
	}

static void __compile_init(struct sock_fprog *fprog)
{
	fprog->len = 0;
	fprog->filter = NULL;
}

void teamd_bpf_desc_compile_start(struct sock_fprog *fprog)
{
	__compile_init(fprog);
}

void teamd_bpf_desc_compile_release(struct sock_fprog *fprog)
{
	free(fprog->filter);
	__compile_init(fprog);
}

int teamd_bpf_desc_compile_finish(struct sock_fprog *fprog)
{
	int err;

	/*
	 * Return hash which is in X. Note that in case of no pattern match,
	 * X will have value 0.
	 */
	add_inst(fprog, BPF_STMT(BPF_MISC + BPF_TXA, 0));
	add_inst(fprog, BPF_STMT(BPF_RET + BPF_A, 0));
	return 0;
err_add_inst:
	return err;
}

int teamd_bpf_desc_compile_frag(struct sock_fprog *fprog,
				const struct teamd_bpf_desc_frag *frag)
{
	int err;
	int i;
	unsigned short start_index = fprog->len;

	/*
	 * Put pattern matching first. Patterns are checked sequentially,
	 * if one pattern match fails, jump to the end is going to be done.
	 * Note that end of frag is not known atm so put __JMP_END there for
	 * now. Last loop in this function will correct this.
	 */
#define __JMP_END 0xFF

	for (i = 0; i < frag->pattern_count; i++) {
		const struct teamd_bpf_pattern *pattern = &frag->pattern[i];

		add_inst(fprog, BPF_STMT(BPF_LD + pattern->type + BPF_ABS,
					 pattern->offset));
		add_inst(fprog, BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
					 pattern->value, 0, __JMP_END));
	}

	/*
	 * If patterns matches (no JUMP_TO_END), compute hash from specified
	 * memory fields. Store the hash in X.
	 */
	for (i = 0; i < frag->hash_field_count; i++) {
		const struct teamd_bpf_hash_field *hfield = &frag->hash_field[i];

		add_inst(fprog, BPF_STMT(BPF_LD + hfield->type + BPF_ABS,
					 hfield->offset));
		add_inst(fprog, BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
					 SKF_AD_OFF + SKF_AD_ALU_XOR_X));
		add_inst(fprog, BPF_STMT(BPF_MISC + BPF_TAX, 0));
	}

	/* Correct jump offsets */
	for (i = start_index; i < fprog->len; i++) {
		struct sock_filter *filter = &fprog->filter[i];

		if (filter->code == BPF_JMP + BPF_JEQ + BPF_K &&
		    filter->jf == __JMP_END)
			filter->jf = fprog->len - i - 1;
	}

	return 0;
err_add_inst:
	return err;
}
