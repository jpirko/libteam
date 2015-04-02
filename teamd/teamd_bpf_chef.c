/*
 *   teamd_bpf_chef.c - Cooking BPF functions for teamd
 *   Copyright (C) 2012-2015 Jiri Pirko <jiri@resnulli.us>
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
#include <stdbool.h>
#include <linux/filter.h>

#include "teamd_bpf_chef.h"

/* protocol offsets */
#define ETH_TYPE_OFFSET		12
#define IPV4_FLAGS_OFFSET	20
#define IPV4_PROTO_OFFSET	23
#define IPV4_FRAG_BITS		0x1fff
#define IPV6_NEXTHEADER_OFFSET	20


/* protocol codes */
#define PROTOID_IPV4		0x800
#define PROTOID_IPV6		0x86dd
#define PROTOID_TCP		0x6
#define PROTOID_UDP		0x11
#define PROTOID_SCTP		0x84

/* jump stack flags */
#define FIX_JT	0x1
#define FIX_JF	0x2
#define FIX_K	0x4


#define VLAN_HEADER_SIZE 2
static int vlan_hdr_shift(unsigned int offset)
{
	return offset + VLAN_HEADER_SIZE;
}

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

#define bpf_load_byte(pos)						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_B + BPF_ABS, pos))

#define bpf_load_half(pos)						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_H + BPF_ABS, pos))

#define bpf_load_word(pos)						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_W + BPF_ABS, pos))

#define bpf_push_a()							\
	add_inst(fprog, BPF_STMT(BPF_ST, 0))

#define bpf_push_x()							\
	add_inst(fprog, BPF_STMT(BPF_STX, 0))

#define bpf_pop_x()							\
	add_inst(fprog, BPF_STMT(BPF_LDX + BPF_W + BPF_MEM, 0))

#define bpf_calc_hash()							\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_B + BPF_ABS,		\
				 SKF_AD_OFF + SKF_AD_ALU_XOR_X))

#define bpf_move_to_x()							\
	add_inst(fprog, BPF_STMT(BPF_MISC + BPF_TAX, 0));

#define bpf_move_to_a()							\
	add_inst(fprog, BPF_STMT(BPF_MISC + BPF_TXA, 0));

#define bpf_return_a()							\
	add_inst(fprog, BPF_STMT(BPF_RET + BPF_A, 0));

#define bpf_cmp(jt, jf, k, flags)					\
	do {								\
		add_inst(fprog, BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,	\
					 k, jt, jf));			\
		push_addr(fprog, flags);				\
	} while (0)

#define bpf_jump(k)							\
	do {								\
		add_inst(fprog, BPF_JUMP(BPF_JMP + BPF_JA, k, 0, 0));	\
		push_addr(fprog, FIX_K);				\
	} while (0)


#define bpf_and(jt, jf, k, flags)					\
	do {								\
		add_inst(fprog, BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K,	\
					 k, jt, jf));			\
		push_addr(fprog, flags);				\
	} while (0)


#define bpf_vlan_tag_present()						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_B + BPF_ABS,		\
				 SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT))

#define bpf_vlan_tag_id()						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_B + BPF_ABS,		\
				 SKF_AD_OFF + SKF_AD_VLAN_TAG))

#define bpf_ipv4_len_to_x(pos)						\
	add_inst(fprog, BPF_STMT(BPF_LDX + BPF_B + BPF_MSH, pos))

#define bpf_l4v4_port_to_a(pos)						\
	add_inst(fprog, BPF_STMT(BPF_LD + BPF_H + BPF_IND, pos))

#define bpf_hash_return()						\
	do {								\
		bpf_move_to_a();					\
		bpf_return_a();						\
	} while(0)


enum bpf_labels {
	LABEL_VLAN_BRANCH,
	LABEL_NOVLAN_IPV6,
	LABEL_NOVLAN_L4v4_OUT,
	LABEL_NOVLAN_TRY_UDP4,
	LABEL_NOVLAN_L4v4_HASH,
	LABEL_NOVLAN_TRY_STCP4,
	LABEL_NOVLAN_IPV6_CONTINUE,
	LABEL_NOVLAN_TRY_UDP6,
	LABEL_NOVLAN_L4v6_OUT,
	LABEL_NOVLAN_L4v6_HASH,
	LABEL_NOVLAN_TRY_STCP6,
	LABEL_VLAN_IPV6,
	LABEL_VLAN_L4v4_OUT,
	LABEL_VLAN_TRY_UDP4,
	LABEL_VLAN_L4v4_HASH,
	LABEL_VLAN_TRY_STCP4,
	LABEL_VLAN_IPV6_CONTINUE,
	LABEL_VLAN_TRY_UDP6,
	LABEL_VLAN_L4v6_OUT,
	LABEL_VLAN_L4v6_HASH,
	LABEL_VLAN_TRY_STCP6,
};

/* stack */
struct stack_entry {
	struct stack_entry *next;
	unsigned int addr;
	union {
		enum bpf_labels label;
		int flags;
	};
};

static struct stack_entry *stack_labels;
static struct stack_entry *stack_addrs;

enum hashing_flags {
	HASH_ETH,
	HASH_VLAN,
	HASH_VLAN_IPV4,
	HASH_VLAN_IPV6,
	HASH_VLAN_UDP4,
	HASH_VLAN_TCP4,
	HASH_VLAN_SCTP4,
	HASH_VLAN_UDP6,
	HASH_VLAN_TCP6,
	HASH_VLAN_SCTP6,
	HASH_NOVLAN_IPV4,
	HASH_NOVLAN_IPV6,
	HASH_NOVLAN_UDP4,
	HASH_NOVLAN_TCP4,
	HASH_NOVLAN_SCTP4,
	HASH_NOVLAN_UDP6,
	HASH_NOVLAN_TCP6,
	HASH_NOVLAN_SCTP6,
};

struct hash_flags {
	unsigned int required;
	unsigned int built;
};

static struct hash_flags hflags;

static void hash_flags_init(struct hash_flags *flags)
{
	flags->required = 0;
	flags->built = 0;
}

static int hash_test_and_set_flag(struct hash_flags *flags,
				  enum hashing_flags hflag)
{
	int flag = 1 << hflag;
	int ret;

	ret = 0;
	if (flags->required & flag) {
		flags->built |= flag;
		ret = 1;
	}

	return ret;
}

static int hash_is_complete(struct hash_flags *flags)
{
	return flags->built == flags->required;
}

static int hash_set_enable(struct hash_flags *flags, enum hashing_flags hflag)
{
	flags->required |= (1 << hflag);
	return 0;
}

static int hash_is_enabled(struct hash_flags *flags, enum hashing_flags hflag)
{
	return (flags->required & (1 << hflag));
}

static int hash_is_l4v4_enabled(struct hash_flags *flags)
{
	if (hash_is_enabled(flags, HASH_NOVLAN_TCP4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_UDP4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_SCTP4) ||
	    hash_is_enabled(flags, HASH_VLAN_TCP4) ||
	    hash_is_enabled(flags, HASH_VLAN_UDP4) ||
	    hash_is_enabled(flags, HASH_VLAN_SCTP4))
		return 1;

	return 0;
}

static int hash_is_l4v6_enabled(struct hash_flags *flags)
{
	if (hash_is_enabled(flags, HASH_NOVLAN_TCP6) ||
	    hash_is_enabled(flags, HASH_NOVLAN_UDP6) ||
	    hash_is_enabled(flags, HASH_NOVLAN_SCTP6) ||
	    hash_is_enabled(flags, HASH_VLAN_TCP6) ||
	    hash_is_enabled(flags, HASH_VLAN_UDP6) ||
	    hash_is_enabled(flags, HASH_VLAN_SCTP6))
		return 1;

	return 0;
}

static int hash_is_novlan_l3l4_enabled(struct hash_flags *flags)
{

	if (hash_is_enabled(flags, HASH_NOVLAN_IPV4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_IPV6) ||
	    hash_is_enabled(flags, HASH_NOVLAN_TCP4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_UDP4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_SCTP4) ||
	    hash_is_enabled(flags, HASH_NOVLAN_TCP6) ||
	    hash_is_enabled(flags, HASH_NOVLAN_UDP6) ||
	    hash_is_enabled(flags, HASH_NOVLAN_SCTP6))
		return 1;

	return 0;
}

static void stack_init(void)
{
	stack_labels = NULL;
	stack_addrs = NULL;
}

static void __stack_release(struct stack_entry *root)
{
	struct stack_entry *p;
	struct stack_entry *pn;

	p = root;
	while (p) {
		pn = p->next;
		free(p);
		p = pn;
	}
}

static void stack_release(void)
{
	__stack_release(stack_labels);
	__stack_release(stack_addrs);
	stack_init();
}

static int push_addr(struct sock_fprog *fprog, int flags)
{
	struct stack_entry *pa;

	pa = malloc(sizeof(struct stack_entry));
	if (!pa)
		return -ENOMEM;

	pa->addr = fprog->len - 1;
	pa->flags = flags;

	pa->next = stack_addrs;
	stack_addrs = pa;

	return 0;
}

static struct stack_entry *__find_label(enum bpf_labels label)
{
	struct stack_entry *p;

	p = stack_labels;
	while (p) {
		if (p->label == label)
			return p;

		p = p->next;
	}

	return NULL;
}

static int push_label(struct sock_fprog *fprog, enum bpf_labels label)
{
	struct stack_entry *pl;

	if (__find_label(label))
		return -EEXIST;

	pl = malloc(sizeof(struct stack_entry));
	if (!pl)
		return -ENOMEM;

	pl->addr = fprog->len;
	pl->label = label;

	pl->next = stack_labels;
	stack_labels = pl;

	return 0;
}

static int stack_resolve_offsets(struct sock_fprog *fprog)
{
	struct stack_entry *paddr;
	struct stack_entry *naddr;
	struct stack_entry *plabel;
	struct stack_entry *nlabel;
	struct sock_filter *sf;
	int offset;

	paddr = stack_addrs;
	while (paddr) {
		sf = fprog->filter + paddr->addr;

		if (paddr->flags & ~(FIX_K|FIX_JT|FIX_JF))
			return -EINVAL;

		if (paddr->flags & FIX_K) {
			plabel = __find_label(sf->k);
			if (!plabel)
				return -ENOENT;

			offset = plabel->addr - paddr->addr - 1;
			if (offset < 0 || offset > 255)
				return -EINVAL;
			sf->k = offset;
		}

		if (paddr->flags & FIX_JT) {
			plabel = __find_label(sf->jt);
			if (!plabel)
				return -ENOENT;

			offset = plabel->addr - paddr->addr - 1;
			if (offset < 0 || offset > 255)
				return -EINVAL;
			sf->jt = offset;
		}

		if (paddr->flags & FIX_JF) {
			plabel = __find_label(sf->jf);
			if (!plabel)
				return -ENOENT;

			offset = plabel->addr - paddr->addr - 1;
			if (offset < 0 || offset > 255)
				return -EINVAL;
			sf->jf = offset;
		}

		naddr = paddr->next;
		free(paddr);
		paddr = naddr;
	}

	plabel = stack_labels;
	while (plabel) {
		nlabel = plabel->next;
		free(plabel);
		plabel = nlabel;
	}

	stack_init();
	return 0;
}

static int bpf_eth_hash(struct sock_fprog *fprog)
{
	int err;

	/* hash dest mac addr */
	bpf_load_word(2);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_half(0);
	bpf_calc_hash();
	bpf_move_to_x();

	/* hash source mac addr */
	bpf_load_word(8);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_half(6);
	bpf_calc_hash();
	bpf_move_to_x();
	return 0;

err_add_inst:
	return err;
}

static int bpf_vlan_hash(struct sock_fprog *fprog)
{
	int err;

	bpf_vlan_tag_id();
	bpf_calc_hash();
	bpf_move_to_x();

err_add_inst:
	return err;
}

static int __bpf_ipv4_hash(struct sock_fprog *fprog, bool vlan)
{
	int vlan_shift = vlan ? vlan_hdr_shift(0) : 0;
	int err;

	bpf_load_word(26 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(30 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	return 0;

err_add_inst:
	return err;
}

static int bpf_vlan_ipv4_hash(struct sock_fprog *fprog)
{
	return __bpf_ipv4_hash(fprog, true);
}

static int bpf_novlan_ipv4_hash(struct sock_fprog *fprog)
{
	return __bpf_ipv4_hash(fprog, false);
}

static int __bpf_ipv6_hash(struct sock_fprog *fprog, bool vlan)
{
	int vlan_shift = vlan ? vlan_hdr_shift(0) : 0;
	int err;

	bpf_load_word(22 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(26 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(30 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(34 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(38 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(42 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(46 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	bpf_load_word(50 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	return 0;

err_add_inst:
	return err;
}

static int bpf_vlan_ipv6_hash(struct sock_fprog *fprog)
{
	return __bpf_ipv6_hash(fprog, true);
}

static int bpf_novlan_ipv6_hash(struct sock_fprog *fprog)
{
	return __bpf_ipv6_hash(fprog, false);
}

static int __bpf_l4v4_hash(struct sock_fprog *fprog, bool vlan)
{
	int vlan_shift = vlan ? vlan_hdr_shift(0) : 0;
	int err;

	bpf_push_x();
	bpf_ipv4_len_to_x(14 + vlan_shift);
	/* source port offset */
	bpf_l4v4_port_to_a(14 + vlan_shift);
	bpf_pop_x();
	bpf_calc_hash();
	bpf_push_a();
	bpf_ipv4_len_to_x(14 + vlan_shift);
	/* dest port offset */
	bpf_l4v4_port_to_a(16 + vlan_shift);
	bpf_pop_x();
	bpf_calc_hash();
	bpf_move_to_x();
	return 0;

err_add_inst:
	return err;
}

static int bpf_vlan_l4v4_hash(struct sock_fprog *fprog)
{
	return __bpf_l4v4_hash(fprog, true);
}

static int bpf_novlan_l4v4_hash(struct sock_fprog *fprog)
{
	return __bpf_l4v4_hash(fprog, false);
}

static int __bpf_l4v6_hash(struct sock_fprog *fprog, bool vlan)
{
	int vlan_shift = vlan ? vlan_hdr_shift(0) : 0;
	int err;

	bpf_load_half(54 + vlan_shift);
	bpf_calc_hash();
	bpf_load_half(56 + vlan_shift);
	bpf_calc_hash();
	bpf_move_to_x();
	return 0;

err_add_inst:
	return err;
}

static int bpf_vlan_l4v6_hash(struct sock_fprog *fprog)
{
	return __bpf_l4v6_hash(fprog, true);
}

static int bpf_novlan_l4v6_hash(struct sock_fprog *fprog)
{
	return __bpf_l4v6_hash(fprog, false);
}

/* bpf_create_code:
 * This function creates the entire bpf hashing code and follows
 * this scheme:
 *
 *                          start
 *                            V
 *                      handle ethernet
 *                            V
 *                   check vlan tag presense
 *		       |yes             | no
 *                   handle             |
 *                    vlan              |
 *		       V                V
 *          +----- ipv4/ipv6?      +--  ipv4/ipv6?--+
 *          |ipv4        |ipv6     | ipv4           |ipv6
 *      +--frag?-+       |       +-frag?-+          |
 *      |yes     |no     |       |yes    |no        |
 *    return     V       V      return   V          V
 *            handle    handle          handle     handle
 *             ipv4     ipv6             ipv4       ipv6
 *               |       |               |          |
 *	     proto?   proto?         proto?      proto?
 *
 * for each branch above:
 *         |tcp |udp |sctp |none
 *         |    |    |     |
 *           handle        |
 *           return <------+
 */
static int bpf_create_code(struct sock_fprog *fprog, struct hash_flags *flags)
{
	int err;

	/* generate the ethernet hashing code */
	if (hash_test_and_set_flag(flags, HASH_ETH))
		bpf_eth_hash(fprog);

	if (hash_is_complete(flags)) {
		bpf_hash_return();
		/* there is no need to keep going, all done */
		return 0;
	}

	bpf_vlan_tag_present();
	bpf_cmp(0, LABEL_VLAN_BRANCH, 0, FIX_JF);
	if (!hash_is_novlan_l3l4_enabled(flags))
		bpf_hash_return();

	/* no vlan branch */
	bpf_load_half(ETH_TYPE_OFFSET);
	bpf_cmp(0, LABEL_NOVLAN_IPV6, PROTOID_IPV4, FIX_JF);

	/* no vlan ipv4 branch */
	if (hash_test_and_set_flag(flags, HASH_NOVLAN_IPV4))
		bpf_novlan_ipv4_hash(fprog);

	if (!hash_is_l4v4_enabled(flags))
		bpf_hash_return();

	/* no vlan ipv4 L4 */
	/* ignore IP frags */
	bpf_load_half(IPV4_FLAGS_OFFSET);
	bpf_and(LABEL_NOVLAN_L4v4_OUT, 0, IPV4_FRAG_BITS, FIX_JT);

	/* L4 protocol check */
	bpf_load_byte(IPV4_PROTO_OFFSET);
	bpf_cmp(0, LABEL_NOVLAN_TRY_UDP4, PROTOID_TCP, FIX_JF);

	if (hash_test_and_set_flag(flags, HASH_NOVLAN_TCP4))
		bpf_jump(LABEL_NOVLAN_L4v4_HASH);
	else
		bpf_jump(LABEL_NOVLAN_L4v4_OUT);

	/* no vlan try udp4 */
	push_label(fprog, LABEL_NOVLAN_TRY_UDP4);
	bpf_cmp(0, LABEL_NOVLAN_TRY_STCP4, PROTOID_UDP, FIX_JF);
	if (hash_test_and_set_flag(flags, HASH_NOVLAN_UDP4))
		bpf_jump(LABEL_NOVLAN_L4v4_HASH);
	else
		bpf_jump(LABEL_NOVLAN_L4v4_OUT);

	/* no vlan try sctp4 */
	push_label(fprog, LABEL_NOVLAN_TRY_STCP4);
	bpf_cmp(0, LABEL_NOVLAN_L4v4_OUT, PROTOID_SCTP, FIX_JF);
	if (!hash_test_and_set_flag(flags, HASH_NOVLAN_SCTP4))
		bpf_jump(LABEL_NOVLAN_L4v4_OUT);

	/* no vlan L4v4 hashing */
	push_label(fprog, LABEL_NOVLAN_L4v4_HASH);
	bpf_novlan_l4v4_hash(fprog);

	/* no vlan L4v4 out: */
	push_label(fprog, LABEL_NOVLAN_L4v4_OUT);
	bpf_hash_return();

	/* no vlan ipv6 branch */
	push_label(fprog, LABEL_NOVLAN_IPV6);
	bpf_cmp(LABEL_NOVLAN_IPV6_CONTINUE, 0, PROTOID_IPV6, FIX_JT);
	bpf_hash_return();

	/* no vlan ipv6 continue */
	push_label(fprog, LABEL_NOVLAN_IPV6_CONTINUE);
	if (hash_test_and_set_flag(flags, HASH_NOVLAN_IPV6))
		bpf_novlan_ipv6_hash(fprog);

	if (!hash_is_l4v6_enabled(flags))
		bpf_hash_return();

	/* no vlan ipv6 l4 branch */
	/* L4 protocol check (Next Header) */
	bpf_load_byte(IPV6_NEXTHEADER_OFFSET);
	bpf_cmp(0, LABEL_NOVLAN_TRY_UDP6, PROTOID_TCP, FIX_JF);

	if (hash_test_and_set_flag(flags, HASH_NOVLAN_TCP6))
		bpf_jump(LABEL_NOVLAN_L4v6_HASH);
	else
		bpf_jump(LABEL_NOVLAN_L4v6_OUT);

	/* no vlan check udp6 */
	push_label(fprog, LABEL_NOVLAN_TRY_UDP6);
	bpf_cmp(0, LABEL_NOVLAN_TRY_STCP6, PROTOID_UDP, FIX_JF);
	if (hash_test_and_set_flag(flags, HASH_NOVLAN_UDP6))
		bpf_jump(LABEL_NOVLAN_L4v6_HASH);
	else
		bpf_jump(LABEL_NOVLAN_L4v6_OUT);

	/* no vlan check sctp6 */
	push_label(fprog, LABEL_NOVLAN_TRY_STCP6);
	bpf_cmp(0, LABEL_NOVLAN_L4v6_OUT, PROTOID_SCTP, FIX_JF);
	if (!hash_test_and_set_flag(flags, HASH_NOVLAN_SCTP4))
		bpf_jump(LABEL_NOVLAN_L4v6_OUT);

	/* no vlan l4v6 hashing */
	push_label(fprog, LABEL_NOVLAN_L4v6_HASH);
	bpf_novlan_l4v6_hash(fprog);

	/* no vlan l4v6 out */
	push_label(fprog, LABEL_NOVLAN_L4v6_OUT);
	bpf_hash_return();

	/* vlan branch */
	push_label(fprog, LABEL_VLAN_BRANCH);
	if (hash_test_and_set_flag(flags, HASH_VLAN))
		bpf_vlan_hash(fprog);

	if (hash_is_complete(flags)) {
		bpf_hash_return();
		return 0;
	}

	bpf_load_half(vlan_hdr_shift(ETH_TYPE_OFFSET));
	bpf_cmp(0, LABEL_VLAN_IPV6, PROTOID_IPV4, FIX_JF);
	/* vlan ipv4 branch */
	if (hash_test_and_set_flag(flags, HASH_VLAN_IPV4))
		bpf_vlan_ipv4_hash(fprog);

	if (!hash_is_l4v4_enabled(flags))
		bpf_hash_return();

	/* vlan ipv4 L4 */
	/* ignore IP frags */
	bpf_load_half(vlan_hdr_shift(IPV4_FLAGS_OFFSET));
	bpf_and(LABEL_VLAN_L4v4_OUT, 0, IPV4_FRAG_BITS, FIX_JT);

	/* L4 protocol check */
	bpf_load_byte(vlan_hdr_shift(IPV4_PROTO_OFFSET));
	bpf_cmp(0, LABEL_VLAN_TRY_UDP4, PROTOID_TCP, FIX_JF);

	if (hash_test_and_set_flag(flags, HASH_VLAN_TCP4))
		bpf_jump(LABEL_VLAN_L4v4_HASH);
	else
		bpf_jump(LABEL_VLAN_L4v4_OUT);

	/* vlan try udp4 */
	push_label(fprog, LABEL_VLAN_TRY_UDP4);
	bpf_cmp(0, LABEL_VLAN_TRY_STCP4, PROTOID_UDP, FIX_JF);
	if (hash_test_and_set_flag(flags, HASH_VLAN_UDP4))
		bpf_jump(LABEL_VLAN_L4v4_HASH);
	else
		bpf_jump(LABEL_VLAN_L4v4_OUT);

	/* vlan try sctp4 */
	push_label(fprog, LABEL_VLAN_TRY_STCP4);
	bpf_cmp(0, LABEL_VLAN_L4v4_OUT, PROTOID_SCTP, FIX_JF);
	if (!hash_test_and_set_flag(flags, HASH_VLAN_SCTP4))
		bpf_jump(LABEL_VLAN_L4v4_OUT);

	/* vlan L4v4 hashing */
	push_label(fprog, LABEL_VLAN_L4v4_HASH);
	bpf_vlan_l4v4_hash(fprog);

	/* vlan L4v4 out: */
	push_label(fprog, LABEL_VLAN_L4v4_OUT);
	bpf_hash_return();

	/* vlan ipv6 branch */
	push_label(fprog, LABEL_VLAN_IPV6);
	bpf_cmp(LABEL_VLAN_IPV6_CONTINUE, 0, PROTOID_IPV6, FIX_JT);
	bpf_hash_return();

	/* vlan ipv6 continue */
	push_label(fprog, LABEL_VLAN_IPV6_CONTINUE);
	if (hash_test_and_set_flag(flags, HASH_VLAN_IPV6))
		bpf_vlan_ipv6_hash(fprog);

	if (!hash_is_l4v6_enabled(flags))
		bpf_hash_return();

	/* vlan ipv6 l4 branch */
	/* L4 protocol check (Next Header) */
	bpf_load_byte(vlan_hdr_shift(IPV6_NEXTHEADER_OFFSET));
	bpf_cmp(0, LABEL_VLAN_TRY_UDP6, PROTOID_TCP, FIX_JF);

	if (hash_test_and_set_flag(flags, HASH_VLAN_TCP6))
		bpf_jump(LABEL_VLAN_L4v6_HASH);
	else
		bpf_jump(LABEL_VLAN_L4v6_OUT);

	/* vlan check udp6 */
	push_label(fprog, LABEL_VLAN_TRY_UDP6);
	bpf_cmp(0, LABEL_VLAN_TRY_STCP6, PROTOID_UDP, FIX_JF);
	if (hash_test_and_set_flag(flags, HASH_VLAN_UDP6))
		bpf_jump(LABEL_VLAN_L4v6_HASH);
	else
		bpf_jump(LABEL_VLAN_L4v6_OUT);

	/* vlan check sctp6 */
	push_label(fprog, LABEL_VLAN_TRY_STCP6);
	bpf_cmp(0, LABEL_VLAN_L4v6_OUT, PROTOID_SCTP, FIX_JF);
	if (!hash_test_and_set_flag(flags, HASH_VLAN_SCTP4))
		bpf_jump(LABEL_VLAN_L4v6_OUT);

	/* vlan l4v6 hashing */
	push_label(fprog, LABEL_VLAN_L4v6_HASH);
	bpf_vlan_l4v6_hash(fprog);

	/* vlan l4v6 out */
	push_label(fprog, LABEL_VLAN_L4v6_OUT);
	bpf_hash_return();
	return 0;

err_add_inst:
	return err;
}

int teamd_bpf_desc_add_frag(struct sock_fprog *fprog,
			    const struct teamd_bpf_desc_frag *frag)
{
	switch (frag->hproto) {
		case PROTO_ETH:
			hash_set_enable(&hflags, HASH_ETH);
			break;

		case PROTO_VLAN:
			hash_set_enable(&hflags, HASH_VLAN);
			break;

		case PROTO_IP:
		case PROTO_L3:
			hash_set_enable(&hflags, HASH_VLAN_IPV4);
			hash_set_enable(&hflags, HASH_VLAN_IPV6);
			hash_set_enable(&hflags, HASH_NOVLAN_IPV4);
			hash_set_enable(&hflags, HASH_NOVLAN_IPV6);
			break;

		case PROTO_IPV4:
			hash_set_enable(&hflags, HASH_VLAN_IPV4);
			hash_set_enable(&hflags, HASH_NOVLAN_IPV4);
			break;

		case PROTO_IPV6:
			hash_set_enable(&hflags, HASH_VLAN_IPV6);
			hash_set_enable(&hflags, HASH_NOVLAN_IPV6);
			break;

		case PROTO_L4:
			hash_set_enable(&hflags, HASH_VLAN_TCP4);
			hash_set_enable(&hflags, HASH_VLAN_TCP6);
			hash_set_enable(&hflags, HASH_VLAN_UDP4);
			hash_set_enable(&hflags, HASH_VLAN_UDP6);
			hash_set_enable(&hflags, HASH_VLAN_SCTP4);
			hash_set_enable(&hflags, HASH_VLAN_SCTP6);
			hash_set_enable(&hflags, HASH_NOVLAN_TCP4);
			hash_set_enable(&hflags, HASH_NOVLAN_TCP6);
			hash_set_enable(&hflags, HASH_NOVLAN_UDP4);
			hash_set_enable(&hflags, HASH_NOVLAN_UDP6);
			hash_set_enable(&hflags, HASH_NOVLAN_SCTP4);
			hash_set_enable(&hflags, HASH_NOVLAN_SCTP6);
			break;

		case PROTO_TCP:
			hash_set_enable(&hflags, HASH_VLAN_TCP4);
			hash_set_enable(&hflags, HASH_VLAN_TCP6);
			hash_set_enable(&hflags, HASH_NOVLAN_TCP4);
			hash_set_enable(&hflags, HASH_NOVLAN_TCP6);
			break;

		case PROTO_UDP:
			hash_set_enable(&hflags, HASH_VLAN_UDP4);
			hash_set_enable(&hflags, HASH_VLAN_UDP6);
			hash_set_enable(&hflags, HASH_NOVLAN_UDP4);
			hash_set_enable(&hflags, HASH_NOVLAN_UDP6);
			break;

		case PROTO_SCTP:
			hash_set_enable(&hflags, HASH_VLAN_SCTP4);
			hash_set_enable(&hflags, HASH_VLAN_SCTP6);
			hash_set_enable(&hflags, HASH_NOVLAN_SCTP4);
			hash_set_enable(&hflags, HASH_NOVLAN_SCTP6);
			break;

		default:
			return -EINVAL;
	}

	return 0;
}

static void __compile_init(struct sock_fprog *fprog)
{
	fprog->len = 0;
	fprog->filter = NULL;
	stack_init();
	hash_flags_init(&hflags);
}

void teamd_bpf_desc_compile_start(struct sock_fprog *fprog)
{
	__compile_init(fprog);
}

void teamd_bpf_desc_compile_release(struct sock_fprog *fprog)
{
	free(fprog->filter);
	__compile_init(fprog);
	stack_release();
	hash_flags_init(&hflags);
}

int teamd_bpf_desc_compile_finish(struct sock_fprog *fprog)
{
	return 0;
}

int teamd_bpf_desc_compile(struct sock_fprog *fprog)
{
	int err;

	err = bpf_create_code(fprog, &hflags);
	if (err)
		return err;

	err = stack_resolve_offsets(fprog);
	return err;
}
