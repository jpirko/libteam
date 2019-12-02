/*
 *   teamd_hash_func.c - Hash function preparation for teamd
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

#include <string.h>
#include <linux/filter.h>
#include <private/misc.h>
#include <team.h>

#include "teamd.h"
#include "teamd_config.h"
#include "teamd_bpf_chef.h"

static const struct teamd_bpf_desc_frag eth_hdr_frag = {
	.name = "eth",
	.hproto = PROTO_ETH,
};

static const struct teamd_bpf_desc_frag vlan_hdr_frag = {
	.name = "vlan",
	.hproto = PROTO_VLAN,
};

static const struct teamd_bpf_desc_frag ipv4_hdr_frag = {
	.name = "ipv4",
	.hproto = PROTO_IPV4,
};

static const struct teamd_bpf_desc_frag ipv6_hdr_frag = {
	.name = "ipv6",
	.hproto = PROTO_IPV6,
};

static const struct teamd_bpf_desc_frag ip_hdr_frag = {
	.name = "ip",
	.hproto = PROTO_IP,
};

static const struct teamd_bpf_desc_frag l3_hdr_frag = {
	.name = "l3",
	.hproto = PROTO_L3,
};

static const struct teamd_bpf_desc_frag l4_hdr_frag = {
	.name = "l4",
	.hproto = PROTO_L4,
};

static const struct teamd_bpf_desc_frag tcp_hdr_frag = {
	.name = "tcp",
	.hproto = PROTO_TCP,
};
static const struct teamd_bpf_desc_frag udp_hdr_frag = {
	.name = "udp",
	.hproto = PROTO_UDP,
};
static const struct teamd_bpf_desc_frag sctp_hdr_frag = {
	.name = "sctp",
	.hproto = PROTO_SCTP,
};

static const struct teamd_bpf_desc_frag *frags[] = {
	&eth_hdr_frag,
	&vlan_hdr_frag,
	&ipv4_hdr_frag,
	&ipv6_hdr_frag,
	&ip_hdr_frag,
	&l3_hdr_frag,
	&l4_hdr_frag,
	&tcp_hdr_frag,
	&udp_hdr_frag,
	&sctp_hdr_frag,
};

static const size_t frags_count = ARRAY_SIZE(frags);

static const struct teamd_bpf_desc_frag *__find_frag(const char *frag_name)
{
	int i;

	for (i = 0; i < frags_count; i++) {
		if (!strcmp(frag_name, frags[i]->name))
			return frags[i];
	}
	return NULL;
}

static int teamd_hash_func_init(struct teamd_context *ctx, struct sock_fprog *fprog)
{
	int i;
	int err;

	teamd_bpf_desc_compile_start(fprog);
	teamd_config_for_each_arr_index(i, ctx, "$.runner.tx_hash") {
		const struct teamd_bpf_desc_frag *frag;
		const char *frag_name;

		err = teamd_config_string_get(ctx, &frag_name,
					      "$.runner.tx_hash[%d]", i);
		if (err)
			continue;

		frag = __find_frag(frag_name);
		if (!frag) {
			teamd_log_warn("Hash frag named \"%s\" not found.",
				       frag_name);
			continue;
		}
		err = teamd_bpf_desc_add_frag(fprog, frag);
		if (err)
			goto release;
	}

	err = teamd_bpf_desc_compile(fprog);
	if (err)
		goto release;

	err = teamd_bpf_desc_compile_finish(fprog);
	if (err)
		goto release;
	return 0;

release:
	teamd_bpf_desc_compile_release(fprog);
	return err;
}

static void teamd_hash_func_fini(struct sock_fprog *fprog)
{
	teamd_bpf_desc_compile_release(fprog);
}

static const char *teamd_hash_default_frags[] = {
	"eth", "ipv4", "ipv6",
};

static int teamd_hash_func_add_default_frags(struct teamd_context *ctx)
{
	int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(teamd_hash_default_frags); i++) {
		err = teamd_config_arr_string_append(ctx,
						     teamd_hash_default_frags[i],
						     "$.runner.tx_hash");
		if (err)
			return err;
	}
	return 0;
}

int teamd_hash_func_set(struct teamd_context *ctx)
{
	struct sock_fprog fprog;
	int err;

	if (!teamd_config_path_exists(ctx, "$.runner.tx_hash")) {
		teamd_log_dbg(ctx, "No Tx hash recipe found in config.");
		err = teamd_hash_func_add_default_frags(ctx);
		if (err)
			return err;
	}
	err = teamd_hash_func_init(ctx, &fprog);
	if (err) {
		teamd_log_err("Failed to init hash function.");
		return err;
	}
	err = team_set_bpf_hash_func(ctx->th, &fprog);
	if (err)
		teamd_log_err("Failed to set hash function.");
	teamd_hash_func_fini(&fprog);
	return err;
}
