/*
 *   teamd_lw_arp_ping.c - Team port arp ping link watcher
 *   Copyright (C) 2012-2013 Jiri Pirko <jiri@resnulli.us>
 *   Copyright (C) 2014 Erik Hugne <erik.hugne@ericsson.com>
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

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <netdb.h>
#include <private/misc.h>
#include "teamd.h"
#include "teamd_link_watch.h"
#include "teamd_config.h"

/*
 * ARP ping link watch
 */

struct lw_ap_port_priv {
	union {
		struct lw_common_port_priv common;
		struct lw_psr_port_priv psr;
	} start; /* must be first */
	struct in_addr src;
	struct in_addr dst;
	bool validate_active;
	bool validate_inactive;
	bool send_always;
	bool vlanid_in_use;
	unsigned short vlanid;
};

static struct lw_ap_port_priv *
lw_ap_ppriv_get(struct lw_psr_port_priv *psr_ppriv)
{
	return (struct lw_ap_port_priv *) psr_ppriv;
}

#define OFFSET_ARP_OP_CODE					\
	in_struct_offset(struct arphdr, ar_op)

static struct sock_filter arp_rpl_flt[] = {
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, OFFSET_ARP_OP_CODE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static const struct sock_fprog arp_rpl_fprog = {
	.len = ARRAY_SIZE(arp_rpl_flt),
	.filter = arp_rpl_flt,
};

static struct sock_filter arp_novlan_rpl_flt[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 0, 4),
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, OFFSET_ARP_OP_CODE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

static const struct sock_fprog arp_novlan_rpl_fprog = {
	.len = ARRAY_SIZE(arp_novlan_rpl_flt),
	.filter = arp_novlan_rpl_flt,
};

static struct sock_filter arp_vlan_rpl_flt[] = {
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0, 6, 0),
	BPF_STMT(BPF_LD + BPF_B + BPF_ABS, SKF_AD_OFF + SKF_AD_VLAN_TAG),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, 0xffff, 0, 4), /* 0xffff will be replaced by vland id */
	BPF_STMT(BPF_LD + BPF_H + BPF_ABS, OFFSET_ARP_OP_CODE),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REPLY, 1, 0),
	BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ARPOP_REQUEST, 0, 1),
	BPF_STMT(BPF_RET + BPF_K, (u_int) -1),
	BPF_STMT(BPF_RET + BPF_K, 0),
};

/* this hack replaces vlanid value in filter code */
#define SET_FILTER_VLANID(fprog, vlanid) (fprog)->filter[3].k = vlanid

static const struct sock_fprog arp_vlan_rpl_fprog = {
	.len = ARRAY_SIZE(arp_vlan_rpl_flt),
	.filter = arp_vlan_rpl_flt,
};

static int set_in_addr(struct in_addr *addr, const char *hostname)
{
	struct sockaddr_in sin;
	int err;

	err = __set_sockaddr((struct sockaddr *) &sin, sizeof(sin),
			     AF_INET, hostname);
	if (err)
		return err;
	memcpy(addr, &sin.sin_addr, sizeof(*addr));
	return 0;
}

static char *str_in_addr(struct in_addr *addr)
{
	struct sockaddr_in sin;
	char buf[NI_MAXHOST];

	memcpy(&sin.sin_addr, addr, sizeof(*addr));
	return __str_sockaddr((struct sockaddr *) &sin, sizeof(sin), AF_INET,
			      buf);
}

static int lw_ap_sock_open(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	struct sock_fprog fprog;
	struct sock_filter arp_vlan_rpl_flt[ARRAY_SIZE(arp_vlan_rpl_flt)];

	if (ap_ppriv->vlanid_in_use) {
		memcpy(&arp_vlan_rpl_flt, arp_vlan_rpl_fprog.filter,
		       sizeof(arp_vlan_rpl_flt));
		fprog = arp_vlan_rpl_fprog;
		fprog.filter = arp_vlan_rpl_flt;
		SET_FILTER_VLANID(&fprog, ap_ppriv->vlanid);
	} else {
		fprog = arp_novlan_rpl_fprog;
	}
	return teamd_packet_sock_open(&psr_ppriv->sock,
				      psr_ppriv->common.tdport->ifindex,
				      htons(ETH_P_ARP), &fprog, &arp_rpl_fprog);
}

static void lw_ap_sock_close(struct lw_psr_port_priv *psr_ppriv)
{
	close(psr_ppriv->sock);
}

static int lw_ap_load_options(struct teamd_context *ctx,
			      struct teamd_port *tdport,
			      struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	struct teamd_config_path_cookie *cpcookie = psr_ppriv->common.cpcookie;
	const char *host;
	int tmp;
	int err;

	err = teamd_config_string_get(ctx, &host, "@.source_host", cpcookie);
	if (!err) {
		err = set_in_addr(&ap_ppriv->src, host);
		if (err)
			return err;
	}
	/*
	 * If source_host is not provided, just use address 0.0.0.0 according
	 * to RFC 5227 (IPv4 Address Conflict Detection).
	 */
	teamd_log_dbg("source address \"%s\".",
		      str_in_addr(&ap_ppriv->src));

	err = teamd_config_string_get(ctx, &host, "@.target_host", cpcookie);
	if (err) {
		teamd_log_err("Failed to get \"target_host\" link-watch option.");
		return -EINVAL;
	}
	err = set_in_addr(&ap_ppriv->dst, host);
	if (err)
		return err;
	teamd_log_dbg("target address \"%s\".", str_in_addr(&ap_ppriv->dst));

	err = teamd_config_bool_get(ctx, &ap_ppriv->validate_active,
				    "@.validate_active", cpcookie);
	if (err)
		ap_ppriv->validate_active = false;
	teamd_log_dbg("validate_active \"%d\".", ap_ppriv->validate_active);

	err = teamd_config_bool_get(ctx, &ap_ppriv->validate_inactive,
				    "@.validate_inactive", cpcookie);
	if (err)
		ap_ppriv->validate_inactive = false;
	teamd_log_dbg("validate_inactive \"%d\".", ap_ppriv->validate_inactive);

	err = teamd_config_bool_get(ctx, &ap_ppriv->send_always,
				    "@.send_always", cpcookie);
	if (err)
		ap_ppriv->send_always = false;
	teamd_log_dbg("send_always \"%d\".", ap_ppriv->send_always);

	err = teamd_config_int_get(ctx, &tmp, "@.vlanid", cpcookie);
	if (!err) {
		if (tmp < 0 || tmp >= 4096) {
			teamd_log_err("Wrong \"vlanid\" option value.");
			return -EINVAL;
		}
		ap_ppriv->vlanid_in_use = true;
		ap_ppriv->vlanid = tmp;
		teamd_log_dbg("vlan id \"%u\".", ap_ppriv->vlanid);
	}

	return 0;
}

static int __get_port_curr_hwaddr(struct lw_psr_port_priv *psr_ppriv,
				  struct sockaddr_ll *addr, size_t expected_len)
{
	struct team_ifinfo *ifinfo = psr_ppriv->common.tdport->team_ifinfo;
	size_t port_hwaddr_len = team_get_ifinfo_hwaddr_len(ifinfo);
	char *port_hwaddr = team_get_ifinfo_hwaddr(ifinfo);
	int err;

	err = teamd_getsockname_hwaddr(psr_ppriv->sock, addr, expected_len);
	if (err)
		return err;
	if ((addr->sll_halen != port_hwaddr_len) ||
	    (expected_len && expected_len != port_hwaddr_len)) {
		teamd_log_err("Unexpected length of hw address.");
		return -ENOTSUP;
	}
	memcpy(addr->sll_addr, port_hwaddr, addr->sll_halen);
	return 0;
}

struct arp_packet {
	struct arphdr			ah;
	unsigned char			sender_mac[ETH_ALEN];
	struct in_addr			sender_ip;
	unsigned char			target_mac[ETH_ALEN];
	struct in_addr			target_ip;
} __attribute__((packed));

struct __vlan_hdr {
	__be16 h_vlan_TCI;
	__be16 h_vlan_encapsulated_proto;
};

struct arp_vlan_packet {
	struct __vlan_hdr		vlanh;
	struct arp_packet		ap;
} __attribute__((packed));

static int lw_ap_send(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	int err;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_bcast;
	struct arp_packet ap;

	if (!(psr_ppriv->common.forced_send || ap_ppriv->send_always))
		return 0;

	err = __get_port_curr_hwaddr(psr_ppriv, &ll_my, 0);
	if (err)
		return err;
	ll_bcast = ll_my;
	memset(ll_bcast.sll_addr, 0xFF, ll_bcast.sll_halen);

	memset(&ap, 0, sizeof(ap));
	ap.ah.ar_hrd = htons(ll_my.sll_hatype);
	ap.ah.ar_pro = htons(ETH_P_IP);
	ap.ah.ar_hln = ll_my.sll_halen;
	ap.ah.ar_pln = 4;
	ap.ah.ar_op = htons(ARPOP_REQUEST);

	memcpy(ap.sender_mac, ll_my.sll_addr, sizeof(ap.sender_mac));
	ap.sender_ip = ap_ppriv->src;
	memcpy(ap.target_mac, ll_bcast.sll_addr, sizeof(ap.target_mac));
	ap.target_ip = ap_ppriv->dst;

	if (ap_ppriv->vlanid_in_use) {
		struct arp_vlan_packet avp;
		avp.ap = ap;
		avp.vlanh.h_vlan_encapsulated_proto = htons(ETH_P_ARP);
		avp.vlanh.h_vlan_TCI = htons(ap_ppriv->vlanid);
		ll_bcast.sll_protocol = htons(ETH_P_8021Q);
		return teamd_sendto(psr_ppriv->sock, &avp, sizeof(avp),
				    0, (struct sockaddr *) &ll_bcast,
				    sizeof(ll_bcast));
	} else {
		return teamd_sendto(psr_ppriv->sock, &ap, sizeof(ap),
				    0, (struct sockaddr *) &ll_bcast,
				    sizeof(ll_bcast));
	}
}

static int lw_ap_receive(struct lw_psr_port_priv *psr_ppriv)
{
	struct lw_common_port_priv *common_ppriv = &psr_ppriv->common;
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);
	int err;
	struct sockaddr_ll ll_my;
	struct sockaddr_ll ll_from;
	struct arp_packet ap;
	bool port_enabled;

	err = teamd_recvfrom(psr_ppriv->sock, &ap, sizeof(ap), 0,
			     (struct sockaddr *) &ll_from, sizeof(ll_from));
	if (err <= 0)
		return err;

	err = teamd_port_enabled(common_ppriv->ctx, common_ppriv->tdport,
				 &port_enabled);
	if (err)
		return err;

	if ((port_enabled && ap_ppriv->validate_active) ||
	    (!port_enabled && ap_ppriv->validate_inactive)) {
		err = __get_port_curr_hwaddr(psr_ppriv, &ll_my, 0);
		if (err)
			return err;

		if (ap.ah.ar_hrd != htons(ll_my.sll_hatype) ||
		    ap.ah.ar_pro != htons(ETH_P_IP) ||
		    ap.ah.ar_hln != ll_my.sll_halen ||
		    ap.ah.ar_pln != 4) {
			return 0;
		}

		if ((ap_ppriv->src.s_addr != ap.target_ip.s_addr ||
		     ap_ppriv->dst.s_addr != ap.sender_ip.s_addr) &&
		    (ap_ppriv->dst.s_addr != ap.target_ip.s_addr ||
		     ap_ppriv->src.s_addr != ap.sender_ip.s_addr))
			return 0;
	}

	psr_ppriv->reply_received = true;
	return 0;
}

static const struct lw_psr_ops lw_psr_ops_ap = {
	.sock_open		= lw_ap_sock_open,
	.sock_close		= lw_ap_sock_close,
	.load_options		= lw_ap_load_options,
	.send			= lw_ap_send,
	.receive		= lw_ap_receive,
};

static int lw_ap_port_added(struct teamd_context *ctx,
			    struct teamd_port *tdport,
			    void *priv, void *creator_priv)
{
	struct lw_ap_port_priv *ap_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = &ap_ppriv->start.psr;

	psr_ppriv->ops = &lw_psr_ops_ap;
	return lw_psr_port_added(ctx, tdport, priv, creator_priv);
}

static int lw_ap_state_source_host_get(struct teamd_context *ctx,
				       struct team_state_gsc *gsc,
				       void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);

	gsc->data.str_val.ptr = str_in_addr(&ap_ppriv->src);
	return 0;
}

static int lw_ap_state_target_host_get(struct teamd_context *ctx,
				       struct team_state_gsc *gsc,
				       void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);

	gsc->data.str_val.ptr = str_in_addr(&ap_ppriv->dst);
	return 0;
}

static int lw_ap_state_validate_active_get(struct teamd_context *ctx,
					   struct team_state_gsc *gsc,
					   void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);

	gsc->data.int_val = ap_ppriv->validate_active;
	return 0;
}

static int lw_ap_state_validate_inactive_get(struct teamd_context *ctx,
					     struct team_state_gsc *gsc,
					     void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);

	gsc->data.int_val = ap_ppriv->validate_inactive;
	return 0;
}

static int lw_ap_state_send_always_get(struct teamd_context *ctx,
				       struct team_state_gsc *gsc,
				       void *priv)
{
	struct lw_common_port_priv *common_ppriv = priv;
	struct lw_psr_port_priv *psr_ppriv = lw_psr_ppriv_get(common_ppriv);
	struct lw_ap_port_priv *ap_ppriv = lw_ap_ppriv_get(psr_ppriv);

	gsc->data.int_val = ap_ppriv->send_always;
	return 0;
}

static const struct teamd_state_val lw_ap_state_vals[] = {
	{
		.subpath = "source_host",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ap_state_source_host_get,
	},
	{
		.subpath = "target_host",
		.type = TEAMD_STATE_ITEM_TYPE_STRING,
		.getter = lw_ap_state_target_host_get,
	},
	{
		.subpath = "interval",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_interval_get,
	},
	{
		.subpath = "init_wait",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_init_wait_get,
	},
	{
		.subpath = "validate_active",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ap_state_validate_active_get,
	},
	{
		.subpath = "validate_inactive",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ap_state_validate_inactive_get,
	},
	{
		.subpath = "send_always",
		.type = TEAMD_STATE_ITEM_TYPE_BOOL,
		.getter = lw_ap_state_send_always_get,
	},
	{
		.subpath = "missed_max",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_missed_max_get,
	},
	{
		.subpath = "missed",
		.type = TEAMD_STATE_ITEM_TYPE_INT,
		.getter = lw_psr_state_missed_get,
	},
};

const struct teamd_link_watch teamd_link_watch_arp_ping = {
	.name			= "arp_ping",
	.state_vg		= {
		.vals		= lw_ap_state_vals,
		.vals_count	= ARRAY_SIZE(lw_ap_state_vals),
	},
	.port_priv = {
		.init		= lw_ap_port_added,
		.fini		= lw_psr_port_removed,
		.priv_size	= sizeof(struct lw_ap_port_priv),
	},
};
