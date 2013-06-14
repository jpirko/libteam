/*
 *   teamd_sriov.c - SR-IOV support for teamd
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

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "teamd.h"

struct pcie_addr {
	uint16_t domain;
	uint8_t bus;
	uint8_t slot;
	uint8_t function;
};

static int teamd_sriov_physfn_addr(struct pcie_addr *addr, const char *ifname)
{
	char link[256];
	char *path;
	char *start;
	int ret;

	ret = asprintf(&path, "/sys/class/net/%s/device/physfn", ifname);
	if (ret == -1)
		return -ENOMEM;

	ret = readlink(path, link, sizeof(link));
	free(path);
	if (ret == -1)
		return -errno;
	link[ret] = '\0';

	start = strrchr(link, '/');
	if (!start)
		return -EINVAL;
	start++;
	memset(addr, 0, sizeof(*addr));
	ret = sscanf(start, "%04x:%02x:%02x.%x", (unsigned int *) &addr->domain,
						 (unsigned int *) &addr->bus,
						 (unsigned int *) &addr->slot,
						 (unsigned int *) &addr->function);
	if (ret != 4)
		return -EINVAL;
	return 0;
}

static int teamd_sriov_event_watch_port_added(struct teamd_context *ctx,
					      struct teamd_port *tdport,
					      void *priv)
{
	struct pcie_addr physfnaddr;
	struct pcie_addr cur_physfnaddr;
	struct teamd_port *cur_tdport;
	int err;

	err = teamd_sriov_physfn_addr(&physfnaddr, tdport->ifname);
	if (err)
		return 0;

	teamd_for_each_tdport(cur_tdport, ctx) {
		if (cur_tdport == tdport)
			continue;
		err = teamd_sriov_physfn_addr(&cur_physfnaddr,
					      cur_tdport->ifname);
		if (err)
			continue;
		if (!memcmp(&physfnaddr, &cur_physfnaddr, sizeof(physfnaddr)))
			teamd_log_warn("%s: port is virtual function of same physical function as port %s. Note that teaming virtual functions of the same physical function makes no sense.",
				       tdport->ifname, cur_tdport->ifname);
	}
	return 0;
}

static const struct teamd_event_watch_ops teamd_sriov_event_watch_ops = {
	.port_added = teamd_sriov_event_watch_port_added,
};

int teamd_sriov_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &teamd_sriov_event_watch_ops,
					 NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

void teamd_sriov_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &teamd_sriov_event_watch_ops,
				     NULL);
}
