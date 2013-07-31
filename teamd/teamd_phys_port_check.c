/*
 *   teamd_phys_port_check.c - Physical port checking support for teamd
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

static bool teamd_phys_port_sriovsysfs_cmp(struct teamd_port *tdport1,
					   struct teamd_port *tdport2)
{
	struct pcie_addr physfnaddr1;
	struct pcie_addr physfnaddr2;
	int err;

	err = teamd_sriov_physfn_addr(&physfnaddr1, tdport1->ifname);
	if (err)
		return false;

	err = teamd_sriov_physfn_addr(&physfnaddr2, tdport2->ifname);
	if (err)
		return false;
	if (!memcmp(&physfnaddr1, &physfnaddr2, sizeof(physfnaddr1)))
		return true;
	return false;
}

static int teamd_phys_port_check_event_watch_port_added(struct teamd_context *ctx,
							struct teamd_port *tdport,
							void *priv)
{
	struct teamd_port *cur_tdport;

	teamd_for_each_tdport(cur_tdport, ctx) {
		if (cur_tdport == tdport)
			continue;
		if (teamd_phys_port_sriovsysfs_cmp(tdport, cur_tdport))
			teamd_log_warn("%s: port is virtual function of same physical function as port %s. Note that teaming virtual functions of the same physical function makes no sense.",
				       tdport->ifname, cur_tdport->ifname);
	}
	return 0;
}

static const struct teamd_event_watch_ops teamd_phys_port_check_event_watch_ops = {
	.port_added = teamd_phys_port_check_event_watch_port_added,
};

int teamd_phys_port_check_init(struct teamd_context *ctx)
{
	int err;

	err = teamd_event_watch_register(ctx, &teamd_phys_port_check_event_watch_ops,
					 NULL);
	if (err) {
		teamd_log_err("Failed to register event watch.");
		return err;
	}
	return 0;
}

void teamd_phys_port_check_fini(struct teamd_context *ctx)
{
	teamd_event_watch_unregister(ctx, &teamd_phys_port_check_event_watch_ops,
				     NULL);
}
