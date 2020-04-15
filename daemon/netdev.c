/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <netlink/socket.h>
#include <netlink/route/link.h>
#include <netlink/route/addr.h>
#include <netlink/route/route.h>
#include <netlink/route/nexthop.h>

#include <osmocom/core/utils.h>

/***********************************************************************
 * netlink helper functions
 ***********************************************************************/

static int _netdev_addr(struct nl_sock *nlsk, int ifindex, const struct sockaddr_storage *ss, bool add)
{
	const struct sockaddr_in6 *sin6;
	const struct sockaddr_in *sin;
	struct nl_addr *local = NULL;
	struct rtnl_addr *addr;
	int rc;

	switch (ss->ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *) ss;
		local = nl_addr_build(AF_INET, &sin->sin_addr, 4);
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *) ss;
		local = nl_addr_build(AF_INET6, &sin6->sin6_addr, 16);
		break;
	}
	OSMO_ASSERT(local);

	addr = rtnl_addr_alloc();
	OSMO_ASSERT(addr);
	rtnl_addr_set_ifindex(addr, ifindex);
	OSMO_ASSERT(rtnl_addr_set_local(addr, local) == 0);

	if (add)
		rc = rtnl_addr_add(nlsk, addr, 0);
	else
		rc = rtnl_addr_delete(nlsk, addr, 0);

	rtnl_addr_put(addr);

	return rc;
}

int netdev_add_addr(struct nl_sock *nlsk, int ifindex, const struct sockaddr_storage *ss)
{
	return _netdev_addr(nlsk, ifindex, ss, true);
}

int netdev_del_addr(struct nl_sock *nlsk, int ifindex, const struct sockaddr_storage *ss)
{
	return _netdev_addr(nlsk, ifindex, ss, false);
}

int netdev_set_link(struct nl_sock *nlsk, int ifindex, bool up)
{
	struct rtnl_link *link, *change;
	int rc;

	rc = rtnl_link_get_kernel(nlsk, ifindex, NULL, &link);
	if (rc < 0)
		return rc;

	change = rtnl_link_alloc();
	OSMO_ASSERT(change);

	if (up)
		rtnl_link_set_flags(change, IFF_UP);
	else
		rtnl_link_unset_flags(change, IFF_UP);

	rc = rtnl_link_change(nlsk, link, change, 0);

	rtnl_link_put(change);
	rtnl_link_put(link);

	return rc;
}

int netdev_add_defaultroute(struct nl_sock *nlsk, int ifindex, uint8_t family)
{
	struct rtnl_route *route = rtnl_route_alloc();
	struct rtnl_nexthop *nhop = rtnl_route_nh_alloc();
	struct nl_addr *dst, *gw;
	uint8_t buf[16];
	int rc;

	OSMO_ASSERT(route);
	OSMO_ASSERT(nhop);

	/* destination address of route: all-zero */
	memset(buf, 0, sizeof(buf));
	dst = nl_addr_build(family, buf, family == AF_INET ? 4 : 16);
	OSMO_ASSERT(dst);
	nl_addr_set_prefixlen(dst, 0);

	/* gateway address of route: also all-zero */
	gw = nl_addr_clone(dst);
	OSMO_ASSERT(gw);

	/* nexthop for route */
	rtnl_route_nh_set_ifindex(nhop, ifindex);
	rtnl_route_nh_set_gateway(nhop, gw);

	/* tie everything together in the route */
	rtnl_route_set_dst(route, dst);
	rtnl_route_set_family(route, family);
	rtnl_route_add_nexthop(route, nhop);

	rc = rtnl_route_add(nlsk, route, NLM_F_CREATE);

	//rtnl_route_nh_free(nhop);
	nl_addr_put(gw);
	nl_addr_put(dst);
	rtnl_route_put(route);

	return rc;
}
