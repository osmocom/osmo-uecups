/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>

#include <pthread.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/icmpv6.h>

#include "internal.h"

/***********************************************************************
 * GTP Tunnel
 ***********************************************************************/
struct gtp_tunnel *gtp_tunnel_alloc(struct gtp_daemon *d, const struct gtp_tunnel_params *cpars)
{
	struct gtp_tunnel *t;
	int rc;

	t = talloc_zero(d, struct gtp_tunnel);
	if (!t)
		goto out;
	t->d = d;
	t->name = talloc_asprintf(t, "%s-R%08x-T%08x", cpars->tun_name, cpars->rx_teid, cpars->tx_teid);
	t->tun_dev = tun_device_find_or_create(d, cpars->tun_name, cpars->tun_netns_name);
	if (!t->tun_dev) {
		LOGT(t, LOGL_ERROR, "Cannot find or create tun device %s\n", cpars->tun_name);
		goto out_free;
	}

	t->gtp_ep = gtp_endpoint_find_or_create(d, &cpars->local_udp);
	if (!t->gtp_ep) {
		LOGT(t, LOGL_ERROR, "Cannot find or create GTP endpoint\n");
		goto out_tun;
	}

	pthread_rwlock_wrlock(&d->rwlock);
	/* check if we already have a tunnel with same Rx-TEID + endpoint */
	if (_gtp_tunnel_find_r(d, cpars->rx_teid, t->gtp_ep)) {
		LOGT(t, LOGL_ERROR, "Error: We already have a tunnel for RxTEID 0x%08x "
			"on this endpoint (%s)\n", cpars->rx_teid, t->gtp_ep->name);
		goto out_ep;
	}

	/* FIXME: check if we already have a tunnel with same Tx-TEID + peer */
	/* FIXME: check if we already have a tunnel with same tun + EUA + filter */

	t->rx_teid = cpars->rx_teid;
	t->tx_teid = cpars->tx_teid;
	memcpy(&t->exthdr, &cpars->exthdr, sizeof(t->exthdr));

	if (cpars->user_addr_type == GTP1U_EUA_TYPE_IPv4 || cpars->user_addr_type == GTP1U_EUA_TYPE_IPv4v6) {
		memcpy(&t->user_addr_ipv4, &cpars->user_addr_ipv4, sizeof(t->user_addr_ipv4));
		if ((rc = osmo_netdev_add_addr(t->tun_dev->netdev, &t->user_addr_ipv4, 32)) < 0) {
			LOGT(t, LOGL_ERROR, "Cannot add user addr to tun device: %s\n",
			strerror(-rc));
		}
	} else {
		t->user_addr_ipv4.u.sa.sa_family = AF_UNSPEC;
	}

	t->user_addr_type = cpars->user_addr_type;
	if (cpars->user_addr_type == GTP1U_EUA_TYPE_IPv6 || cpars->user_addr_type == GTP1U_EUA_TYPE_IPv4v6)
		memcpy(&t->user_addr_ipv6_ll, &cpars->user_addr_ipv6, sizeof(t->user_addr_ipv6_ll));
	else
		t->user_addr_ipv6_ll.u.sa.sa_family = AF_UNSPEC;

	/* user_addr_ipv6_global will be set later on during IPv6 SLAAC procedure: */
	t->user_addr_ipv6_global.u.sa.sa_family = AF_UNSPEC;

	memcpy(&t->remote_udp, &cpars->remote_udp, sizeof(t->remote_udp));

	/* TODO: hash table? */
	llist_add_tail(&t->list, &d->gtp_tunnels);
	pthread_rwlock_unlock(&d->rwlock);
	LOGT(t, LOGL_NOTICE, "Created\n");

	return t;

out_ep:
	pthread_rwlock_unlock(&d->rwlock);
	_gtp_endpoint_release(t->gtp_ep);
out_tun:
	_tun_device_release(t->tun_dev);
out_free:
	talloc_free(t);
out:
	return NULL;
}

#if 0
/* find tunnel by R(x_teid), T(x_teid) + A(ddr) */
static struct gtp_tunnel *
_gtp_tunnel_find_rta(struct gtp_daemon *d, uint32_t rx_teid, uint32_t tx_teid,
		     const struct osmo_sockaddr *user_addr)
{
	struct gtp_tunnel *t;
	llist_for_each_entry(t, &d->gtp_tunnels, list) {
		if (t->rx_teid == rx_teid && t->tx_teid == tx_teid &&
		    osmo_sockaddr_cmp(&t->user_addr, &user_addr) == 0)
			return t;
	}
	return NULL;
}
#endif

/* find tunnel by R(x_teid) + optionally local endpoint */
struct gtp_tunnel *
_gtp_tunnel_find_r(struct gtp_daemon *d, uint32_t rx_teid, struct gtp_endpoint *ep)
{
	struct gtp_tunnel *t;
	llist_for_each_entry(t, &d->gtp_tunnels, list) {
		if (t->rx_teid == rx_teid) {
			if (!ep)
				return t;
			if (t->gtp_ep == ep)
				return t;
		}
	}
	return NULL;
}

/* UNLOCKED find tunnel by tun + EUA ip (+proto/port) */
struct gtp_tunnel *
_gtp_tunnel_find_eua(struct tun_device *tun, const struct osmo_sockaddr *osa, uint8_t proto)
{
	struct gtp_daemon *d = tun->d;
	struct gtp_tunnel *t;

	llist_for_each_entry(t, &d->gtp_tunnels, list) {
		/* TODO: Find best matching filter */
		if (t->tun_dev != tun)
			continue;
		switch (osa->u.sa.sa_family) {
		case AF_INET:
			if (t->user_addr_type == GTP1U_EUA_TYPE_IPv6)
				continue;
			if (osmo_sockaddr_cmp(osa, &t->user_addr_ipv4) != 0)
				continue;
			return t;
		case AF_INET6:
			if (t->user_addr_type == GTP1U_EUA_TYPE_IPv4)
				continue;
			if (osmo_sockaddr_cmp(osa, &t->user_addr_ipv6_ll) != 0 &&
			    osmo_sockaddr_cmp(osa, &t->user_addr_ipv6_global) != 0)
				continue;
			return t;
		}
	}
	return NULL;
}

/* UNLOCKED destroy of tunnel; drops references to EP + TUN */
void _gtp_tunnel_destroy(struct gtp_tunnel *t)
{
	int rc;

	LOGT(t, LOGL_NOTICE, "Destroying\n");
	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(t->d);

	if (t->user_addr_type == GTP1U_EUA_TYPE_IPv4 || t->user_addr_type == GTP1U_EUA_TYPE_IPv4v6) {
		if ((rc = osmo_netdev_del_addr(t->tun_dev->netdev, &t->user_addr_ipv4, 32)) < 0)
			LOGT(t, LOGL_ERROR, "Cannot remove IPv4 user address: %s\n", strerror(-rc));
	}
	if (t->user_addr_type == GTP1U_EUA_TYPE_IPv6 || t->user_addr_type == GTP1U_EUA_TYPE_IPv4v6) {
		if ((rc = osmo_netdev_del_addr(t->tun_dev->netdev, &t->user_addr_ipv6_ll, 32)) < 0)
			LOGT(t, LOGL_ERROR, "Cannot remove IPv6 link-local user address: %s\n", strerror(-rc));
		if (t->user_addr_ipv6_global.u.sa.sa_family != AF_UNSPEC) {
			if ((rc = osmo_netdev_del_addr(t->tun_dev->netdev, &t->user_addr_ipv6_global, 32)) < 0)
				LOGT(t, LOGL_ERROR, "Cannot remove IPv6 global user address: %s\n", strerror(-rc));
		}
	}

	llist_del(&t->list);

	/* drop reference to endpoint + tun */
	_gtp_endpoint_release(t->gtp_ep);
	_tun_device_release(t->tun_dev);

	talloc_free(t);
}

bool gtp_tunnel_destroy(struct gtp_daemon *d, const struct osmo_sockaddr *bind_addr, uint32_t rx_teid)
{
	struct gtp_endpoint *ep;
	bool rc = false;

	pthread_rwlock_wrlock(&d->rwlock);
	/* find endpoint for bind_addr */
	ep = _gtp_endpoint_find(d, bind_addr);
	if (ep) {
		/* find tunnel for rx TEID within endpoint */
		struct gtp_tunnel *t = _gtp_tunnel_find_r(d, rx_teid, ep);
		if (t) {
			_gtp_tunnel_destroy(t);
			rc = true;
		}
	}
	pthread_rwlock_unlock(&d->rwlock);

	return rc;
}

/* Called with d->rwlock locked, tx_gtp1u_pk() will unlock. */
static int _gtp_tunnel_tx_icmpv6_rs(struct gtp_tunnel *t)
{
	struct msgb *msg;
	int rc;

	OSMO_ASSERT(t->user_addr_type == GTP1U_EUA_TYPE_IPv6 ||
		    t->user_addr_type == GTP1U_EUA_TYPE_IPv4v6);

	msg = osmo_icmpv6_construct_rs(&t->user_addr_ipv6_ll.u.sin6.sin6_addr);

	pthread_rwlock_rdlock(&t->d->rwlock);
	rc = tx_gtp1u_pkt(t, msg->head, msgb_data(msg), msgb_length(msg));
	/* pthread_rwlock_unlock() was called inside tx_gtp1u_pkt(). */
	if (rc < 0)
		LOGT(t, LOGL_FATAL, "Error Writing to UDP socket: %s\n", strerror(errno));
	msgb_free(msg);
	return 0;
}

int gtp_tunnel_tx_icmpv6_rs(struct gtp_daemon *d, const struct osmo_sockaddr *bind_addr, uint32_t rx_teid)
{
	struct gtp_endpoint *ep;

	pthread_rwlock_wrlock(&d->rwlock);
	ep = _gtp_endpoint_find(d, bind_addr);
	if (ep) {
		/* find tunnel for rx TEID within endpoint */
		struct gtp_tunnel *t = _gtp_tunnel_find_r(d, rx_teid, ep);
		if (t) {
			return _gtp_tunnel_tx_icmpv6_rs(t);
			/* pthread_rwlock_unlock() was called inside _gtp_tunnel_tx_icmpv6_rs()->tx_gtp1u_pkt(). */
		}
	}
	pthread_rwlock_unlock(&d->rwlock);
	return -ENOENT;
}
