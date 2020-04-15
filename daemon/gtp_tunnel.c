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

#include "internal.h"

#define LOGT(t, lvl, fmt, args ...) \
	LOGP(DGT, lvl, "%s: " fmt, (t)->name, ## args)

/***********************************************************************
 * GTP Tunnel
 ***********************************************************************/
struct gtp_tunnel *gtp_tunnel_alloc(struct gtp_daemon *d, const struct gtp_tunnel_params *cpars)
{
	struct gtp_tunnel *t;

	t = talloc_zero(d, struct gtp_tunnel);
	if (!t)
		goto out_unlock;
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
	memcpy(&t->user_addr, &cpars->user_addr, sizeof(t->user_addr));
	memcpy(&t->remote_udp, &cpars->remote_udp, sizeof(t->remote_udp));

	if (netdev_add_addr(t->tun_dev->nl, t->tun_dev->ifindex, &t->user_addr) < 0) {
		LOGT(t, LOGL_ERROR, "Cannot add user addr to tun device: %s\n",
			strerror(errno));
	}

	/* TODO: hash table? */
	llist_add_tail(&t->list, &d->gtp_tunnels);
	pthread_rwlock_unlock(&d->rwlock);
	LOGT(t, LOGL_NOTICE, "Created\n");

	return t;

out_ep:
	_gtp_endpoint_release(t->gtp_ep);
out_tun:
	_tun_device_release(t->tun_dev);
out_free:
	talloc_free(t);
out_unlock:
	pthread_rwlock_unlock(&d->rwlock);

	return NULL;
}

/* find tunnel by R(x_teid), T(x_teid) + A(ddr) */
static struct gtp_tunnel *
_gtp_tunnel_find_rta(struct gtp_daemon *d, uint32_t rx_teid, uint32_t tx_teid,
		     const struct sockaddr_storage *user_addr)
{
	struct gtp_tunnel *t;
	llist_for_each_entry(t, &d->gtp_tunnels, list) {
		if (t->rx_teid == rx_teid && t->tx_teid == tx_teid &&
		    sockaddr_equals((struct sockaddr *) &t->user_addr, (struct sockaddr *)user_addr))
			return t;
	}
	return NULL;
}

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
_gtp_tunnel_find_eua(struct tun_device *tun, const struct sockaddr *sa, uint8_t proto)
{
	struct gtp_daemon *d = tun->d;
	struct gtp_tunnel *t;

	llist_for_each_entry(t, &d->gtp_tunnels, list) {
		/* TODO: Find best matching filter */
		if (t->tun_dev == tun && sockaddr_equals(sa, (struct sockaddr *) &t->user_addr))
			return t;
	}
	return NULL;
}

/* UNLOCKED destroy of tunnel; drops references to EP + TUN */
void _gtp_tunnel_destroy(struct gtp_tunnel *t)
{
	LOGT(t, LOGL_NOTICE, "Destroying\n");
	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(t->d);

	if (netdev_del_addr(t->tun_dev->nl, t->tun_dev->ifindex, &t->user_addr) < 0)
		LOGT(t, LOGL_ERROR, "Cannot remove user address: %s\n", strerror(errno));

	llist_del(&t->list);

	/* drop reference to endpoint + tun */
	_gtp_endpoint_release(t->gtp_ep);
	_tun_device_release(t->tun_dev);

	talloc_free(t);
}

bool gtp_tunnel_destroy(struct gtp_daemon *d, const struct sockaddr_storage *bind_addr, uint32_t rx_teid)
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
