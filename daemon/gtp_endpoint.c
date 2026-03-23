/* SPDX-License-Identifier: GPL-2.0 */

/*pthread.h pthread_setname_np(): */
#define _GNU_SOURCE

#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <pthread.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/socket.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>

#include <osmocom/netif/icmpv6.h>

#include "gtp.h"
#include "internal.h"

#define LOGEP(ep, lvl, fmt, args ...) \
	LOGP(DEP, lvl, "%s: " fmt, (ep)->name, ## args)

/* LOGEP "No Cancel": Use within the pthread which can be pthread_cancel()ed, in
 * order to avoid exiting with the logging mutex held and causing a deadlock afterwards. */
#define LOGEP_NC(ep, lvl, fmt, args ...) \
	do { \
		int _old_cancelst_unused; \
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &_old_cancelst_unused); \
		LOGEP(ep, lvl, fmt, ## args); \
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &_old_cancelst_unused); \
	} while (0)

/***********************************************************************
 * GTP Endpoint (UDP socket)
 ***********************************************************************/

static void handle_router_adv(struct gtp_tunnel *t, struct ip6_hdr *ip6h, struct osmo_icmpv6_radv_hdr *ra, size_t ra_len)
{
	struct osmo_icmpv6_opt_hdr *opt_hdr;
	struct osmo_icmpv6_opt_prefix *opt_prefix;
	int rc;
	struct in6_addr rm;
	char ip6strbuf[2][INET6_ADDRSTRLEN];
	memset(&rm, 0, sizeof(rm));

	LOGT(t, LOGL_INFO, "Received ICMPv6 Router Advertisement\n");

	foreach_icmpv6_opt(ra, ra_len, opt_hdr) {
		if (opt_hdr->type == ICMPv6_OPT_TYPE_PREFIX_INFO) {
			opt_prefix = (struct osmo_icmpv6_opt_prefix *)opt_hdr;
			size_t prefix_len_bytes = (opt_prefix->prefix_len + 7)/8;
			LOGT(t, LOGL_DEBUG, "Parsing OPT Prefix info (prefix_len=%u): %s\n",
			     opt_prefix->prefix_len,
			     osmo_hexdump((const unsigned char *)opt_prefix->prefix, prefix_len_bytes));

			memcpy(&t->user_addr_ipv6_prefix.u.sin6.sin6_addr,
			       opt_prefix->prefix,
			       prefix_len_bytes);
			memset(&((uint8_t *)&t->user_addr_ipv6_prefix.u.sin6.sin6_addr)[prefix_len_bytes],
			     0, 16 - prefix_len_bytes);

			/* Pick second address in the prefix: */
			t->user_addr_ipv6_global.u.sa.sa_family = AF_INET6;
			memcpy(&t->user_addr_ipv6_global.u.sin6.sin6_addr,
			       &t->user_addr_ipv6_prefix.u.sin6.sin6_addr,
			       sizeof(t->user_addr_ipv6_prefix.u.sin6.sin6_addr));
			((uint8_t *)&t->user_addr_ipv6_global.u.sin6.sin6_addr)[15] = 2;

			LOGT(t, LOGL_INFO, "Adding global IPv6 prefix %s/%u address %s\n",
			     inet_ntop(AF_INET6, &t->user_addr_ipv6_prefix.u.sin6.sin6_addr, &ip6strbuf[0][0], sizeof(ip6strbuf[0])),
			     opt_prefix->prefix_len,
			     inet_ntop(AF_INET6, &t->user_addr_ipv6_global.u.sin6.sin6_addr, &ip6strbuf[1][0], sizeof(ip6strbuf[1])));

			if ((rc = osmo_netdev_add_addr(t->tun_dev->netdev, &t->user_addr_ipv6_global, 64)) < 0) {
				LOGT(t, LOGL_ERROR, "Cannot add global IPv6 user addr %s to tun device: %s\n",
				     inet_ntop(AF_INET6, &t->user_addr_ipv6_global.u.sin6.sin6_addr, &ip6strbuf[1][0], sizeof(ip6strbuf[1])),
				     strerror(-rc));
			}

			/* Notify cups_client about the new available IPv6 prefix and global address: */
			cc_ipv6_slaac_ind(t);
		}
	}
}

static void handle_gtp1u(struct gtp_endpoint *ep, const uint8_t *buffer, unsigned int nread)
{
	struct gtp_daemon *d = ep->d;
	struct gtp_tunnel *t;
	const struct gtp1_header *gtph;
	const uint8_t *payload;
	int rc, outfd;
	uint32_t teid;
	uint16_t gtp_len;
	char ip6strbuf[200];

	if (nread < sizeof(*gtph)) {
		LOGEP_NC(ep, LOGL_NOTICE, "Short read: %u < %lu\n", nread, sizeof(*gtph));
		return;
	}
	gtph = (struct gtp1_header *)buffer;

	/* check GTP header contents */
	if ((gtph->flags & 0xf0) != 0x30) {
		LOGEP_NC(ep, LOGL_NOTICE, "Unexpected GTP Flags: 0x%02x\n", gtph->flags);
		return;
	}
	if (gtph->type != GTP_TPDU) {
		LOGEP_NC(ep, LOGL_NOTICE, "Unexpected GTP Message Type: 0x%02x\n", gtph->type);
		return;
	}

	gtp_len = ntohs(gtph->length);
	if (sizeof(*gtph)+gtp_len > nread) {
		LOGEP_NC(ep, LOGL_NOTICE, "Short GTP Message: %lu < len=%u\n",
			sizeof(*gtph)+gtp_len, nread);
		return;
	}
	teid = ntohl(gtph->tid);

	payload = buffer + sizeof(*gtph);
	if (gtph->flags & GTP1_F_MASK) {
		const struct gtp1_exthdr *exthdr = (const struct gtp1_exthdr *)payload;
		if (gtp_len < 4) {
			LOGEP_NC(ep, LOGL_NOTICE, "Short GTP Message according to flags 0x%02x: %lu < len=%u\n",
				gtph->flags, sizeof(*gtph) + gtp_len, nread);
			return;
		}
		gtp_len -= 4;
		payload += 4;
		const uint8_t *it = &exthdr->array[0].type;
		while (*it != 0) {
			unsigned int ext_len;
			if (gtp_len < 1) {
				LOGEP_NC(ep, LOGL_NOTICE, "Short GTP Message according to flags 0x%02x: %lu < len=%u\n",
				gtph->flags, sizeof(*gtph) + gtp_len, nread);
				return;
			}
			ext_len = 1 + 1 + it[1] + 1;
			if (gtp_len < ext_len) {
				LOGEP_NC(ep, LOGL_NOTICE, "Short GTP Message according to flags 0x%02x: %lu < len=%u\n",
					gtph->flags, sizeof(*gtph) + gtp_len, nread);
				return;
			}
			gtp_len -= ext_len;
			payload += ext_len;
			it = payload - 1;
		}
	}

	/* 2) look-up tunnel based on TEID */
	pthread_rwlock_rdlock(&d->rwlock);
	t = _gtp_tunnel_find_r(d, teid, ep);
	if (!t) {
		pthread_rwlock_unlock(&d->rwlock);
		LOGEP_NC(ep, LOGL_NOTICE, "Unable to find tunnel for TEID=0x%08x\n", teid);
		return;
	}
	outfd = t->tun_dev->fd;

	struct iphdr *iph = (struct iphdr *)payload;
	struct ip6_hdr *ip6h;
	struct osmo_icmpv6_radv_hdr *ra;
	switch (iph->version) {
	case 4:
		if (t->user_addr_ipv4.u.sa.sa_family != AF_INET) {
			LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unexpected IPv4 %s in non-IPv4 PDP Context\n",
				inet_ntop(AF_INET, &iph->daddr, ip6strbuf, sizeof(ip6strbuf)));
			goto unlock_ret;
		}
		if (memcmp(&iph->daddr, &t->user_addr_ipv4.u.sin.sin_addr, 4) != 0) {
			LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unknown dst IP addr %s\n",
				inet_ntop(AF_INET, &iph->daddr, ip6strbuf, sizeof(ip6strbuf)));
			goto unlock_ret;
		}
		break;
	case 6:
		ip6h = (struct ip6_hdr *)payload;
		if (IN6_IS_ADDR_LINKLOCAL(&ip6h->ip6_dst)) {
			if (t->user_addr_ipv6_ll.u.sa.sa_family != AF_INET6) {
				LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unexpected IPv6 %s in non-IPv6 PDP Context\n",
				     inet_ntop(AF_INET6, &ip6h->ip6_dst, ip6strbuf, sizeof(ip6strbuf)));
				goto unlock_ret;
			}
			if (memcmp(&ip6h->ip6_dst, &t->user_addr_ipv6_ll.u.sin6.sin6_addr, 16) != 0) {
				LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unknown link-local dst IP addr %s\n",
				     inet_ntop(AF_INET6, &ip6h->ip6_dst, ip6strbuf, sizeof(ip6strbuf)));
				goto unlock_ret;
			}
			if ((ra = osmo_icmpv6_validate_router_adv(payload, gtp_len))) {
				size_t ra_len = (uint8_t *)ra - (uint8_t *)payload;
				handle_router_adv(t, (struct ip6_hdr *)payload, ra, ra_len);
				goto unlock_ret;
			}
		} else {
			/* Match by global IPv6 /64 prefix allocated through SLAAC: */
			if (t->user_addr_ipv6_global.u.sa.sa_family != AF_INET6) {
				LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unexpected IPv6 %s in non-IPv6 PDP Context\n",
				     inet_ntop(AF_INET6, &ip6h->ip6_dst, ip6strbuf, sizeof(ip6strbuf)));
				goto unlock_ret;
			}
			if (memcmp(&ip6h->ip6_dst, &t->user_addr_ipv6_prefix.u.sin6.sin6_addr, 8) != 0) {
				LOGT(t, LOGL_NOTICE, "Rx GTPU payload for unknown global dst IP addr %s\n",
				inet_ntop(AF_INET6, &ip6h->ip6_dst, ip6strbuf, sizeof(ip6strbuf)));
				goto unlock_ret;
			}
		}
		break;
	default:
		LOGT(t, LOGL_NOTICE, "Rx GTPU payload with unknown IP version %d\n", iph->version);
		goto unlock_ret;
	}

	outfd = t->tun_dev->fd;
	pthread_rwlock_unlock(&d->rwlock);

	/* 3) write to TUN device */
	rc = write(outfd, payload, gtp_len);
	if (rc < gtp_len) {
		LOGEP_NC(ep, LOGL_FATAL, "Error writing to tun device %s\n", strerror(errno));
		exit(1);
	}
	return;

unlock_ret:
	pthread_rwlock_unlock(&d->rwlock);
	return;
}

/* One thread for reading from each GTP/UDP socket (GTP decapsulation -> tun)
 * IMPORTANT!: Since this thread is cancellable (deferred type):
 * - All osmo logging functions in this thread must be called with PTHREAD_CANCEL_DISABLE set,
 *   otherwise the thread could be cancelled while holding the libosmocore logging mutex, hence causing
 *   deadlock with main (or other) thread.
 * - Within pthread_rwlock_*(&d->rwlock) mutual exclusion zone, if we ever do any call considered
 *   a cancellation point (see "man pthreads"), then make sure to do the call protected with
 *   PTHREAD_CANCEL_DISABLE set, otherwise we may leave the d->rwlock held forever and cause a deadlock
 *   with main (or other) thread.
 */
static void *gtp_endpoint_thread(void *arg)
{
	struct gtp_endpoint *ep = (struct gtp_endpoint *)arg;
	char thread_name[16];
	uint8_t buffer[sizeof(struct gtp1_header) + sizeof(struct gtp1_exthdr) + MAX_UDP_PACKET];

	snprintf(thread_name, sizeof(thread_name), "RxGtpu%s", ep->name);
	pthread_setname_np(pthread_self(), thread_name);

	while (1) {
		int rc;

		/* 1) read GTP packet from UDP socket */
		rc = recvfrom(ep->fd, buffer, sizeof(buffer), 0, (struct sockaddr *)NULL, 0);
		if (rc < 0) {
			LOGEP_NC(ep, LOGL_FATAL, "Error reading from UDP socket: %s\n", strerror(errno));
			exit(1);
		}
		handle_gtp1u(ep, buffer, rc);
	}
}

static struct gtp_endpoint *
_gtp_endpoint_create(struct gtp_daemon *d, const struct osmo_sockaddr *bind_addr)
{
	struct gtp_endpoint *ep = talloc_zero(d, struct gtp_endpoint);
	char ipstr[INET6_ADDRSTRLEN];
	char portstr[8];
	int rc;

	if (!ep)
		return NULL;

	rc = getnameinfo(&bind_addr->u.sa, sizeof(bind_addr->u.sas),
			 ipstr, sizeof(ipstr), portstr, sizeof(portstr), NI_NUMERICHOST|NI_NUMERICSERV);
	if (rc != 0)
		goto out_free;
	ep->name = talloc_asprintf(ep, "%s:%s", ipstr, portstr);

	ep->d = d;
	ep->use_count = 1;
	ep->bind_addr = *bind_addr;
	ep->fd = socket(ep->bind_addr.u.sa.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (ep->fd < 0) {
		LOGEP(ep, LOGL_ERROR, "Cannot create UDP socket: %s\n", strerror(errno));
		goto out_free;
	}
	rc = bind(ep->fd, &ep->bind_addr.u.sa, sizeof(ep->bind_addr.u.sas));
	if (rc < 0) {
		LOGEP(ep, LOGL_ERROR, "Cannot bind UDP socket: %s\n", strerror(errno));
		goto out_close;
	}

	if (pthread_create(&ep->thread, NULL, gtp_endpoint_thread, ep)) {
		LOGEP(ep, LOGL_ERROR, "Cannot start GTP thread: %s\n", strerror(errno));
		goto out_close;
	}

	llist_add_tail(&ep->list, &d->gtp_endpoints);
	LOGEP(ep, LOGL_INFO, "Created\n");

	return ep;

out_close:
	close(ep->fd);
out_free:
	talloc_free(ep);
	return NULL;
}

struct gtp_endpoint *
_gtp_endpoint_find(struct gtp_daemon *d, const struct osmo_sockaddr *bind_addr)
{
	struct gtp_endpoint *ep;

	llist_for_each_entry(ep, &d->gtp_endpoints, list) {
		if (osmo_sockaddr_cmp(&ep->bind_addr, bind_addr) == 0)
			return ep;
	}
	return NULL;
}

struct gtp_endpoint *
gtp_endpoint_find_or_create(struct gtp_daemon *d, const struct osmo_sockaddr *bind_addr)
{
	struct gtp_endpoint *ep;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(d);

	pthread_rwlock_wrlock(&d->rwlock);
	ep = _gtp_endpoint_find(d, bind_addr);
	if (ep)
		ep->use_count++;
	else
		ep = _gtp_endpoint_create(d, bind_addr);
	pthread_rwlock_unlock(&d->rwlock);

	return ep;
}

/* UNLOCKED hard/forced destroy; caller must make sure references are cleaned up */
static void _gtp_endpoint_destroy(struct gtp_endpoint *ep)
{
	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(ep->d);

	if (ep->use_count)
		LOGEP(ep, LOGL_ERROR, "Destroying despite use_count %lu != 0\n", ep->use_count);
	else
		LOGEP(ep, LOGL_INFO, "Destroying\n");

	pthread_cancel(ep->thread);
	llist_del(&ep->list);
	close(ep->fd);
	talloc_free(ep);
}

/* UNLOCKED remove all objects referencing this ep and then destroy */
void _gtp_endpoint_deref_destroy(struct gtp_endpoint *ep)
{
	struct gtp_daemon *d = ep->d;
	struct osmo_sockaddr osa = ep->bind_addr;
	struct gtp_tunnel *t, *t2;
	struct gtp_endpoint *ep2;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(ep->d);

	/* iterate over all tunnels; delete all references to ep */
	llist_for_each_entry_safe(t, t2, &d->gtp_tunnels, list) {
		if (t->gtp_ep == ep)
			_gtp_tunnel_destroy(t);
	}

	/* _gtp_endpoint_destroy may already have been called via
	 * _gtp_tunnel_destroy -> gtp_endpoint_release, so we have to
	 * check if the ep can still be found in the list */
	ep2 = _gtp_endpoint_find(d, &osa);
	if (ep2 && ep2 == ep)
		_gtp_endpoint_destroy(ep2);
}

/* UNLOCKED release a reference; destroy if refcount drops to 0 */
bool _gtp_endpoint_release(struct gtp_endpoint *ep)
{
	bool released = false;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(ep->d);

	ep->use_count--;
	if (ep->use_count == 0) {
		_gtp_endpoint_destroy(ep);
		released = true;
	} else
		LOGEP(ep, LOGL_DEBUG, "Release; new use_count=%lu\n", ep->use_count);

	return released;
}


/* release a reference; destroy if refcount drops to 0 */
bool gtp_endpoint_release(struct gtp_endpoint *ep)
{
	struct gtp_daemon *d = ep->d;
	bool released;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(ep->d);

	pthread_rwlock_wrlock(&d->rwlock);
	released = _gtp_endpoint_release(ep);
	pthread_rwlock_unlock(&d->rwlock);

	return released;
}
