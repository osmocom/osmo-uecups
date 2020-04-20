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
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>

#include <netinet/ip.h>
#include <netinet/ip6.h>

#include <pthread.h>

#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>

#include <linux/netlink.h>
#include <netlink/socket.h>
#include <netlink/route/link.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/utils.h>

#include "gtp.h"
#include "internal.h"
#include "netns.h"

/***********************************************************************
 * TUN Device
 ***********************************************************************/

#define LOGTUN(tun, lvl, fmt, args ...) \
	LOGP(DTUN, lvl, "%s: " fmt, (tun)->devname, ## args)

/* extracted information from a packet */
struct pkt_info {
	struct sockaddr_storage saddr;
	struct sockaddr_storage daddr;
	uint8_t proto;
};

static int parse_pkt(struct pkt_info *out, const uint8_t *in, unsigned int in_len)
{
	const struct iphdr *ip4 = (struct iphdr *) in;
	const uint16_t *l4h = NULL;

	memset(out, 0, sizeof(*out));

	if (ip4->version == 4) {
		struct sockaddr_in *saddr4 = (struct sockaddr_in *) &out->saddr;
		struct sockaddr_in *daddr4 = (struct sockaddr_in *) &out->daddr;

		if (in_len < sizeof(*ip4) || in_len < 4*ip4->ihl)
			return -1;

		saddr4->sin_family = AF_INET;
		saddr4->sin_addr.s_addr = ip4->saddr;

		daddr4->sin_family = AF_INET;
		daddr4->sin_addr.s_addr = ip4->daddr;

		out->proto = ip4->protocol;
		l4h = (const uint16_t *) (in + sizeof(*ip4));

		switch (out->proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_DCCP:
		case IPPROTO_SCTP:
		case IPPROTO_UDPLITE:
			saddr4->sin_port = ntohs(l4h[0]);
			daddr4->sin_port = ntohs(l4h[1]);
			break;
		default:
			break;
		}
	} else if (ip4->version == 6) {
		const struct ip6_hdr *ip6 = (struct ip6_hdr *) in;
		struct sockaddr_in6 *saddr6 = (struct sockaddr_in6 *) &out->saddr;
		struct sockaddr_in6 *daddr6 = (struct sockaddr_in6 *) &out->daddr;

		if (in_len < sizeof(*ip6))
			return -1;

		saddr6->sin6_family = AF_INET6;
		saddr6->sin6_addr = ip6->ip6_src;

		daddr6->sin6_family = AF_INET6;
		daddr6->sin6_addr = ip6->ip6_dst;

		/* FIXME: ext hdr */
		out->proto = ip6->ip6_nxt;
		l4h = (const uint16_t *) (in + sizeof(*ip6));

		switch (out->proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_DCCP:
		case IPPROTO_SCTP:
		case IPPROTO_UDPLITE:
			saddr6->sin6_port = ntohs(l4h[0]);
			daddr6->sin6_port = ntohs(l4h[1]);
			break;
		default:
			break;
		}
	} else
		return -1;

	return 0;
}

/* one thread for reading from each TUN device (TUN -> GTP encapsulation) */
static void *tun_device_thread(void *arg)
{
	struct tun_device *tun = (struct tun_device *)arg;
	struct gtp_daemon *d = tun->d;

	uint8_t base_buffer[MAX_UDP_PACKET+sizeof(struct gtp1_header)];
	struct gtp1_header *gtph = (struct gtp1_header *)base_buffer;
	uint8_t *buffer = base_buffer + sizeof(struct gtp1_header);

	struct sockaddr_storage daddr;

	/* initialize the fixed part of the GTP header */
	gtph->flags = 0x30;
	gtph->type = GTP_TPDU;

	while (1) {
		struct gtp_tunnel *t;
		struct pkt_info pinfo;
		int rc, nread, outfd;

		/* 1) read from tun */
		rc = read(tun->fd, buffer, MAX_UDP_PACKET);
		if (rc < 0) {
			LOGTUN(tun, LOGL_FATAL, "Error readingfrom tun device: %s\n", strerror(errno));
			exit(1);
		}
		nread = rc;
		gtph->length = htons(nread);

		rc = parse_pkt(&pinfo, buffer, nread);
		if (rc < 0) {
			LOGTUN(tun, LOGL_NOTICE, "Error parsing IP packet: %s\n",
				osmo_hexdump(buffer, nread));
			continue;
		}

		if (pinfo.saddr.ss_family == AF_INET6 && pinfo.proto == IPPROTO_ICMPV6) {
			/* 2) TODO: magic voodoo for IPv6 neighbor discovery */
		}

		/* 3) look-up tunnel based on source IP address (+ filter) */
		pthread_rwlock_rdlock(&d->rwlock);
		t = _gtp_tunnel_find_eua(tun, (struct sockaddr *) &pinfo.saddr, pinfo.proto);
		if (!t) {
			char host[128];
			char port[8];
			pthread_rwlock_unlock(&d->rwlock);
			getnameinfo((const struct sockaddr *)&pinfo.saddr,
				    sizeof(pinfo.saddr), host, sizeof(host), port, sizeof(port),
				    NI_NUMERICHOST | NI_NUMERICSERV);
			LOGTUN(tun, LOGL_NOTICE, "No tunnel found for source address %s:%s\n", host, port);
			continue;
		}
		outfd = t->gtp_ep->fd;
		memcpy(&daddr, &t->remote_udp, sizeof(daddr));
		gtph->tid = htonl(t->tx_teid);
		pthread_rwlock_unlock(&d->rwlock);

		/* 4) write to GTP/UDP socket */
		rc = sendto(outfd, base_buffer, nread+sizeof(*gtph), 0,
			    (struct sockaddr *)&daddr, sizeof(daddr));
		if (rc < 0) {
			LOGTUN(tun, LOGL_FATAL, "Error Writing to UDP socket: %s\n", strerror(errno));
			exit(1);
		}
	}
}

static int tun_open(int flags, const char *name)
{
	struct ifreq ifr;
	int fd, rc;

	fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		LOGP(DTUN, LOGL_ERROR, "Cannot open /dev/net/tun: %s\n", strerror(errno));
		return fd;
	}

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI | flags;
	if (name) {
		/* if a TUN interface name was specified, put it in the structure; otherwise,
		   the kernel will try to allocate the "next" device of the specified type */
		strncpy(ifr.ifr_name, name, IFNAMSIZ);
	}

	/* try to create the device */
	rc = ioctl(fd, TUNSETIFF, (void *) &ifr);
	if (rc < 0) {
		close(fd);
		return rc;
	}

	/* FIXME: read name back from device? */
	/* FIXME: SIOCSIFTXQLEN / SIOCSIFFLAGS */

	return fd;
}

static struct tun_device *
_tun_device_create(struct gtp_daemon *d, const char *devname, const char *netns_name)
{
	struct rtnl_link *link;
	struct tun_device *tun;
	sigset_t oldmask;
	int rc;

	tun = talloc_zero(d, struct tun_device);
	if (!tun)
		return NULL;

	tun->d = d;
	tun->use_count = 1;
	tun->devname = talloc_strdup(tun, devname);

	if (netns_name) {
		tun->netns_name = talloc_strdup(tun, netns_name);
		tun->netns_fd = get_nsfd(tun->netns_name);
		if (tun->netns_fd < 0) {
			LOGTUN(tun, LOGL_ERROR, "Cannot obtain netns file descriptor: %s\n",
				strerror(errno));
			goto err_free;
		}
	}

	/* temporarily switch to specified namespace to create tun device */
	if (tun->netns_name) {
		rc = switch_ns(tun->netns_fd, &oldmask);
		if (rc < 0) {
			LOGTUN(tun, LOGL_ERROR, "Cannot switch to netns '%s': %s\n",
				tun->netns_name, strerror(errno));
			goto err_close_ns;
		}
	}

	tun->fd = tun_open(0, tun->devname);
	if (tun->fd < 0) {
		LOGTUN(tun, LOGL_ERROR, "Cannot open TUN device: %s\n", strerror(errno));
		goto err_restore_ns;
	}

	tun->nl = nl_socket_alloc();
	if (!tun->nl || nl_connect(tun->nl, NETLINK_ROUTE) < 0) {
		LOGTUN(tun, LOGL_ERROR, "Cannot create netlink socket in namespace '%s'\n",
			tun->netns_name);
		goto err_close;
	}

	rc = rtnl_link_get_kernel(tun->nl, 0, tun->devname, &link);
	if (rc < 0) {
		LOGTUN(tun, LOGL_ERROR, "Cannot get ifindex for netif after create?!?\n");
		goto err_free_nl;
	}
	tun->ifindex = rtnl_link_get_ifindex(link);
	rtnl_link_put(link);

	/* switch back to default namespace before creating new thread */
	if (tun->netns_name)
		OSMO_ASSERT(restore_ns(&oldmask) == 0);

	/* bring the network device up */
	rc = netdev_set_link(tun->nl, tun->ifindex, true);
	if (rc < 0)
		LOGTUN(tun, LOGL_ERROR, "Cannot set interface to 'up'\n");

	if (tun->netns_name) {
		rc = netdev_add_defaultroute(tun->nl, tun->ifindex, AF_INET);
		if (rc < 0)
			LOGTUN(tun, LOGL_ERROR, "Cannot add IPv4 default route\n");
		else
			LOGTUN(tun, LOGL_INFO, "Added IPv4 default route\n");

		rc = netdev_add_defaultroute(tun->nl, tun->ifindex, AF_INET6);
		if (rc < 0)
			LOGTUN(tun, LOGL_ERROR, "Cannot add IPv6 default route\n");
		else
			LOGTUN(tun, LOGL_INFO, "Added IPv6 default route\n");
	}

	if (pthread_create(&tun->thread, NULL, tun_device_thread, tun)) {
		LOGTUN(tun, LOGL_ERROR, "Cannot create TUN thread: %s\n", strerror(errno));
		goto err_free_nl;
	}

	LOGTUN(tun, LOGL_INFO, "Created (in netns '%s')\n", tun->netns_name);
	llist_add_tail(&tun->list, &d->tun_devices);

	return tun;

err_free_nl:
	nl_socket_free(tun->nl);
err_close:
	close(tun->fd);
err_restore_ns:
	if (tun->netns_name)
		OSMO_ASSERT(restore_ns(&oldmask) == 0);
err_close_ns:
	if (tun->netns_name)
		close(tun->netns_fd);
err_free:
	talloc_free(tun);
	return NULL;
}

struct tun_device *
_tun_device_find(struct gtp_daemon *d, const char *devname)
{
	struct tun_device *tun;

	llist_for_each_entry(tun, &d->tun_devices, list) {
		if (!strcmp(tun->devname, devname))
			return tun;
	}
	return NULL;
}

/* find the first tun device within given named netns */
struct tun_device *
tun_device_find_netns(struct gtp_daemon *d, const char *netns_name)
{
	struct tun_device *tun;

	pthread_rwlock_rdlock(&d->rwlock);
	llist_for_each_entry(tun, &d->tun_devices, list) {
		if (!strcmp(tun->netns_name, netns_name)) {
			pthread_rwlock_unlock(&d->rwlock);
			return tun;
		}
	}
	pthread_rwlock_unlock(&d->rwlock);
	return NULL;
}

struct tun_device *
tun_device_find_or_create(struct gtp_daemon *d, const char *devname, const char *netns_name)
{
	struct tun_device *tun;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(d);

	pthread_rwlock_wrlock(&d->rwlock);
	tun = _tun_device_find(d, devname);
	if (tun)
		tun->use_count++;
	else
		tun = _tun_device_create(d, devname, netns_name);
	pthread_rwlock_unlock(&d->rwlock);

	return tun;
}

/* UNLOCKED hard/forced destroy; caller must make sure references are cleaned up */
static void _tun_device_destroy(struct tun_device *tun)
{
	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);

	pthread_cancel(tun->thread);
	llist_del(&tun->list);
	if (tun->netns_name)
		close(tun->netns_fd);
	close(tun->fd);
	nl_socket_free(tun->nl);
	LOGTUN(tun, LOGL_INFO, "Destroying\n");
	talloc_free(tun);
}

/* UNLOCKED remove all objects referencing this tun and then destroy */
void _tun_device_deref_destroy(struct tun_device *tun)
{
	struct gtp_daemon *d = tun->d;
	char *devname = talloc_strdup(d, tun->devname);
	struct gtp_tunnel *t, *t2;
	struct tun_device *tun2;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);

	llist_for_each_entry_safe(t, t2, &g_daemon->gtp_tunnels, list) {
		if (t->tun_dev == tun)
			_gtp_tunnel_destroy(t);
	}
	/* _tun_device_destroy may already have been called via
	 * _gtp_tunnel_destroy -> _tun_device_release, so we have to
	 * check if the tun can still be found in the list */
	tun2 = _tun_device_find(d, devname);
	if (tun2 && tun2 == tun)
		_tun_device_destroy(tun2);

	talloc_free(devname);
}

/* UNLOCKED release a reference; destroy if refcount drops to 0 */
bool _tun_device_release(struct tun_device *tun)
{
	bool released = false;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);

	tun->use_count--;
	if (tun->use_count == 0) {
		_tun_device_destroy(tun);
		released = true;
	} else
		LOGTUN(tun, LOGL_DEBUG, "Release; new use_count=%lu\n", tun->use_count);

	return released;
}

/* release a reference; destroy if refcount drops to 0 */
bool tun_device_release(struct tun_device *tun)
{
	struct gtp_daemon *d = tun->d;
	bool released;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);

	pthread_rwlock_wrlock(&d->rwlock);
	released = _tun_device_release(tun);
	pthread_rwlock_unlock(&d->rwlock);

	return released;
}
