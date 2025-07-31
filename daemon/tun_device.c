/* SPDX-License-Identifier: GPL-2.0 */

/*pthread.h pthread_setname_np(): */
#define _GNU_SOURCE

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

/* LOGTUN "No Cancel": Use within the pthread which can be pthread_cancel()ed, in
 * order to avoid exiting with the logging mutex held and causing a deadlock afterwards. */
#define LOGTUN_NC(ep, lvl, fmt, args ...) \
	do { \
		int _old_cancelst_unused; \
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &_old_cancelst_unused); \
		LOGTUN(tun, lvl, fmt, ## args); \
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &_old_cancelst_unused); \
	} while (0)

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

static void tun_device_pthread_cleanup_routine(void *data)
{
	struct tun_device *tun = data;
	LOGTUN(tun, LOGL_DEBUG, "pthread_cleanup\n");
	int rc = osmo_it_q_enqueue(tun->d->itq, &tun->itq_msg, list);
	OSMO_ASSERT(rc == 0);
}

/* Note: This function is called with d->rwlock locked, and it's responsible of unlocking it before returning. */
static int tx_gtp1u_pkt(struct gtp_tunnel *t, uint8_t *base_buffer, const uint8_t *payload, unsigned int payload_len)
{
	struct gtp1_header *gtph;
	unsigned int head_len = payload - base_buffer;
	unsigned int hdr_len_needed;
	unsigned int opt_hdr_len_needed = 0;
	struct sockaddr_storage daddr;
	int outfd = t->gtp_ep->fd;
	int rc;
	uint8_t flags;

#define GTP1_F_NPDU	0x01
#define GTP1_F_SEQ	0x02
#define GTP1_F_EXTHDR	0x04
#define GTP1_F_MASK	0x07

	flags = 0x30; /* Version */

	if (t->exthdr.seq_num_enabled)
		flags |= GTP1_F_SEQ;

	if (t->exthdr.n_pdu_num_enabled)
		flags |= GTP1_F_NPDU;

	if (t->exthdr.pdu_sess_container.enabled) {
		flags |= GTP1_F_EXTHDR;
		opt_hdr_len_needed += 4; /* Extra Header struct */
	}

	/* Make sure the Next Extension Header Type is counted: */
	if (flags & GTP1_F_MASK)
		opt_hdr_len_needed += 4;

	hdr_len_needed = sizeof(struct gtp1_header) + opt_hdr_len_needed;
	OSMO_ASSERT(hdr_len_needed < head_len);
	gtph = (struct gtp1_header *)(payload - hdr_len_needed);
	/* initialize the fixed part of the GTP header */
	gtph->flags = flags;
	gtph->type = GTP_TPDU;
	gtph->length = htons(opt_hdr_len_needed + payload_len);
	gtph->tid = htonl(t->tx_teid);

	if (flags & GTP1_F_MASK) {
		struct gtp1_exthdr *exthdr = (struct gtp1_exthdr *)(((uint8_t *)gtph) + sizeof(*gtph));
		exthdr->sequence_number = htons(0); /* TODO: increment sequence_number in "t". */
		exthdr->n_pdu_number = 0; /* TODO: increment n_pdu_number in "t". */
		if (t->exthdr.pdu_sess_container.enabled) {
			exthdr->array[0].type = GTP1_EXTHDR_PDU_SESSION_CONTAINER;
			exthdr->array[0].len = 1;
			exthdr->array[0].spare1 = 0;
			exthdr->array[0].pdu_type = t->exthdr.pdu_sess_container.pdu_type;
			exthdr->array[0].qos_flow_identifier = t->exthdr.pdu_sess_container.qos_flow_identifier;
			exthdr->array[0].reflective_qos_indicator = 0;
			exthdr->array[0].paging_policy_presence = 0;
			exthdr->array[1].type = 0; /* No extension headers */
		} else {
			exthdr->array[0].type = 0; /* No extension headers */
		}
	}

	memcpy(&daddr, &t->remote_udp, sizeof(daddr));
	pthread_rwlock_unlock(&t->d->rwlock);

	/* 4) write to GTP/UDP socket */
	rc = sendto(outfd, gtph, hdr_len_needed + payload_len, 0,
			(struct sockaddr *)&daddr, sizeof(daddr));
	return rc;
}

/* one thread for reading from each TUN device (TUN -> GTP encapsulation) */
static void *tun_device_thread(void *arg)
{
	struct tun_device *tun = (struct tun_device *)arg;
	struct gtp_daemon *d = tun->d;
	char thread_name[16];
	/* Make sure "buffer" below ends up aligned to 4byte so that it can access struct iphdr in a 4-byte aligned way. */
	const size_t payload_off_4byte_aligned = ((sizeof(struct gtp1_header) + sizeof(struct gtp1_exthdr)) + 3) & (~0x3);
	uint8_t base_buffer[payload_off_4byte_aligned + MAX_UDP_PACKET];

	pthread_cleanup_push(tun_device_pthread_cleanup_routine, tun);
	/* IMPORTANT!: All logging functions in this function block must be called with
	 * PTHREAD_CANCEL_DISABLE set, otherwise the thread could be cancelled while
	 * holding the logging mutex, hence causing deadlock with main (or other)
	 * thread. */

	snprintf(thread_name, sizeof(thread_name), "Rx%s", tun->devname);
	pthread_setname_np(pthread_self(), thread_name);

	while (1) {
		struct gtp_tunnel *t;
		struct pkt_info pinfo;
		int rc, nread;
		uint8_t *buffer = base_buffer + payload_off_4byte_aligned;

		/* 1) read from tun */
		rc = read(tun->fd, buffer, MAX_UDP_PACKET);
		if (rc < 0) {
			LOGTUN_NC(tun, LOGL_FATAL, "Error readingfrom tun device: %s\n", strerror(errno));
			exit(1);
		}
		nread = rc;

		rc = parse_pkt(&pinfo, buffer, nread);
		if (rc < 0) {
			LOGTUN_NC(tun, LOGL_NOTICE, "Error parsing IP packet: %s\n", osmo_hexdump(buffer, nread));
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
			LOGTUN_NC(tun, LOGL_NOTICE, "No tunnel found for source address %s:%s\n", host, port);
			continue;
		}
		rc = tx_gtp1u_pkt(t, base_buffer, buffer, nread);
		if (rc < 0) {
			LOGTUN_NC(tun, LOGL_FATAL, "Error Writing to UDP socket: %s\n", strerror(errno));
			exit(1);
		}
	}
	pthread_cleanup_pop(1);
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
		osmo_strlcpy(ifr.ifr_name, name, IFNAMSIZ);
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
			LOGTUN(tun, LOGL_ERROR, "Cannot add IPv4 default route "
						"(rc=%d): %s\n", rc, nl_geterror(rc));
		else
			LOGTUN(tun, LOGL_INFO, "Added IPv4 default route\n");

		rc = netdev_add_defaultroute(tun->nl, tun->ifindex, AF_INET6);
		if (rc < 0)
			LOGTUN(tun, LOGL_ERROR, "Cannot add IPv6 default route "
						"(rc=%d): %s\n", rc, nl_geterror(rc));
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

/* UNLOCKED hard/forced destroy; caller must make sure references are cleaned
 * up, and tun thread is stopped beforehand by calling
 * _tun_device_{deref_}release */
void _tun_device_destroy(struct tun_device *tun)
{
	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);
	LOGTUN(tun, LOGL_INFO, "Destroying\n");

	if (tun->netns_name)
		close(tun->netns_fd);
	close(tun->fd);
	nl_socket_free(tun->nl);
	talloc_free(tun);
}

/* UNLOCKED remove all objects referencing this tun and then start async tun release procedure */
void _tun_device_deref_release(struct tun_device *tun)
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
		_tun_device_release(tun2);

	talloc_free(devname);
}

/* UNLOCKED release a reference; start async tun release procedure if refcount drops to 0 */
bool _tun_device_release(struct tun_device *tun)
{
	bool released = false;

	/* talloc is not thread safe, all alloc/free must come from main thread */
	ASSERT_MAIN_THREAD(tun->d);

	tun->use_count--;
	if (tun->use_count == 0) {
		LOGTUN(tun, LOGL_INFO, "Releasing\n");
		llist_del(&tun->list);
		tun->itq_msg.tun_released.tun = tun;
		tun->d->reset_all_state_tun_remaining++;
		/* We cancel the thread: the pthread_cleanup routing will send a message
		 * back to us (main thread) when finally cancelled. */
		pthread_cancel(tun->thread);
		released = true;
	} else {
		LOGTUN(tun, LOGL_DEBUG, "Release; new use_count=%lu\n", tun->use_count);
	}

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
