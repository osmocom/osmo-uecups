/* SPDX-License-Identifier: GPL-2.0 */
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/socket.h>
#include <osmocom/core/linuxlist.h>
#include <osmocom/core/write_queue.h>
#include <osmocom/core/utils.h>

struct nl_sock;
struct osmo_stream_srv_link;

/***********************************************************************
 * Utility
 ***********************************************************************/
/* ensure we are called from main thread context */
#define ASSERT_MAIN_THREAD(d) OSMO_ASSERT(pthread_self() == (d)->main_thread)

#define MAX_UDP_PACKET 65535

bool sockaddr_equals(const struct sockaddr *a, const struct sockaddr *b);

struct addrinfo *addrinfo_helper(uint16_t family, uint16_t type, uint8_t proto,
				 const char *host, uint16_t port, bool passive);
enum {
	DTUN,
	DEP,
	DGT,
	DUECUPS,
};

/***********************************************************************
 * netdev / netlink
 ***********************************************************************/

int netdev_add_addr(struct nl_sock *nlsk, int ifindex, const struct sockaddr_storage *ss);
int netdev_del_addr(struct nl_sock *nlsk, int ifindex, const struct sockaddr_storage *ss);
int netdev_set_link(struct nl_sock *nlsk, int ifindex, bool up);
int netdev_add_defaultroute(struct nl_sock *nlsk, int ifindex, uint8_t family);


/***********************************************************************
 * GTP Endpoint (UDP socket)
 ***********************************************************************/

struct gtp_daemon;

/* local UDP socket for GTP communication */
struct gtp_endpoint {
	/* entry in global list */
	struct llist_head list;
	/* back-pointer to daemon */
	struct gtp_daemon *d;
	unsigned long use_count;

	/* file descriptor */
	int fd;

	/* local IP:port */
	struct sockaddr_storage bind_addr;
	char *name;

	/* the thread handling Rx from the fd/socket */
	pthread_t thread;
};


struct gtp_endpoint *
gtp_endpoint_find_or_create(struct gtp_daemon *d, const struct sockaddr_storage *bind_addr);

struct gtp_endpoint *
_gtp_endpoint_find(struct gtp_daemon *d, const struct sockaddr_storage *bind_addr);

void _gtp_endpoint_deref_destroy(struct gtp_endpoint *ep);

bool _gtp_endpoint_release(struct gtp_endpoint *ep);

bool gtp_endpoint_release(struct gtp_endpoint *ep);



/***********************************************************************
 * TUN Device
 ***********************************************************************/

struct tun_device {
	/* entry in global list */
	struct llist_head list;
	/* back-pointer to daemon */
	struct gtp_daemon *d;
	unsigned long use_count;

	/* which device we refer to */
	const char *devname;
	int ifindex;

	/* file descriptor */
	int fd;

	/* network namespace */
	const char *netns_name;
	int netns_fd;

	/* netlink socket in the namespace of the tun device */
	struct nl_sock *nl;

	/* list of local addresses? or simply only have the kernel know thses? */

	/* the thread handling Rx from the tun fd */
	pthread_t thread;
};

struct tun_device *
tun_device_find_or_create(struct gtp_daemon *d, const char *devname, const char *netns_name);

struct tun_device *
_tun_device_find(struct gtp_daemon *d, const char *devname);

void _tun_device_deref_destroy(struct tun_device *tun);

bool _tun_device_release(struct tun_device *tun);

bool tun_device_release(struct tun_device *tun);



/***********************************************************************
 * GTP Tunnel
 ***********************************************************************/

/* Every tunnel is identified uniquely by the following tuples:
 *
 * a) local endpoint + TEID
 *    this is what happens on incoming GTP messages
 *
 * b) tun device + end-user-address (+ filter, if any)
 *    this is what happens when IP arrives on the tun device
 */

struct gtp_tunnel {
	/* entry in global list / hash table */
	struct llist_head list;
	/* back-pointer to daemon */
	struct gtp_daemon *d;

	const char *name;

	/* the TUN device associated with this tunnel */
	struct tun_device *tun_dev;
	/* the GTP endpoint (UDP socket) associated with this tunnel */
	struct gtp_endpoint *gtp_ep;

	/* TEID on transmit (host byte order) */
	uint32_t tx_teid;
	/* TEID one receive (host byte order) */
	uint32_t rx_teid;

	/* End user Address (inner IP) */
	struct sockaddr_storage	user_addr;

	/* Remote UDP IP/Port*/
	struct sockaddr_storage remote_udp;

	/* TODO: Filter */
};

struct gtp_tunnel *
_gtp_tunnel_find_r(struct gtp_daemon *d, uint32_t rx_teid, struct gtp_endpoint *ep);

struct gtp_tunnel *
_gtp_tunnel_find_eua(struct tun_device *tun, const struct sockaddr *sa, uint8_t proto);

struct gtp_tunnel_params {
	/* TEID in receive and transmit direction */
	uint32_t rx_teid;
	uint32_t tx_teid;

	/* end user address */
	struct sockaddr_storage user_addr;

	/* remote GTP/UDP IP+Port */
	struct sockaddr_storage remote_udp;

	/* local GTP/UDP IP+Port (used to lookup/create local EP) */
	struct sockaddr_storage local_udp;

	/* local TUN device name (used to lookup/create local tun) */
	const char *tun_name;
        const char *tun_netns_name;
};
struct gtp_tunnel *gtp_tunnel_alloc(struct gtp_daemon *d, const struct gtp_tunnel_params *cpars);

void _gtp_tunnel_destroy(struct gtp_tunnel *t);
bool gtp_tunnel_destroy(struct gtp_daemon *d, const struct sockaddr_storage *bind_addr, uint32_t rx_teid);


/***********************************************************************
 * GTP Daemon
 ***********************************************************************/

#define UECUPS_SCTP_PORT	4268

struct gtp_daemon {
	/* global lists of various objects */
	struct llist_head gtp_endpoints;
	struct llist_head tun_devices;
	struct llist_head gtp_tunnels;
	/* lock protecting all of the above lists */
	pthread_rwlock_t rwlock;
	/* main thread ID */
	pthread_t main_thread;
	/* client CUPS interface */
	struct llist_head cups_clients;
	struct osmo_stream_srv_link *cups_link;

	struct {
		char *cups_local_ip;
		uint16_t cups_local_port;
	} cfg;
};
extern struct gtp_daemon *g_daemon;

int gtpud_vty_init(void);
