#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <osmocom/core/talloc.h>
#include <osmocom/core/utils.h>
#include <osmocom/core/rate_ctr.h>

#include <osmocom/vty/command.h>
#include <osmocom/vty/vty.h>
#include <osmocom/vty/misc.h>

#include "internal.h"
#include "gtp.h"

#define TUN_STR	"tun device commands\n"
#define GTP_EP_STR "GTP endpoint commands\n"
#define TUNNEL_STR "GTP tunnel commands\n"

static void show_tun_hdr(struct vty *vty)
{
	vty_out(vty,
		" tun device name | netwk  namespace | use count%s", VTY_NEWLINE);
	vty_out(vty,
		"---------------- | ---------------- | ---------%s", VTY_NEWLINE);
}

static void show_one_tun(struct vty *vty, const struct tun_device *tun)
{
	vty_out(vty, "%16s | %16s | %lu%s",
		tun->devname, tun->netns_name, tun->use_count, VTY_NEWLINE);
}

DEFUN(show_tun, show_tun_cmd,
	"show tun-device [IFNAME]",
	SHOW_STR TUN_STR
	"Name of TUN network device\n")
{
	struct tun_device *tun;

	show_tun_hdr(vty);
	pthread_rwlock_rdlock(&g_daemon->rwlock);
	if (argc) {
		tun = _tun_device_find(g_daemon, argv[0]);
		if (!tun) {
			pthread_rwlock_unlock(&g_daemon->rwlock);
			vty_out(vty, "Cannot find TUN device '%s'%s", argv[0], VTY_NEWLINE);
			return CMD_WARNING;
		}
		show_one_tun(vty, tun);
	} else {
		llist_for_each_entry(tun, &g_daemon->tun_devices, list)
			show_one_tun(vty, tun);
	}
	pthread_rwlock_unlock(&g_daemon->rwlock);

	return CMD_SUCCESS;
}

DEFUN(tun_create, tun_create_cmd,
	"tun-device create IFNAME [NETNS]",
	TUN_STR "Create a new TUN interface\n"
	"Name of TUN network device\n"
	"Name of network namespace for tun device\n"
	)
{
	struct tun_device *tun;
	const char *ifname = argv[0];
	const char *netns_name = NULL;

	if (argc > 1)
		netns_name = argv[1];

	tun = tun_device_find_or_create(g_daemon, ifname, netns_name);
	if (!tun) {
		vty_out(vty, "Error creating TUN%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN(tun_destroy, tun_destroy_cmd,
	"tun-device destroy IFNAME",
	TUN_STR "Destroy a TUN interface\n"
	"Name of TUN network device\n"
	)
{
	struct tun_device *tun;
	const char *ifname = argv[0];

	pthread_rwlock_wrlock(&g_daemon->rwlock);
	tun = _tun_device_find(g_daemon, ifname);
	if (!tun) {
		pthread_rwlock_unlock(&g_daemon->rwlock);
		vty_out(vty, "Cannot destrory non-existant TUN%s", VTY_NEWLINE);
		return CMD_WARNING;
	}
	_tun_device_deref_destroy(tun);
	pthread_rwlock_unlock(&g_daemon->rwlock);

	return CMD_SUCCESS;
}


static void show_ep_hdr(struct vty *vty)
{
	vty_out(vty,
		"                    address port | use count%s", VTY_NEWLINE);
	vty_out(vty,
		" ------------------------------- | ---------%s", VTY_NEWLINE);
}

static void show_one_ep(struct vty *vty, const struct gtp_endpoint *ep)
{
	vty_out(vty, "%32s | %lu%s",
		ep->name, ep->use_count, VTY_NEWLINE);

}

DEFUN(show_gtp, show_gtp_cmd,
	"show gtp-endpoint [(A.B.C.D|X:X::X:X) [<0-65535>]]",
	SHOW_STR GTP_EP_STR
	"Local IP address\n" "Local UDP Port\n")
{
	struct gtp_endpoint *ep;
	struct addrinfo *ai = NULL;
	const char *ipstr;
	uint16_t port = GTP1U_PORT;

	if (argc > 0) {
		ipstr = argv[0];
		if (argc > 1)
			port = atoi(argv[1]);

		ai = addrinfo_helper(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipstr, port, true);
		if (!ai) {
			vty_out(vty, "Error parsing IP/Port%s", VTY_NEWLINE);
			return CMD_WARNING;
		}
	}

	show_ep_hdr(vty);
	pthread_rwlock_rdlock(&g_daemon->rwlock);
	if (argc) {
		ep = _gtp_endpoint_find(g_daemon, (const struct sockaddr_storage *) ai->ai_addr);
		if (!ep) {
			pthread_rwlock_unlock(&g_daemon->rwlock);
			vty_out(vty, "Cannot find GTP endpoint %s:%s%s", argv[0], argv[1], VTY_NEWLINE);
			freeaddrinfo(ai);
			return CMD_WARNING;
		}
		show_one_ep(vty, ep);
	} else {
		llist_for_each_entry(ep, &g_daemon->gtp_endpoints, list)
			show_one_ep(vty, ep);
	}
	pthread_rwlock_unlock(&g_daemon->rwlock);

	freeaddrinfo(ai);
	return CMD_SUCCESS;
}

DEFUN(gtp_create, gtp_create_cmd,
	"gtp-endpoint create (A.B.C.D|X:X::X:X) [<0-65535>]",
	GTP_EP_STR "Create a new GTP endpoint (UDP socket)\n"
	"Local IP address\n" "Local UDP Port\n")
{
	struct addrinfo *ai;
	struct gtp_endpoint *ep;
	const char *ipstr = argv[0];
	uint16_t port = GTP1U_PORT;

	if (argc > 1)
		port = atoi(argv[1]);

	ai = addrinfo_helper(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipstr, port, true);
	if (!ai) {
		vty_out(vty, "Error parsing IP/Port%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	ep = gtp_endpoint_find_or_create(g_daemon, (struct sockaddr_storage *) ai->ai_addr);
	if (!ep) {
		vty_out(vty, "Error creating endpoint%s", VTY_NEWLINE);
		freeaddrinfo(ai);
		return CMD_WARNING;
	}

	freeaddrinfo(ai);
	return CMD_SUCCESS;
}

DEFUN(gtp_destroy, gtp_destroy_cmd,
	"gtp-endpoint destroy (A.B.C.D|X:X::X:X) [<0-65535>]",
	GTP_EP_STR "Destroy a GTP endpoint\n"
	"Local IP address\n" "Local UDP Port\n")
{
	struct addrinfo *ai;
	struct gtp_endpoint *ep;
	const char *ipstr = argv[0];
	uint16_t port = GTP1U_PORT;

	if (argc > 1)
		port = atoi(argv[1]);

	ai = addrinfo_helper(AF_UNSPEC, SOCK_DGRAM, IPPROTO_UDP, ipstr, port, true);
	if (!ai) {
		vty_out(vty, "Error parsing IP/Port%s", VTY_NEWLINE);
		return CMD_WARNING;
	}

	pthread_rwlock_wrlock(&g_daemon->rwlock);
	ep = _gtp_endpoint_find(g_daemon, (struct sockaddr_storage *) ai->ai_addr);
	if (!ep) {
		pthread_rwlock_unlock(&g_daemon->rwlock);
		vty_out(vty, "Cannot find to-be-destoryed endpoint%s", VTY_NEWLINE);
		freeaddrinfo(ai);
		return CMD_WARNING;
	}
	_gtp_endpoint_deref_destroy(ep);
	pthread_rwlock_unlock(&g_daemon->rwlock);

	freeaddrinfo(ai);
	return CMD_SUCCESS;
}

static void show_one_tunnel(struct vty *vty, const struct gtp_tunnel *t)
{
	char remote_ip[64], remote_port[16], user_addr[64];

	getnameinfo((struct sockaddr *) &t->remote_udp, sizeof(t->remote_udp),
		    remote_ip, sizeof(remote_ip), remote_port, sizeof(remote_port),
		    NI_NUMERICHOST|NI_NUMERICSERV);

	getnameinfo((struct sockaddr *) &t->user_addr, sizeof(t->user_addr),
		    user_addr, sizeof(user_addr), NULL, 0,
		    NI_NUMERICHOST|NI_NUMERICSERV);


	vty_out(vty, "%s/%08X - %s:%s/%08X %s(%s) %s%s",
		t->gtp_ep->name, t->rx_teid, remote_ip, remote_port, t->tx_teid,
		t->tun_dev->devname, t->tun_dev->netns_name, user_addr, VTY_NEWLINE);
}

DEFUN(show_tunnel, show_tunnel_cmd,
	"show gtp-tunnel",
	SHOW_STR TUNNEL_STR)
{
	struct gtp_tunnel *t;

	pthread_rwlock_rdlock(&g_daemon->rwlock);
	llist_for_each_entry(t, &g_daemon->gtp_tunnels, list) {
		show_one_tunnel(vty, t);
	}
	pthread_rwlock_unlock(&g_daemon->rwlock);
	return CMD_SUCCESS;
}


int gtpud_vty_init(void)
{
	install_element_ve(&show_tun_cmd);
	install_element(ENABLE_NODE, &tun_create_cmd);
	install_element(ENABLE_NODE, &tun_destroy_cmd);

	install_element_ve(&show_gtp_cmd);
	install_element(ENABLE_NODE, &gtp_create_cmd);
	install_element(ENABLE_NODE, &gtp_destroy_cmd);

	install_element_ve(&show_tunnel_cmd);

	return 0;
}


static const char copyright[] =
	"Copyright (C) 2020 Harald Welte <laforge@gnumonks.org>\r\n"
	"License GPLv2: GNU GPL version 2 <http://gnu.org/licenses/gpl-2.0.html>\r\n"
	"This is free software: you are free to change and redistribute it.\r\n"
	"There is NO WARRANTY, to the extent permitted by law.\r\n";

struct vty_app_info g_vty_info = {
	.name		= "osmo-gtpud",
	.version	= PACKAGE_VERSION,
	.copyright	= copyright,
};
