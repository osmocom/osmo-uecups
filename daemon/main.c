/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#include <pthread.h>

#include <osmocom/core/linuxlist.h>
#include <osmocom/core/talloc.h>
#include <osmocom/core/select.h>
#include <osmocom/core/application.h>
#include <osmocom/core/logging.h>
#include <osmocom/core/stats.h>
#include <osmocom/core/rate_ctr.h>
#include <osmocom/core/socket.h>
#include <osmocom/vty/telnet_interface.h>
#include <osmocom/vty/logging.h>
#include <osmocom/vty/stats.h>
#include <osmocom/vty/ports.h>
#include <osmocom/vty/command.h>
#include <osmocom/vty/misc.h>

#include <osmocom/netif/stream.h>
#include <netinet/sctp.h>

#include <jansson.h>

#include "internal.h"
#include "netns.h"
#include "gtp.h"

/***********************************************************************
 * Client (Contol/User Plane Separation) Socket
 ***********************************************************************/

#define CUPS_MSGB_SIZE	1024

#define LOGCC(cc, lvl, fmt, args ...)	\
	LOGP(DUECUPS, lvl, "%s: " fmt, (cc)->sockname, ## args)

struct cups_client {
	/* member in daemon->cups_clients */
	struct llist_head list;
	/* back-pointer to daemon */
	struct gtp_daemon *d;
	/* client socket */
	struct osmo_stream_srv *srv;
	char sockname[OSMO_SOCK_NAME_MAXLEN];
};

/* Send JSON to a given client/connection */
static int cups_client_tx_json(struct cups_client *cc, json_t *jtx)
{
	struct msgb *msg = msgb_alloc(CUPS_MSGB_SIZE, "Tx JSON");
	char *json_str = json_dumps(jtx, JSON_SORT_KEYS);
	char *out;
	int json_strlen;

	json_decref(jtx);
	if (!json_str) {
		LOGCC(cc, LOGL_ERROR, "Error encoding JSON\n");
		return 0;
	}
	json_strlen = strlen(json_str);

	LOGCC(cc, LOGL_DEBUG, "JSON Tx '%s'\n", json_str);

	if (json_strlen > msgb_tailroom(msg)) {
		LOGCC(cc, LOGL_ERROR, "Not enough room for JSON in msgb\n");
		free(json_str);
		return 0;
	}

	out = (char *)msgb_put(msg, json_strlen);
	memcpy(out, json_str, json_strlen);
	free(json_str);
	osmo_stream_srv_send(cc->srv, msg);

	return 0;
}

static json_t *gen_uecups_result(const char *name, const char *res)
{
	json_t *jres = json_object();
	json_t *jret = json_object();

	json_object_set_new(jres, "result", json_string(res));
	json_object_set_new(jret, name, jres);

	return jret;
}

static int parse_ep(struct sockaddr_storage *out, json_t *in)
{
	json_t *jaddr_type, *jport, *jip;
	const char *addr_type, *ip;
	uint8_t buf[16];

	/* {"addr_type":"IPV4","ip":"31323334","Port":2152} */

	if (!json_is_object(in))
		return -EINVAL;

	jaddr_type = json_object_get(in, "addr_type");
	jport = json_object_get(in, "Port");
	jip = json_object_get(in, "ip");

	if (!jaddr_type || !jport || !jip)
		return -EINVAL;

	if (!json_is_string(jaddr_type) || !json_is_integer(jport) || !json_is_string(jip))
		return -EINVAL;

	addr_type = json_string_value(jaddr_type);
	ip = json_string_value(jip);

	memset(out, 0, sizeof(*out));

	if (!strcmp(addr_type, "IPV4")) {
		struct sockaddr_in *sin = (struct sockaddr_in *) out;
		if (osmo_hexparse(ip, buf, sizeof(buf)) != 4)
			return -EINVAL;
		memcpy(&sin->sin_addr, buf, 4);
		sin->sin_family = AF_INET;
		sin->sin_port = htons(json_integer_value(jport));
	} else if (!strcmp(addr_type, "IPV6")) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) out;
		if (osmo_hexparse(ip, buf, sizeof(buf)) != 16)
			return -EINVAL;
		memcpy(&sin6->sin6_addr, buf, 16);
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = htons(json_integer_value(jport));
	} else
		return -EINVAL;

	return 0;
}

static int parse_eua(struct sockaddr_storage *out, json_t *jip, json_t *jaddr_type)
{
	const char *addr_type, *ip;
	uint8_t buf[16];

	if (!json_is_string(jip) || !json_is_string(jaddr_type))
		return -EINVAL;

	addr_type = json_string_value(jaddr_type);
	ip = json_string_value(jip);

	memset(out, 0, sizeof(*out));

	if (!strcmp(addr_type, "IPV4")) {
		struct sockaddr_in *sin = (struct sockaddr_in *) out;
		if (osmo_hexparse(ip, buf, sizeof(buf)) != 4)
			return -EINVAL;
		memcpy(&sin->sin_addr, buf, 4);
		sin->sin_family = AF_INET;
	} else if (!strcmp(addr_type, "IPV6")) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) out;
		if (osmo_hexparse(ip, buf, sizeof(buf)) != 16)
			return -EINVAL;
		memcpy(&sin6->sin6_addr, buf, 16);
		sin6->sin6_family = AF_INET6;
	} else
		return -EINVAL;

	return 0;
}


static int parse_create_tun(struct gtp_tunnel_params *out, json_t *ctun)
{
	json_t *jlocal_gtp_ep, *jremote_gtp_ep;
	json_t *jrx_teid, *jtx_teid;
	json_t *jtun_dev_name, *jtun_netns_name;
	json_t *juser_addr, *juser_addr_type;
	int rc;

	/* '{"create_tun":{"tx_teid":1234,"rx_teid":5678,"user_addr_type":"IPV4","user_addr":"21222324","local_gtp_ep":{"addr_type":"IPV4","ip":"31323334","Port":2152},"remote_gtp_ep":{"addr_type":"IPV4","ip":"41424344","Port":2152},"tun_dev_name":"tun23","tun_netns_name":"foo"}}' */

	if (!json_is_object(ctun))
		return -EINVAL;

	/* mandatory IEs */
	jlocal_gtp_ep = json_object_get(ctun, "local_gtp_ep");
	jremote_gtp_ep = json_object_get(ctun, "remote_gtp_ep");
	jrx_teid = json_object_get(ctun, "rx_teid");
	jtx_teid = json_object_get(ctun, "tx_teid");
	jtun_dev_name = json_object_get(ctun, "tun_dev_name");
	juser_addr = json_object_get(ctun, "user_addr");
	juser_addr_type = json_object_get(ctun, "user_addr_type");

	if (!jlocal_gtp_ep || !jremote_gtp_ep || !jrx_teid || !jtx_teid || !jtun_dev_name ||
	    !juser_addr || !juser_addr_type)
		return -EINVAL;
	if (!json_is_object(jlocal_gtp_ep) || !json_is_object(jremote_gtp_ep) ||
	    !json_is_integer(jrx_teid) || !json_is_integer(jtx_teid) ||
	    !json_is_string(jtun_dev_name) ||
	    !json_is_string(juser_addr) || !json_is_string(juser_addr_type))
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	rc = parse_ep(&out->local_udp, jlocal_gtp_ep);
	if (rc < 0)
		return rc;
	rc = parse_ep(&out->remote_udp, jremote_gtp_ep);
	if (rc < 0)
		return rc;
	rc = parse_eua(&out->user_addr, juser_addr, juser_addr_type);
	if (rc < 0)
		return rc;
	out->rx_teid = json_integer_value(jrx_teid);
	out->tx_teid = json_integer_value(jtx_teid);
	out->tun_name = talloc_strdup(out, json_string_value(jtun_dev_name));

	/* optional IEs */
	jtun_netns_name = json_object_get(ctun, "tun_netns_name");
	if (jtun_netns_name) {
		if (!json_is_string(jtun_netns_name))
			return -EINVAL;
		out->tun_netns_name = talloc_strdup(out, json_string_value(jtun_netns_name));
	}

	return 0;
}


static int cups_client_handle_create_tun(struct cups_client *cc, json_t *ctun)
{
	int rc;
	struct gtp_tunnel_params *tpars = talloc_zero(cc, struct gtp_tunnel_params);
	struct gtp_tunnel *t;

	rc = parse_create_tun(tpars, ctun);
	if (rc < 0) {
		talloc_free(tpars);
		return rc;
	}

	t = gtp_tunnel_alloc(g_daemon, tpars);
	if (!t) {
		LOGCC(cc, LOGL_NOTICE, "Failed to allocate tunnel\n");
		cups_client_tx_json(cc, gen_uecups_result("create_tun_res", "ERR_NOT_FOUND"));
	} else {
		cups_client_tx_json(cc, gen_uecups_result("create_tun_res", "OK"));
	}

	talloc_free(tpars);
	return 0;
}

static int cups_client_handle_destroy_tun(struct cups_client *cc, json_t *dtun)
{
	struct sockaddr_storage local_ep_addr;
	json_t *jlocal_gtp_ep, *jrx_teid;
	uint32_t rx_teid;
	int rc;

	jlocal_gtp_ep = json_object_get(dtun, "local_gtp_ep");
	jrx_teid = json_object_get(dtun, "rx_teid");

	if (!jlocal_gtp_ep || !jrx_teid)
		return -EINVAL;

	if (!json_is_object(jlocal_gtp_ep) || !json_is_integer(jrx_teid))
		return -EINVAL;

	rc = parse_ep(&local_ep_addr, jlocal_gtp_ep);
	if (rc < 0)
		return rc;
	rx_teid = json_integer_value(jrx_teid);

	rc = gtp_tunnel_destroy(g_daemon, &local_ep_addr, rx_teid);
	if (rc < 0) {
		LOGCC(cc, LOGL_NOTICE, "Failed to destroy tunnel\n");
		cups_client_tx_json(cc, gen_uecups_result("destroy_tun_res", "ERR_NOT_FOUND"));
	} else {
		cups_client_tx_json(cc, gen_uecups_result("destroy_tun_res", "OK"));
	}

	return 0;
}

static int cups_client_handle_json(struct cups_client *cc, json_t *jroot)
{
	void *iter;
	const char *key;
	json_t *cmd;
	int rc;

	if (!json_is_object(jroot))
		return -EINVAL;

	iter = json_object_iter(jroot);
	key = json_object_iter_key(iter);
	cmd = json_object_iter_value(iter);
	if (!iter || !key || !cmd)
		return -EINVAL;

	if (!strcmp(key, "create_tun")) {
		rc = cups_client_handle_create_tun(cc, cmd);
	} else if (!strcmp(key, "destroy_tun")) {
		rc = cups_client_handle_destroy_tun(cc, cmd);
	} else {
		LOGCC(cc, LOGL_NOTICE, "Unknown command '%s' received\n", key);
		return -EINVAL;
	}

	if (rc < 0) {
		LOGCC(cc, LOGL_NOTICE, "Error %d handling '%s' command\n", rc, key);
		char buf[64];
		snprintf(buf, sizeof(buf), "%s_res", key);
		cups_client_tx_json(cc, gen_uecups_result(buf, "ERR_INVALID_DATA"));
		return -EINVAL;
	}

	return 0;
}

/* control/user plane separation per-client read cb */
static int cups_client_read_cb(struct osmo_stream_srv *conn)
{
	struct osmo_fd *ofd = osmo_stream_srv_get_ofd(conn);
	struct cups_client *cc = osmo_stream_srv_get_data(conn);
	struct msgb *msg = msgb_alloc(CUPS_MSGB_SIZE, "Rx JSON");
	struct sctp_sndrcvinfo sinfo;
	json_error_t jerr;
	json_t *jroot;
	int flags = 0;
	int rc = 0;

	/* Read message from socket */
	/* we cannot use osmo_stream_srv_recv() here, as we might get some out-of-band info from
	 * SCTP. FIXME: add something like osmo_stream_srv_recv_sctp() to libosmo-netif and use
	 * it here as well as in libosmo-sigtran and osmo-msc */
	rc = sctp_recvmsg(ofd->fd, msg->tail, msgb_tailroom(msg), NULL, NULL, &sinfo,&flags);
	if (rc <= 0) {
		osmo_stream_srv_destroy(conn);
		rc = -1;
		goto out;
	} else
		msgb_put(msg, rc);

	if (flags & MSG_NOTIFICATION) {
		union sctp_notification *notif = (union sctp_notification *) msgb_data(msg);
		switch (notif->sn_header.sn_type) {
		case SCTP_SHUTDOWN_EVENT:
			osmo_stream_srv_destroy(conn);
			rc = -EBADF;
			goto out;
		default:
			break;
		}
		goto out;
	}

	LOGCC(cc, LOGL_DEBUG, "Rx '%s'\n", msgb_data(msg));

	/* Parse the JSON */
	jroot = json_loadb((const char *) msgb_data(msg), msgb_length(msg), 0, &jerr);
	if (!jroot) {
		LOGCC(cc, LOGL_ERROR, "Error decoding JSON (%s)", jerr.text);
		rc = -1;
		goto out;
	}

	/* Dispatch */
	rc = cups_client_handle_json(cc, jroot);

	json_decref(jroot);
	msgb_free(msg);

	return 0;
out:
	msgb_free(msg);
	return rc;
}

static int cups_client_closed_cb(struct osmo_stream_srv *conn)
{
	struct cups_client *cc = osmo_stream_srv_get_data(conn);

	LOGCC(cc, LOGL_INFO, "UECUPS connection lost\n");
	llist_del(&cc->list);
	return 0;
}


/* the control/user plane separation server bind/accept fd */
static int cups_accept_cb(struct osmo_stream_srv_link *link, int fd)
{
	struct gtp_daemon *d = osmo_stream_srv_link_get_data(link);
	struct cups_client *cc;

	cc = talloc_zero(d, struct cups_client);
	if (!cc)
		return -1;

	osmo_sock_get_name_buf(cc->sockname, sizeof(cc->sockname), fd);
	cc->srv = osmo_stream_srv_create(cc, link, fd, cups_client_read_cb, cups_client_closed_cb, cc);
	if (!cc->srv) {
		talloc_free(cc);
		return -1;
	}
	LOGCC(cc, LOGL_INFO, "Accepted new UECUPS connection\n");

	llist_add_tail(&cc->list, &d->cups_clients);

	return 0;
}

/***********************************************************************
 * GTP Daemon
 ***********************************************************************/

#ifndef OSMO_VTY_PORT_UECUPS
#define OSMO_VTY_PORT_UECUPS	4268
#endif

struct gtp_daemon *g_daemon;
static int g_daemonize;
static char *g_config_file = "osmo-gtpu-daemon.cfg";
extern struct vty_app_info g_vty_info;

static struct gtp_daemon *gtp_daemon_alloc(void *ctx)
{
	struct gtp_daemon *d = talloc_zero(ctx, struct gtp_daemon);
	if (!d)
		return NULL;

	INIT_LLIST_HEAD(&d->gtp_endpoints);
	INIT_LLIST_HEAD(&d->tun_devices);
	INIT_LLIST_HEAD(&d->gtp_tunnels);
	pthread_rwlock_init(&d->rwlock, NULL);
	d->main_thread = pthread_self();

	INIT_LLIST_HEAD(&d->cups_clients);

	d->cfg.cups_local_ip = talloc_strdup(d, "localhost");
	d->cfg.cups_local_port = UECUPS_SCTP_PORT;

	return d;
}

static const struct log_info_cat log_categories[] = {
	[DTUN] = {
		.name ="DTUN",
		.description = "Tunnel interface (tun device)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DEP] = {
		.name = "DEP",
		.description = "GTP endpoint (UDP socket)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DGT] = {
		.name = "DGT",
		.description = "GTP tunnel (session)",
		.enabled = 1, .loglevel = LOGL_INFO,
	},
	[DUECUPS] = {
		.name = "DUECUPS",
		.description = "UE Control User Plane Separation",
		.enabled = 1, .loglevel = LOGL_DEBUG,
	},

};

static const struct log_info log_info = {
	.cat = log_categories,
	.num_cat = ARRAY_SIZE(log_categories),
};

int main(int argc, char **argv)
{
	void *ctx = talloc_named_const(NULL, 0, "root");
	int rc;

	g_vty_info.tall_ctx = ctx;

	osmo_init_ignore_signals();
	osmo_init_logging2(ctx,  &log_info);

	g_daemon = gtp_daemon_alloc(ctx);
	OSMO_ASSERT(g_daemon);

	osmo_stats_init(ctx);
	vty_init(&g_vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	rate_ctr_init(ctx);
	gtpud_vty_init();

	init_netns();

	rc = vty_read_config_file(g_config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to open config file: '%s'\n", g_config_file);
		exit(2);
	}

	rc = telnet_init_dynif(ctx, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_UECUPS);
	if (rc < 0)
		exit(1);

	g_daemon->cups_link = osmo_stream_srv_link_create(g_daemon);
	if (!g_daemon->cups_link) {
		fprintf(stderr, "Failed to create CUPS socket %s:%u (%s)\n",
			g_daemon->cfg.cups_local_ip, g_daemon->cfg.cups_local_port, strerror(errno));
		exit(1);
	}

	/* UECUPS socket for control from control plane side */
	osmo_stream_srv_link_set_nodelay(g_daemon->cups_link, true);
	osmo_stream_srv_link_set_addr(g_daemon->cups_link, g_daemon->cfg.cups_local_ip);
	osmo_stream_srv_link_set_port(g_daemon->cups_link, g_daemon->cfg.cups_local_port);
	osmo_stream_srv_link_set_proto(g_daemon->cups_link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(g_daemon->cups_link, g_daemon);
	osmo_stream_srv_link_set_accept_cb(g_daemon->cups_link, cups_accept_cb);
	osmo_stream_srv_link_open(g_daemon->cups_link);

	if (g_daemonize) {
		rc = osmo_daemonize();
		if (rc < 0) {
			perror("Error during daemonize");
			exit(1);
		}
	}

	while (1) {
		osmo_select_main(0);
	}
}
