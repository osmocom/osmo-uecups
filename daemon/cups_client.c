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
#include <osmocom/core/exec.h>

#include "internal.h"
#include "gtp.h"

#include <netinet/sctp.h>

/***********************************************************************
 * Client (Control/User Plane Separation) Socket
 ***********************************************************************/

#define CUPS_MSGB_SIZE	1024

#define LOGCC(cc, lvl, fmt, args ...)	\
	LOGP(DUECUPS, lvl, "%s: " fmt, (cc)->sockname, ## args)

struct subprocess {
	/* member in daemon->cups_clients */
	struct llist_head list;
	/* pointer to the client that started us */
	struct cups_client *cups_client;
	/* PID of the process */
	pid_t pid;
};

static json_t *gen_uecups_term_ind(pid_t pid, int status);

/* kill the specified subprocess and forget about it */
static void subprocess_destroy(struct subprocess *p, int signal)
{
	LOGCC(p->cups_client, LOGL_DEBUG, "Kill subprocess pid %llu with signal %u\n",
		  (unsigned long long)p->pid, signal);
	kill(p->pid, signal);
	llist_del(&p->list);
	talloc_free(p);
}

static struct subprocess *subprocess_by_pid(struct gtp_daemon *d, pid_t pid)
{
	struct subprocess *sproc;
	llist_for_each_entry(sproc, &d->subprocesses, list) {
		if (sproc->pid == pid)
			return sproc;
	}
	return NULL;
}

void child_terminated(struct gtp_daemon *d, int pid, int status)
{
	struct subprocess *sproc;
	json_t *jterm_ind;

	LOGP(DUECUPS, LOGL_DEBUG, "SIGCHLD receive from pid %u; status=%d\n", pid, status);

	sproc = subprocess_by_pid(d, pid);
	if (!sproc) {
		LOGP(DUECUPS, LOGL_NOTICE, "subprocess %u terminated (status=%d) but we don't know it?\n",
			pid, status);
		return;
	}

	/* generate prog_term_ind towards control plane */
	jterm_ind = gen_uecups_term_ind(pid, status);
	if (!jterm_ind)
		return;

	cups_client_tx_json(sproc->cups_client, jterm_ind);

	llist_del(&sproc->list);
	talloc_free(sproc);
}

/* Send JSON to a given client/connection */
int cups_client_tx_json(struct cups_client *cc, json_t *jtx)
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

json_t *gen_uecups_result(const char *name, const char *res)
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

static int parse_ext_hdr_pdu_session_container(struct gtp1u_exthdr_pdu_sess_container *out, json_t *jpdu_sess_cont)
{
	json_t *jpdu_type, *jqfi;
	const char *str_pdu_type;

	if (!json_is_object(jpdu_sess_cont))
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	out->enabled = true;

	jpdu_type = json_object_get(jpdu_sess_cont, "pdu_type");
	if (!json_is_string(jpdu_type))
		return -EINVAL;
	str_pdu_type = json_string_value(jpdu_type);
	if (!strcmp(str_pdu_type, "ul_pdu_sess_info"))
		out->pdu_type = GTP1_EXTHDR_PDU_TYPE_UL_PDU_SESSION_INFORMATION;
	else if (!strcmp(str_pdu_type, "dl_pdu_sess_info"))
		out->pdu_type = GTP1_EXTHDR_PDU_TYPE_DL_PDU_SESSION_INFORMATION;
	else
		return -EINVAL;

	jqfi = json_object_get(jpdu_sess_cont, "qfi");
	if (!json_is_integer(jqfi))
		return -EINVAL;
	out->qos_flow_identifier = json_number_value(jqfi);

	return 0;
}
static int parse_ext_hdr(struct gtp1u_exthdrs *out, json_t *jexthdr)
{
	json_t *jseq_num, *jn_pdu_num, *jpdu_sess_cont;
	int rc = 0;

	if (!json_is_object(jexthdr))
		return -EINVAL;

	jseq_num = json_object_get(jexthdr, "sequence_number");
	if (jseq_num)
		out->seq_num_enabled = true;

	jn_pdu_num = json_object_get(jexthdr, "n_pdu_number");
	if (jn_pdu_num)
		out->n_pdu_num_enabled = true;

	jpdu_sess_cont = json_object_get(jexthdr, "pdu_session_container");
	if (jpdu_sess_cont)
		rc = parse_ext_hdr_pdu_session_container(&out->pdu_sess_container, jpdu_sess_cont);

	return rc;
}

static int parse_create_tun(struct gtp_tunnel_params *out, json_t *ctun)
{
	json_t *jlocal_gtp_ep, *jremote_gtp_ep;
	json_t *jrx_teid, *jtx_teid;
	json_t *jtun_dev_name, *jtun_netns_name;
	json_t *juser_addr, *juser_addr_type;
	json_t *jgtp_ext_hdr;
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

	jgtp_ext_hdr = json_object_get(ctun, "gtp_ext_hdr");
	if (jgtp_ext_hdr) {
		rc = parse_ext_hdr(&out->exthdr, jgtp_ext_hdr);
		if (rc < 0)
			return rc;
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

static json_t *gen_uecups_term_ind(pid_t pid, int status)
{
	json_t *jterm = json_object();
	json_t *jret = json_object();

	json_object_set_new(jterm, "pid", json_integer(pid));
	json_object_set_new(jterm, "exit_code", json_integer(status));

	json_object_set_new(jret, "program_term_ind", jterm);

	return jret;
}

static json_t *gen_uecups_start_res(pid_t pid, const char *result)
{
	json_t *ret = gen_uecups_result("start_program_res", result);
	json_object_set_new(json_object_get(ret, "start_program_res"), "pid", json_integer(pid));

	return ret;
}

static int cups_client_handle_start_program(struct cups_client *cc, json_t *sprog)
{
	json_t *juser, *jcmd, *jenv, *jnetns, *jres;
	struct gtp_daemon *d = cc->d;
	const char *cmd, *user;
	char **addl_env = NULL;
	sigset_t oldmask;
	int nsfd = -1, rc;

	juser = json_object_get(sprog, "run_as_user");
	jcmd = json_object_get(sprog, "command");
	jenv = json_object_get(sprog, "environment");
	jnetns = json_object_get(sprog, "tun_netns_name");

	/* mandatory parts */
	if (!juser || !jcmd)
		return -EINVAL;
	if (!json_is_string(juser) || !json_is_string(jcmd))
		return -EINVAL;

	/* optional parts */
	if (jenv && !json_is_array(jenv))
		return -EINVAL;
	if (jnetns && !json_is_string(jnetns))
		return -EINVAL;

	cmd = json_string_value(jcmd);
	user = json_string_value(juser);
	if (jnetns) {
		struct tun_device *tun = tun_device_find_netns(d, json_string_value(jnetns));
		if (!tun)
			return -ENODEV;
		nsfd = tun->netns_fd;
	}

	/* build environment */
	if (jenv) {
		json_t *j;
		int i;
		addl_env = talloc_zero_array(cc, char *, json_array_size(jenv)+1);
		if (!addl_env)
			return -ENOMEM;
		json_array_foreach(jenv, i, j) {
			addl_env[i] = talloc_strdup(addl_env, json_string_value(j));
		}
	}

	if (jnetns) {
		rc = switch_ns(nsfd, &oldmask);
		if (rc < 0) {
			talloc_free(addl_env);
			return -EIO;
		}
	}

	rc = osmo_system_nowait2(cmd, osmo_environment_whitelist, addl_env, user);

	if (jnetns) {
		OSMO_ASSERT(restore_ns(&oldmask) == 0);
	}

	talloc_free(addl_env);

	if (rc > 0) {
		/* create a record about the subprocess we started, so we can notify the
		 * client that crated it upon termination */
		struct subprocess *sproc = talloc_zero(cc, struct subprocess);
		if (!sproc)
			return -ENOMEM;

		sproc->cups_client = cc;
		sproc->pid = rc;
		llist_add_tail(&sproc->list, &d->subprocesses);
		jres = gen_uecups_start_res(sproc->pid, "OK");
	} else {
		jres = gen_uecups_start_res(0, "ERR_INVALID_DATA");
	}

	cups_client_tx_json(cc, jres);

	return 0;
}

static int cups_client_handle_reset_all_state(struct cups_client *cc, json_t *sprog)
{
	struct gtp_daemon *d = cc->d;
	struct gtp_tunnel *t, *t2;
	struct subprocess *p, *p2;
	json_t *jres;

	LOGCC(cc, LOGL_DEBUG, "Destroying all tunnels\n");
	pthread_rwlock_wrlock(&d->rwlock);
	llist_for_each_entry_safe(t, t2, &d->gtp_tunnels, list) {
		_gtp_tunnel_destroy(t);
	}
	pthread_rwlock_unlock(&d->rwlock);

	/* no locking needed as this list is only used by main thread */
	LOGCC(cc, LOGL_DEBUG, "Destroying all subprocesses\n");
	llist_for_each_entry_safe(p, p2, &d->subprocesses, list) {
		subprocess_destroy(p, SIGKILL);
	}

	if (d->reset_all_state_tun_remaining == 0) {
		jres = gen_uecups_result("reset_all_state_res", "OK");
		cups_client_tx_json(cc, jres);
	} else {
		cc->reset_all_state_res_pending = true;
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
	} else if (!strcmp(key, "start_program")) {
		rc = cups_client_handle_start_program(cc, cmd);
	} else if (!strcmp(key, "reset_all_state")) {
		rc = cups_client_handle_reset_all_state(cc, cmd);
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
	rc = sctp_recvmsg(ofd->fd, msg->tail, msgb_tailroom(msg), NULL, NULL, &sinfo, &flags);
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
	struct gtp_daemon *d = cc->d;
	struct subprocess *p, *p2;

	/* kill + forget about all subprocesses of this client */
	/* We need no locking here as the subprocess list is only used from the main thread */
	llist_for_each_entry_safe(p, p2, &d->subprocesses, list) {
		if (p->cups_client == cc)
			subprocess_destroy(p, SIGKILL);
	}

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

	cc->d = d;
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

struct osmo_stream_srv_link *cups_srv_link_create(struct gtp_daemon *d)
{
	struct osmo_stream_srv_link *srv_link;
	srv_link = osmo_stream_srv_link_create(g_daemon);
	if (!srv_link)
		return NULL;

	/* UECUPS socket for control from control plane side */
	osmo_stream_srv_link_set_nodelay(srv_link, true);
	osmo_stream_srv_link_set_addr(srv_link, g_daemon->cfg.cups_local_ip);
	osmo_stream_srv_link_set_port(srv_link, g_daemon->cfg.cups_local_port);
	osmo_stream_srv_link_set_proto(srv_link, IPPROTO_SCTP);
	osmo_stream_srv_link_set_data(srv_link, g_daemon);
	osmo_stream_srv_link_set_accept_cb(srv_link, cups_accept_cb);
	osmo_stream_srv_link_open(srv_link);
	return srv_link;
}
