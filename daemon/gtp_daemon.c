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


/***********************************************************************
 * GTP Daemon
 ***********************************************************************/

#ifndef OSMO_VTY_PORT_UECUPS
#define OSMO_VTY_PORT_UECUPS	4268
#endif

struct gtp_daemon *g_daemon;

static void gtp_daemon_itq_read_cb(struct osmo_it_q *q, struct llist_head *item)
{
	struct gtp_daemon *d = (struct gtp_daemon *)q->data;
	struct gtp_daemon_itq_msg *itq_msg = container_of(item, struct gtp_daemon_itq_msg, list);

	LOGP(DTUN, LOGL_DEBUG, "Rx new itq message from %s\n",
		 itq_msg->tun_released.tun->devname);

	_tun_device_destroy(itq_msg->tun_released.tun);
	if (d->reset_all_state_tun_remaining > 0) {
		d->reset_all_state_tun_remaining--;
		if (d->reset_all_state_tun_remaining == 0) {
			struct cups_client *cc;
			llist_for_each_entry(cc, &d->cups_clients, list) {
				json_t *jres;
				if (!cc->reset_all_state_res_pending)
					continue;
				cc->reset_all_state_res_pending = false;
				jres = gen_uecups_result("reset_all_state_res", "OK");
				cups_client_tx_json(cc, jres);
			}
		}
	}
}

struct gtp_daemon *gtp_daemon_alloc(void *ctx)
{
	int rc;
	struct gtp_daemon *d = talloc_zero(ctx, struct gtp_daemon);
	if (!d)
		return NULL;

	INIT_LLIST_HEAD(&d->gtp_endpoints);
	INIT_LLIST_HEAD(&d->tun_devices);
	INIT_LLIST_HEAD(&d->gtp_tunnels);
	INIT_LLIST_HEAD(&d->subprocesses);
	pthread_rwlock_init(&d->rwlock, NULL);
	d->main_thread = pthread_self();

	d->itq = osmo_it_q_alloc(d, "itq", 4096, gtp_daemon_itq_read_cb, d);
	if (!d->itq)
		goto out_free;

	rc = osmo_fd_register(&d->itq->event_ofd);
	if (rc < 0)
		goto out_free_q;

	INIT_LLIST_HEAD(&d->cups_clients);

	d->cfg.cups_local_ip = talloc_strdup(d, "localhost");
	d->cfg.cups_local_port = UECUPS_SCTP_PORT;

	return d;

out_free_q:
	osmo_it_q_destroy(d->itq);
out_free:
	talloc_free(d);
	return NULL;
}
