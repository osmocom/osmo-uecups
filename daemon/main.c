/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include <getopt.h>
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
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

#include <jansson.h>

#include "internal.h"
#include "netns.h"
#include "gtp.h"

static void *g_tall_ctx;
static char *g_config_file = "osmo-uecups-daemon.cfg";
static int g_daemonize;
extern struct vty_app_info g_vty_info;

#include <pwd.h>

static void sigchild_cb(struct osmo_signalfd *osfd, const struct signalfd_siginfo *fdsi)
{
	struct gtp_daemon *d = osfd->data;
	int pid, status;

	OSMO_ASSERT(fdsi->ssi_signo == SIGCHLD);

	/* it is known that classic signals coalesce: If you get multiple signals of the
	 * same type before a process is scheduled, the subsequent signals are dropped.  This
	 * makes sense for SIGINT or something like this, but for SIGCHLD carrying the PID of
	 * the terminated process, it doesn't really.  Linux had the chance to fix this when
	 * introducing signalfd() - but the developers decided not to fix it.  So the signalfd_siginfo
	 * contains the PID of one process that terminated - but there may be any number of other
	 * processes that also have terminated, and for which we don't get events this way. */

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0)
		child_terminated(d, pid, status);

}

static void signal_cb(struct osmo_signalfd *osfd, const struct signalfd_siginfo *fdsi)
{
	switch (fdsi->ssi_signo) {
	case SIGCHLD:
		sigchild_cb(osfd, fdsi);
		break;
	case SIGUSR1:
		talloc_report_full(g_tall_ctx, stderr);
		break;
	default:
		break;
	}
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

static void print_help()
{
	printf("Some useful options:\n");
	printf(" -h --help is printing this text.\n");
	printf(" -c --config-file filename The config file to use.\n");
	printf(" -s --disable-color\n");
	printf(" -D --daemonize Fork the process into a background daemon\n");
	printf(" -V --version Print the version number\n");

	printf("\nVTY reference generation:\n");
	printf("    --vty-ref-mode MODE		VTY reference generation mode (e.g. 'expert').\n");
	printf("    --vty-ref-xml		Generate the VTY reference XML output and exit.\n");
}

static void handle_long_options(const char *prog_name, const int long_option)
{
	static int vty_ref_mode = VTY_REF_GEN_MODE_DEFAULT;

	switch (long_option) {
	case 1:
		vty_ref_mode = get_string_value(vty_ref_gen_mode_names, optarg);
		if (vty_ref_mode < 0) {
			fprintf(stderr, "%s: Unknown VTY reference generation "
				"mode '%s'\n", prog_name, optarg);
			exit(2);
		}
		break;
	case 2:
		fprintf(stderr, "Generating the VTY reference in mode '%s' (%s)\n",
			get_value_string(vty_ref_gen_mode_names, vty_ref_mode),
			get_value_string(vty_ref_gen_mode_desc, vty_ref_mode));
		vty_dump_xml_ref_mode(stdout, (enum vty_ref_gen_mode) vty_ref_mode);
		exit(0);
	default:
		fprintf(stderr, "%s: error parsing cmdline options\n", prog_name);
		exit(2);
	}
}

static void handle_options(int argc, char **argv)
{
	while (1) {
		int option_index = 0, c;
		static int long_option = 0;
		static struct option long_options[] = {
			{"help", 0, 0, 'h'},
			{"config-file", 1, 0, 'c'},
			{"daemonize", 0, 0, 'D'},
			{"version", 0, 0, 'V'},
			{"disable-color", 0, 0, 's'},
			{"vty-ref-mode", 1, &long_option, 1},
			{"vty-ref-xml", 0, &long_option, 2},
			{0, 0, 0, 0},
		};

		c = getopt_long(argc, argv, "hc:sVD", long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {
		case 'h':
			print_help();
			exit(0);
			break;
		case 0:
			handle_long_options(argv[0], long_option);
			break;
		case 'c':
			g_config_file = talloc_strdup(g_tall_ctx, optarg);
			break;
		case 's':
			log_set_use_color(osmo_stderr_target, 0);
			break;
		case 'V':
			print_version(1);
			exit(0);
			break;
		case 'D':
			g_daemonize = 1;
			break;
		default:
			/* ignore */
			break;
		};
	}
	if (argc > optind) {
		fprintf(stderr, "Unsupported positional arguments on command line\n");
		exit(2);
	}
}

int main(int argc, char **argv)
{
	int rc;

	g_tall_ctx = talloc_named_const(NULL, 0, "root");
	g_vty_info.tall_ctx = g_tall_ctx;

	osmo_init_ignore_signals();
	osmo_init_logging2(g_tall_ctx,  &log_info);
	log_enable_multithread();

	g_daemon = gtp_daemon_alloc(g_tall_ctx);
	OSMO_ASSERT(g_daemon);

	msgb_talloc_ctx_init(g_tall_ctx, 10);
	osmo_stats_init(g_tall_ctx);
	vty_init(&g_vty_info);
	logging_vty_add_cmds();
	osmo_talloc_vty_add_cmds();
	osmo_stats_vty_add_cmds();
	rate_ctr_init(g_tall_ctx);
	gtpud_vty_init();

	handle_options(argc, argv);

	init_netns();

	rc = vty_read_config_file(g_config_file, NULL);
	if (rc < 0) {
		fprintf(stderr, "Failed to open config file: '%s'\n", g_config_file);
		exit(2);
	}

	rc = telnet_init_dynif(g_daemon, NULL, vty_get_bind_addr(), OSMO_VTY_PORT_UECUPS);
	if (rc < 0)
		exit(1);

	/* UECUPS socket for control from control plane side */
	g_daemon->cups_link = cups_srv_link_create(g_daemon);
	if (!g_daemon->cups_link) {
		fprintf(stderr, "Failed to create CUPS socket %s:%u (%s)\n",
			g_daemon->cfg.cups_local_ip, g_daemon->cfg.cups_local_port, strerror(errno));
		exit(1);
	}

	/* block SIGCHLD via normal delivery; redirect it to signalfd */
	sigset_t sigset;
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGCHLD);
	sigaddset(&sigset, SIGUSR1);
	sigprocmask(SIG_BLOCK, &sigset, NULL);
	g_daemon->signalfd = osmo_signalfd_setup(g_daemon, sigset, signal_cb, g_daemon);
	osmo_init_ignore_signals();

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
