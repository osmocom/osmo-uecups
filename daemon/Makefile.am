AM_CPPFLAGS = \
	$(all_includes) \
	$(NULL)

AM_CFLAGS = \
	-Wall \
	$(LIBOSMOCORE_CFLAGS) \
	$(LIBOSMOVTY_CFLAGS) \
	$(LIBOSMONETIF_CFLAGS) \
	$(LIBJANSSON_CFLAGS) \
	$(LIBNLROUTE3_CFLAGS) \
	$(NULL)

LDADD = \
	-lpthread \
	-lsctp \
	$(LIBOSMOCORE_LIBS) \
	$(LIBOSMOVTY_LIBS) \
	$(LIBOSMONETIF_LIBS) \
	$(LIBJANSSON_LIBS) \
	$(LIBNLROUTE3_LIBS) \
	$(NULL)

AM_LDFLAGS = \
	$(COVERAGE_LDFLAGS) \
	$(NULL)

noinst_HEADERS = \
	gtp.h \
	netns.h \
	internal.h \
	$(NULL)

bin_PROGRAMS = \
	osmo-uecups-daemon \
	$(NULL)

osmo_uecups_daemon_SOURCES = \
	utility.c \
	netdev.c \
	netns.c \
	tun_device.c \
	gtp_endpoint.c \
	gtp_tunnel.c \
	daemon_vty.c \
	main.c \
	$(NULL)
