LIBS=-lpthread -lsctp $(shell pkg-config --libs libosmocore libosmovty libosmo-netif jansson libnl-route-3.0)
INC=$(shell pkg-config --cflags libosmocore libosmovty libosmo-netif jansson libnl-route-3.0)
VER=$(shell git describe --tags)
CFLAGS=-Wall -g -DPACKAGE_VERSION='"$(VER)"' $(INC)

all: osmo-uecups-daemon

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $^

osmo-uecups-daemon: 	utility.o netdev.o netns.o tun_device.o \
			gtp_endpoint.o gtp_tunnel.o daemon_vty.o main.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LIBS)

clean:
	@rm -f *.o osmo-uecups-daemon
