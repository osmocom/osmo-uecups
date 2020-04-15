/* SPDX-License-Identifier: GPL-2.0 */
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>

#include "internal.h"

/***********************************************************************
 * Utility
 ***********************************************************************/

bool sockaddr_equals(const struct sockaddr *a, const struct sockaddr *b)
{
	const struct sockaddr_in *a4, *b4;
	const struct sockaddr_in6 *a6, *b6;

	if (a->sa_family != b->sa_family)
		return false;

	switch (a->sa_family) {
	case AF_INET:
		a4 = (struct sockaddr_in *) a;
		b4 = (struct sockaddr_in *) b;
		if (a4->sin_port != b4->sin_port)
			return false;
		if (a4->sin_addr.s_addr != b4->sin_addr.s_addr)
			return false;
		break;
	case AF_INET6:
		a6 = (struct sockaddr_in6 *) a;
		b6 = (struct sockaddr_in6 *) b;
		if (a6->sin6_port != b6->sin6_port)
			return false;
		if (memcmp(a6->sin6_addr.s6_addr, b6->sin6_addr.s6_addr, sizeof(b6->sin6_addr.s6_addr)))
			return false;
		break;
	default:
		assert(false);
	}

	return true;
}

struct addrinfo *addrinfo_helper(uint16_t family, uint16_t type, uint8_t proto,
				 const char *host, uint16_t port, bool passive)
{
	struct addrinfo hints, *result;
	char portbuf[6];
	int rc;

	snprintf(portbuf, sizeof(portbuf), "%u", port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = type;
	hints.ai_protocol = proto;
	if (passive)
		hints.ai_flags |= AI_PASSIVE;

	rc = getaddrinfo(host, portbuf, &hints, &result);
	if (rc != 0)
		return NULL;

	return result;
}
