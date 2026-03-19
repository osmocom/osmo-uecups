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
