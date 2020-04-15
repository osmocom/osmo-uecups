/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdint.h>

/* General GTP protocol related definitions. */

#define GTP0_PORT	3386
#define GTP1U_PORT	2152

#define GTP_TPDU	255

struct gtp0_header {	/* According to GSM TS 09.60. */
	uint8_t	flags;
	uint8_t	type;
	uint16_t length;
	uint16_t seq;
	uint16_t flow;
	uint8_t	number;
	uint8_t	spare[3];
	uint64_t tid;
} __attribute__ ((packed));

struct gtp1_header {	/* According to 3GPP TS 29.060. */
	uint8_t	flags;
	uint8_t	type;
	uint16_t length;
	uint32_t tid;
} __attribute__ ((packed));

#define GTP1_F_NPDU	0x01
#define GTP1_F_SEQ	0x02
#define GTP1_F_EXTHDR	0x04
#define GTP1_F_MASK	0x07
