/* SPDX-License-Identifier: GPL-2.0 */
#pragma once
#include <stdint.h>
#include <osmocom/core/endian.h>

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


/*
 * 5GC GTP Header (16byte)
 *  o Flags(1byte) : 0x34
 *  o Message Type(1byte) : T-PDU (0xff)
 *  o Length(2byte) : 36
 *  o TEID(4byte) : 0x00000001
 *  o Sequence Number(2byte) : 0x0000
 *  o N PDU Number(1byte) : 0x00
 *  o Next extension header type(4byte): PDU Session container(1byte) : (0x85)
 *  o Extension header(4byte)
 *    - Extension HEader Length(1byte) : 1
 *    - PDU Session Container(2byte)
 *      ; PDU Type : UL PDU SESSION INFORMATION (1)
 *      ; QoS Flow Identifier (QFI) : 1
 *    - Next extension header type : No more extension headers (0x00)
 */

#define GTP1_EXTHDR_UDP_PORT 0x40
#define GTP1_EXTHDR_PDU_SESSION_CONTAINER 0x85
#define GTP1_EXTHDR_PDCP_NUMBER 0xc0
#define GTP1_EXTHDR_NO_MORE_EXTENSION_HEADERS 0x0

#define GTP1_EXTHDR_PDU_TYPE_DL_PDU_SESSION_INFORMATION 0
#define GTP1_EXTHDR_PDU_TYPE_UL_PDU_SESSION_INFORMATION 1

struct gtp1_exthdr {
	uint16_t sequence_number;
	uint8_t n_pdu_number;
	struct {
#if OSMO_IS_LITTLE_ENDIAN
		uint8_t type;
		uint8_t len;
		union {
			struct { /* TODO: make sure order of fields is correct or swapped */
				uint8_t spare1:4,
					pdu_type:4;
				uint8_t qos_flow_identifier:6,
					reflective_qos_indicator:1,
					paging_policy_presence:1;
#elif OSMO_IS_BIG_ENDIAN
/* auto-generated from the little endian part above (libosmocore/contrib/struct_endianness.py) */
		uint8_t type;
		uint8_t len;
		union {
			struct {
				uint8_t spare1:4,
					pdu_type:4;
				uint8_t paging_policy_presence:1, reflective_qos_indicator:1, qos_flow_identifier:6;
#endif
			};
			uint16_t udp_port;
			uint16_t pdcp_number;
		};
	} __attribute__ ((packed)) array[8];
} __attribute__ ((packed));
