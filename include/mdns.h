/* yamdns -- yet another very simple mdns.
 * Copyright (C) 2013  Oleh Kravchenko <oleg@kaa.org.ua>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __YAMDNS_H
#define __YAMDNS_H

#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>

#define MDNS_QUERY_TYPE_A		0x0001
#define MDNS_QUERY_TYPE_AAAA	0x001c
#define MDNS_QUERY_TYPE_PTR		0x000c

/*------------------------------------------------------------------------*/

#define MDNS_FLAG_RESPONSE	0
#define MDNS_FLAG_QUERY		0x8000
#define MDNS_FLAG_AUTH		0x0400

/*------------------------------------------------------------------------*/

/** max size of dns name including zero byte */
#define MDNS_MAX_NAME	0x100

/*------------------------------------------------------------------------*/

typedef struct mdns_hdr {
	/** must be zero */
	uint16_t id;

	/** must be zero for queries */
	uint16_t flags;

	/** number of queries */
	uint16_t qd_cnt;

	/** number of response */
	uint16_t an_cnt;

	/** must be zero */
	uint16_t ns_cnt;

	/** must be zero */
	uint16_t ar_cnt;
} __attribute__((__packed__)) mdns_hdr_t ;

/*------------------------------------------------------------------------*/

typedef struct mdns_query_hdr {
	uint16_t q_type;

	uint16_t q_class;
} __attribute__((__packed__)) mdns_query_hdr_t;

/*------------------------------------------------------------------------*/

typedef struct mdns_query {
	mdns_query_hdr_t hdr;

	char name[MDNS_MAX_NAME];
} mdns_query_t;

/*------------------------------------------------------------------------*/

typedef struct mdns_answer_hdr {
	uint16_t a_type;

	uint16_t a_class;

	int32_t a_ttl;

	uint16_t a_data_len;
} mdns_answer_hdr_t;

/*------------------------------------------------------------------------*/

typedef struct mdns_answer {
	mdns_answer_hdr_t hdr;

	char name[MDNS_MAX_NAME];

	union {
		char name[MDNS_MAX_NAME];

		struct in_addr addr;
	} data;
} mdns_answer_t;

/*------------------------------------------------------------------------*/

typedef struct mdns_pkt {
	mdns_hdr_t hdr;

	mdns_query_t* queries;

	mdns_answer_t* answers;
} mdns_pkt_t;

/*------------------------------------------------------------------------*/

mdns_pkt_t* mdns_pkt_parse(const void* buf, size_t len);

void mdns_pkt_destroy(mdns_pkt_t* pkt);

void mdns_pkt_dump(mdns_pkt_t* pkt);

#endif /* __YAMDNS_H */
