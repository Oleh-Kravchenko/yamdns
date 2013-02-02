/**
 * @file mdns.h
 *
 * yamdns -- yet another very simple mdns.
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

/*------------------------------------------------------------------------*/

#define MDNS_QUERY_TYPE_A       0x0001
#define MDNS_QUERY_TYPE_PTR     0x000c
#define MDNS_QUERY_TYPE_AAAA    0x001c

/*------------------------------------------------------------------------*/

#define MDNS_FLAG_RESPONSE      0
#define MDNS_FLAG_QUERY         0x8000
#define MDNS_FLAG_AUTH          0x0400

/*------------------------------------------------------------------------*/

/** max size of dns name including zero byte */
#define MDNS_MAX_NAME 0x100

/*------------------------------------------------------------------------*/

/** header of dns packet */
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
} __attribute__((__packed__)) mdns_hdr_t;

/*------------------------------------------------------------------------*/

/** header of query */
typedef struct mdns_query_hdr {
	/** type of query */
	uint16_t q_type;

	/** class of query */
	uint16_t q_class;
} __attribute__((__packed__)) mdns_query_hdr_t;

/*------------------------------------------------------------------------*/

/** uncompressed query */
typedef struct mdns_query {
	/** header of query */
	mdns_query_hdr_t hdr;

	/** target of query */
	char name[MDNS_MAX_NAME];
} mdns_query_t;

/*------------------------------------------------------------------------*/

/** header of answer */
typedef struct mdns_answer_hdr {
	/** type of answer */
	uint16_t a_type;

	/** class of answer */
	uint16_t a_class;

	/** time to live of answer*/
	int32_t a_ttl;

	/** length of rdata */
	uint16_t rd_len;
} __attribute__((__packed__)) mdns_answer_hdr_t;

/*------------------------------------------------------------------------*/

/** uncompressed answer */
typedef struct mdns_answer {
	/** header of answer */
	mdns_answer_hdr_t hdr;

	/** owner of answer */
	char owner[MDNS_MAX_NAME];

	/** payload for answer */
	union {
		/** name */
		char name[MDNS_MAX_NAME];

		/** IPv4 address */
		struct in_addr in;

		/** raw data */
		uint8_t raw[MDNS_MAX_NAME];
	} rdata;
} mdns_answer_t;

/*------------------------------------------------------------------------*/

/** uncompressed/parsed mDNS packet */
typedef struct mdns_pkt {
	/** header */
	mdns_hdr_t hdr;

	/** pointer to queries */
	mdns_query_t* queries;

	/** pointer to answers */
	mdns_answer_t* answers;
} mdns_pkt_t;

/*------------------------------------------------------------------------*/

/** create empty mdns packet */
mdns_pkt_t* mdns_pkt_init(void);

/**
 * @brief free resource of mDNS packet
 * @param [in] pkt mDNS packet, can be NULL
 */
void mdns_pkt_destroy(mdns_pkt_t* pkt);

/**
 * @brief parse raw mDNS packet
 * @param [in] buf buffer
 * @param [in] len length of buffer
 * @return NULL if parser failed.
 */
mdns_pkt_t* mdns_pkt_unpack(const void* buf, size_t len);

/**
 * @brief pack mDNS packet into raw packet
 * @param [in] pkt packet
 * @param [in,out] buf buffer for raw packet
 * @param [in,out] len maximum length of buffer
 * @return zero if successful
 */
int mdns_pkt_pack(mdns_pkt_t* pkt, void* buf, size_t len);

/**
 * @brief dump mdns packet
 * @param [in] pkt mDNS packet
 */
void mdns_pkt_dump(mdns_pkt_t* pkt);

/**
 * @brief add answer into packet
 * @param pkt packet
 * @param ttl time to live
 * @param owner owner name
 * @param in inet address
 * @return zero, if successfully
 */
int mdns_pkt_add_answer_in(mdns_pkt_t* pkt, int32_t ttl, const char* owner, struct in_addr* in);

/**
 * @brief add answer into packet
 * @param pkt packet
 * @param ttl time to live
 * @param owner owner name
 * @param name name
 * @return zero, if successfully
 **/
int mdns_pkt_add_answer_name(mdns_pkt_t* pkt, int32_t ttl, const char* owner, const char* name);

/**
 * @brief add query into packet
 * @param pkt packet
 * @param q_type query type
 * @param name quering name
 * @return zero, if successfully
 */
int mdns_pkt_add_query_in(mdns_pkt_t* pkt, uint16_t q_type, const char* name);

#endif /* __YAMDNS_H */
