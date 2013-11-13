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

/** 224.0.0.251 */
#define __MDNS_MC_GROUP 0xfb0000e0

#define __MDNS_PORT 5353

/*------------------------------------------------------------------------*/

typedef enum mdns_record_type {
	MDNS_QUERY_TYPE_A     = 0x0001,
	MDNS_QUERY_TYPE_PTR   = 0x000c,
	MDNS_QUERY_TYPE_TEXT  = 0x0010,
	MDNS_QUERY_TYPE_AAAA  = 0x001c,
	MDNS_QUERY_TYPE_SRV   = 0x0021,
} mdns_record_type_t;

/*------------------------------------------------------------------------*/

enum {
	MDNS_FLAG_RESPONSE    = 0,
	MDNS_FLAG_QUERY       = 0x8000,
	MDNS_FLAG_AUTH        = 0x0400,
};

/*------------------------------------------------------------------------*/

/** max size of dns name including zero byte */
#define MDNS_MAX_NAME 0x100

/** max size label of name */
#define MDNS_MAX_LABEL_NAME 0x40

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

typedef struct mdns_record_srv {
	uint16_t priority;

	uint16_t weight;

	uint16_t port;

	char target[];
} mdns_record_srv_t;

/*------------------------------------------------------------------------*/

typedef void (*mdns_query_handler)(const mdns_query_hdr_t*, const char*);
typedef void (*mdns_answer_handler_a)(const mdns_answer_hdr_t*, const char*, struct in_addr*);
typedef void (*mdns_answer_handler_ptr)(const mdns_answer_hdr_t*, const char*, const char*);
typedef void (*mdns_answer_handler_text)(const mdns_answer_hdr_t*, const char*, const char*);
typedef void (*mdns_answer_handler_srv)(const mdns_answer_hdr_t*, const char*, mdns_record_srv_t*, const char*);
typedef void (*mdns_answer_handler_raw)(const mdns_answer_hdr_t*, const char*, const void*, size_t);

typedef struct mdns_handlers {
	mdns_query_handler q;
	mdns_answer_handler_a a;
	mdns_answer_handler_ptr ptr;
	mdns_answer_handler_text text;
	mdns_answer_handler_srv srv;
	mdns_answer_handler_raw raw;
} mdns_handlers_t;

/*------------------------------------------------------------------------*/

int mdns_packet_init(void* buf, size_t len);

size_t mdns_packet_process(const void* buf, size_t len, mdns_handlers_t* handlers);

void mdns_packet_dump(const void* buf, size_t len);

size_t mdns_packet_size(void* buf, size_t len);

int mdns_packet_add_answer_in(void* buf, size_t len, uint32_t ttl, const char* owner, struct in_addr in);

int mdns_packet_add_answer_ptr(void* buf, size_t len, uint32_t ttl, const char* owner, const char* name);

int mdns_packet_add_answer_text(void* buf, size_t len, uint32_t ttl, const char* owner, const char* text);

int mdns_packet_add_answer_srv(void* buf, size_t len, uint32_t ttl, const char* owner, uint16_t prio, uint16_t weight, uint16_t port, const char* name);

int mdns_packet_add_query_in(void* buf, size_t len, uint16_t q_type, const char* name);

#endif /* __YAMDNS_H */
