/**
 * @file type.h
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

#ifndef __YAMDNS_TYPE_H
#define __YAMDNS_TYPE_H

#include <stdint.h>

#include <yamdns/define.h>

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

/** mDNS record about service */
typedef struct mdns_record_srv {
	/** always zero */
	uint16_t priority;

	/** always zero */
	uint16_t weight;

	/** port of service */
	uint16_t port;

	/** service name and pointer to service owner */
	char name[];
} mdns_record_srv_t;

/*------------------------------------------------------------------------*/

/** type of query handler */
typedef void (*mdns_query_handler)(const mdns_query_hdr_t*, const char*);

/** type of answer handler for type A */
typedef void (*mdns_answer_handler_a)(const mdns_answer_hdr_t*, const char*, struct in_addr*);

/** type of answer handler for type PTR */
typedef void (*mdns_answer_handler_ptr)(const mdns_answer_hdr_t*, const char*, const char*);

/** type of answer handler for type TEXT */
typedef void (*mdns_answer_handler_text)(const mdns_answer_hdr_t*, const char*, const char*);

/** type of answer handler for type SRV */
typedef void (*mdns_answer_handler_srv)(const mdns_answer_hdr_t*, const char*, mdns_record_srv_t*, const char*);

/** type of answer handler for unknown types */
typedef void (*mdns_answer_handler_raw)(const mdns_answer_hdr_t*, const char*, const void*, size_t);

/*------------------------------------------------------------------------*/

/** callbacks handlers for mDNS packet */
typedef struct mdns_handlers {
	/** query handler */
	mdns_query_handler q;
	
	/** answer handler for type A */
	mdns_answer_handler_a a;

	/** answer handler for type PTR */
	mdns_answer_handler_ptr ptr;

	/** answer handler for type TEXT */
	mdns_answer_handler_text text;

	/** answer handler for type SRV */
	mdns_answer_handler_srv srv;

	/** answer handler for unknown types */
	mdns_answer_handler_raw raw;
} mdns_handlers_t;

#endif /* __YAMDNS_TYPE_H */
