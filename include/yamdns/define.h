/**
 * @file define.h
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

#ifndef __YAMDNS_DEFINE_H
#define __YAMDNS_DEFINE_H

#include <netinet/in.h>

/*------------------------------------------------------------------------*/

/** 224.0.0.251 */
#define __MDNS_MC_GROUP (struct in_addr){.s_addr = 0xfb0000e0}

/** default mdns port */
#define __MDNS_PORT 5353

/** default TTL for mDNS */
#define __MDNS_TTL 255

/** max size of dns name including zero byte */
#define MDNS_MAX_NAME 0x100

/** max size label of name */
#define MDNS_MAX_LABEL_NAME 0x40

/** max size of address name, example "192.168.100.200.in-addr.arpa." */
#define MDNS_MAX_ADDRESS_NAME 30

/** service discovery query */
#define MDNS_QUERY_SERVICE_DISCOVERY "_services._dns-sd._udp.local."

/** address resolve query */
#define MDNS_QUERY_RESOLVE_ADDRESS "in-addr.arpa."

/** default mdns domain */
#define MDNS_DOMAIN "local."

/*------------------------------------------------------------------------*/

/** DNS record types */
typedef enum mdns_record_type {
	MDNS_RECORD_A     = 0x0001,
	MDNS_RECORD_PTR   = 0x000c,
	MDNS_RECORD_TEXT  = 0x0010,
	MDNS_RECORD_AAAA  = 0x001c,
	MDNS_RECORD_SRV   = 0x0021,
} mdns_record_type_t;

/*------------------------------------------------------------------------*/

/** mDNS class */
typedef enum mdns_class_type {
	/** internet class */
	MDNS_CLASS_IN     = 0x0001,
} mdns_class_type_t;

/*------------------------------------------------------------------------*/

enum {
	MDNS_FLAG_QUERY  = 0,
	MDNS_FLAG_ANSWER = 0x8000,
	MDNS_FLAG_AUTH   = 0x0400,
};

#endif /* __YAMDNS_DEFINE_H */
