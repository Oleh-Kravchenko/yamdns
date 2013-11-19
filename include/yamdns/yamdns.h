/**
 * @file yamdns.h
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

#include <yamdns/type.h>

/**
 * @brief initialize buffer with empty mDNS packet
 * @param [in,out] buf buffer for data
 * @param [in] len length of buf
 * @return zero, if successful
 */
int mdns_packet_init(void* buf, size_t len);

/**
 * @brief process mDNS packet and call handlers
 * @param [in] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] handlers callback handlers
 * @return size of successfully parsed data
 */
size_t mdns_packet_process(const void* buf, size_t len, mdns_handlers_t* handlers);

/**
 * @brief print dump of mDNS packet
 * @param [in] buf buffer with packet
 * @param [in] len size of buffer or packet
 */
void mdns_packet_dump(const void* buf, size_t len);

/**
 * @brief calculate mDNS packet size
 * @param [in] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @return size of mDNS packet in buf
 */
size_t mdns_packet_size(const void* buf, size_t len);

/**
 * @brief add query into mDNS packet
 * @param [in,out] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] q_type resource type
 * @param [in] name requested resource
 * @return zero, if successful
 */
int mdns_packet_add_query_in(void* buf, size_t len, uint16_t q_type, const char* name);

/**
 * @brief add answer for in address into mDNS packet
 * @param [in,out] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] ttl time to live of this answer
 * @param [in] root query of answer
 * @param [in] in IPv4 address
 * @return zero, if successful
 */
int mdns_packet_add_answer_in(void* buf, size_t len, uint32_t ttl, const char* root, struct in_addr in);

/**
 * @brief add answer about pointer into mDNS packet
 * @param [in,out] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] ttl time to live of this answer
 * @param [in] root query of answer
 * @param [in] name pointer name
 * @return zero, if successful
 */
int mdns_packet_add_answer_in_ptr(void* buf, size_t len, uint32_t ttl, const char* root, const char* name);

/**
 * @brief add answer text record into mDNS packet
 * @param [in,out] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] ttl time to live of this answer
 * @param [in] root query of answer
 * @param [in] text text
 * @return zero, if successful
 */
int mdns_packet_add_answer_in_text(void* buf, size_t len, uint32_t ttl, const char* root, const char* text);

/**
 * @brief add answer about service into mDNS packet
 * @param [in,out] buf buffer with packet
 * @param [in] len size of buffer or packet
 * @param [in] ttl time to live of this answer
 * @param [in] root query of answer
 * @param [in] prio priority of service
 * @param [in] weight weight of service
 * @param [in] port service port (0-65535)
 * @param [in] name name of service host
 * @return zero, if successful
 */
int mdns_packet_add_answer_in_srv(void* buf, size_t len, uint32_t ttl, const char* root, uint16_t prio, uint16_t weight, uint16_t port, const char* name);

#endif /* __YAMDNS_H */
