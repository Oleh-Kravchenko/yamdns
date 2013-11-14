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

#include <mdns/type.h>

int mdns_packet_init(void* buf, size_t len);

size_t mdns_packet_process(const void* buf, size_t len, mdns_handlers_t* handlers);

void mdns_packet_dump(const void* buf, size_t len);

size_t mdns_packet_size(const void* buf, size_t len);

int mdns_packet_add_answer_in(void* buf, size_t len, uint32_t ttl, const char* owner, struct in_addr in);

int mdns_packet_add_answer_ptr(void* buf, size_t len, uint32_t ttl, const char* owner, const char* name);

int mdns_packet_add_answer_text(void* buf, size_t len, uint32_t ttl, const char* owner, const char* text);

int mdns_packet_add_answer_srv(void* buf, size_t len, uint32_t ttl, const char* owner, uint16_t prio, uint16_t weight, uint16_t port, const char* name);

int mdns_packet_add_query_in(void* buf, size_t len, uint16_t q_type, const char* name);

#endif /* __YAMDNS_H */
