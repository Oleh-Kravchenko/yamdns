/**
 * @file network.h
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

#ifndef __YAMDNS_NETWORK_H
#define __YAMDNS_NETWORK_H

#include <arpa/inet.h>

/**
 * @brief create and bind socket for mdns
 * @param [in] ifaddr interface address
 * @param [in] timeout default timeout for socket read ops
 * @return zero, if successful
 */
int mdns_socket(struct in_addr ifaddr, int timeout);

/**
 * @brief close mdns socket
 * @param [in] ifaddr interface address
 * @param [in] sockfd socket desctriptor
 * @return zero, if successful
 */
int mdns_close(struct in_addr ifaddr, int sockfd);

/**
 * @brief send mDNS packet
 * @param [in] sockfd socket desctriptor
 * @param [in] buf pointer to packet
 * @param [in] len length of packet
 * @return int
 */
int mdns_send(int sockfd, void* buf, size_t len);

#endif /* __YAMDNS_NETWORK_H */
