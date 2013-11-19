/**
 * @file network.c
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

#include <string.h>
#include <unistd.h>

#include <yamdns/type.h>

/*------------------------------------------------------------------------*/

int mdns_socket(struct in_addr ifaddr, int timeout)
{
	struct sockaddr_in saaddr;
	struct ip_mreq mreq;
	int sockfd;

	/* create UDP socket for multicasting */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return(-1);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) == -1) {
		goto error;
	}

	memset(&saaddr, 0, sizeof(saaddr));
	saaddr.sin_family = AF_INET;
	saaddr.sin_port = htons(__MDNS_PORT);

	if(bind(sockfd, (struct sockaddr*)&saaddr, sizeof(saaddr)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &(uint8_t){0}, sizeof(uint8_t)) == -1) {
		goto error;
	}

	/* send multicasting from interface */
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&ifaddr, sizeof(ifaddr)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval) {timeout, 0}, sizeof(struct timeval)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &(int){__MDNS_TTL}, sizeof(int)) == -1) {
		goto error;
	}

	mreq.imr_interface = ifaddr;
	mreq.imr_multiaddr = __MDNS_MC_GROUP;

	if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		goto error;
	}

	return(sockfd);

error:
	close(sockfd);

	return(-1);
}

/*------------------------------------------------------------------------*/

int mdns_close(struct in_addr ifaddr, int sockfd)
{
	struct ip_mreq mreq;

	mreq.imr_interface = ifaddr;
	mreq.imr_multiaddr = __MDNS_MC_GROUP;

	if(setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		/* TODO print warning? */;
	}

	return(close(sockfd));
}

/*------------------------------------------------------------------------*/

int mdns_send(int sockfd, void* buf, size_t len)
{
	struct sockaddr_in sa;

	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(__MDNS_PORT);
	sa.sin_addr = __MDNS_MC_GROUP;

	return(sendto(sockfd, buf, len, 0, (struct sockaddr*)&sa, sizeof(sa)));
}
