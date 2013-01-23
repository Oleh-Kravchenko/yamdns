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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>

#include "mdns.h"

/*------------------------------------------------------------------------*/

static int exit_code = 1;

/*------------------------------------------------------------------------*/

#if 0
uint8_t recv_pkt[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x63, 0x6f, 0x6d, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
	0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01
};

uint8_t send_pkt[] = {
	0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
	0x04, 0x63, 0x6f, 0x6d, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00,
	0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0xc0, 0xa8,
	0x01, 0x6e
};
#endif

/*------------------------------------------------------------------------*/

int main(int narg, char** argv)
{
	uint8_t buf[0x10000];
	struct sockaddr_in recvaddr;
	struct sockaddr_in bindaddr;
	socklen_t recvaddr_len;
	int sockfd;
	int res;

	/* create raw socket for ICMP */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket()");
		return(exit_code);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval) {10, 0}, sizeof(struct timeval)) == -1) {
		perror("setsockopt(SO_RCVTIMEO)");
		return(exit_code);
	}

	int ttl = 255;

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
		perror("setsockopt(IP_MULTICAST_TTL)");
		return(exit_code);
	}

	struct ip_mreq mreq;

	inet_aton("224.0.0.251", &mreq.imr_multiaddr);
	inet_aton("10.7.0.2", &mreq.imr_interface);

	if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		perror("setsockopt(IP_ADD_MEMBERSHIP)");
		return(exit_code);
	}

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(5353);

	if(bind(sockfd, (struct sockaddr*)&bindaddr, sizeof(bindaddr)) == -1) {
		perror("bind()");
		return(exit_code);
	}

	do {
		recvaddr_len = sizeof(recvaddr);

		/* receive packet */
		if((res = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&recvaddr, &recvaddr_len)) == -1) {
			if(errno == EAGAIN) {
				puts("No packets");
				continue;
			}

			perror("recvfrom()");
			goto error;
		}

		mdns_pkt_t* pkt;

		if((pkt = mdns_pkt_parse(buf, res))) {
			mdns_pkt_dump(pkt);
			mdns_pkt_destroy(pkt);
		}
	} while(1);

	exit_code = 0;

error:
	close(sockfd);

	return(exit_code);
}
