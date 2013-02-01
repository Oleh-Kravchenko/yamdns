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

int main(int narg, char** argv)
{
	struct sockaddr_in recvaddr;
	struct sockaddr_in bindaddr;
	socklen_t recvaddr_len;
	uint8_t buf[0x10000];
	mdns_pkt_t* pkt;
	size_t len;
	int sockfd;
	int answer;
	int res, i;

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
#if 0
				puts("No packets");
#endif
				continue;
			}

			perror("recvfrom()");
			goto error;
		}

		puts(inet_ntoa(recvaddr.sin_addr));

		if(!(pkt = mdns_pkt_unpack(buf, res)))
			continue;

		answer = 0;

		mdns_pkt_dump(pkt);

		for(i = 0; i < pkt->hdr.qd_cnt; ++ i) {
			printf("--> %s : %d\n", pkt->queries[i].name, strcmp(pkt->queries[i].name, "comp.local."));
			if(!strcmp(pkt->queries[i].name, "comp.local.")) {
				answer = 1;
				break;
			}
		}

		mdns_pkt_destroy(pkt);

		if(answer) {
			/*memset(&recvaddr, 0, sizeof(recvaddr));
			inet_aton("224.0.0.251", &recvaddr.sin_addr);
			recvaddr.sin_family = AF_INET;
			recvaddr.sin_port = htons(5353);*/

			pkt = mdns_pkt_init();
			pkt->hdr.flags = MDNS_FLAG_QUERY | MDNS_FLAG_AUTH;

			mdns_pkt_add_answer_in(pkt, 120, "comp.local.", &mreq.imr_interface);
			len = mdns_pkt_pack(pkt, buf, sizeof(buf));
			sendto(sockfd, buf, len, 0, (struct sockaddr *)&recvaddr, sizeof(recvaddr));
			perror("sendto");
			mdns_pkt_destroy(pkt);
		}
	} while(1);

	exit_code = 0;

error:
	close(sockfd);

	return(exit_code);
}
