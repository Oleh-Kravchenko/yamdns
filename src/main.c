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
#include <signal.h>
#include <syslog.h>

#include "mdns.h"

/*------------------------------------------------------------------------*/

static int exit_code = 1;
static int terminate = 0;

static char host_name[MDNS_MAX_NAME];
static char addr_name[MDNS_MAX_NAME];
static const char* hostname;

/*------------------------------------------------------------------------*/

void on_sigterm(int prm)
{
	terminate = 1;
}

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
	int host_answer, addr_answer;
	int res, i;

	struct ip_mreq mreq;

	if(narg != 2) {
		puts("Interface not specificaited");
		return(1);
	}

	/* mDNS multicasting address */
	inet_aton("224.0.0.251", &mreq.imr_multiaddr);

	/* interface address validation */
	if(!inet_aton(argv[1], &mreq.imr_interface)) {
		struct hostent* host = gethostbyname(argv[1]);

		if(!host) {
			printf("%s: unknown interface %s\n", argv[0], argv[1]);

			return(exit_code);
		}

		mreq.imr_interface = *((struct in_addr*)host->h_addr);
	}

	if(!(hostname = getenv("HOSTNAME"))) {
		puts("HOSTNAME not defined");
		return(1);
	}

	snprintf(host_name, sizeof(host_name), "%s.local.", hostname);

	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);

	openlog(argv[0], LOG_PID, LOG_DAEMON);

	/* prepare ip address resolution name */
	snprintf(addr_name, sizeof(addr_name),
		"%s.in-addr.arpa.",
		inet_ntoa((struct in_addr){__builtin_bswap32(mreq.imr_interface.s_addr)})
	);

	/* create UDP socket for multicasting */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket()");
		return(exit_code);
	}

	memset(&bindaddr, 0, sizeof(bindaddr));
	bindaddr.sin_family = AF_INET;
	bindaddr.sin_port = htons(5353);

	if(bind(sockfd, (struct sockaddr*)&bindaddr, sizeof(bindaddr)) == -1) {
		perror("bind()");
		return(exit_code);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &(uint8_t){0}, sizeof(uint8_t)) == -1) {
		perror("setsockopt(IP_MULTICAST_LOOP)");
		return(exit_code);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&mreq.imr_interface, sizeof(mreq.imr_interface)) == -1) {
		perror("setsockopt(IP_MULTICAST_IF)");
		return(exit_code);
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval) {10, 0}, sizeof(struct timeval)) == -1) {
		perror("setsockopt(SO_RCVTIMEO)");
		return(exit_code);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &(int){255}, sizeof(int)) == -1) {
		perror("setsockopt(IP_MULTICAST_TTL)");
		return(exit_code);
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		perror("setsockopt(IP_ADD_MEMBERSHIP)");
		return(exit_code);
	}

	do {
		recvaddr_len = sizeof(recvaddr);

		/* receive packet */
		if((res = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&recvaddr, &recvaddr_len)) == -1) {
			if(errno == EAGAIN)
				continue;

			perror("recvfrom()");
			goto error;
		}

		if(!(pkt = mdns_pkt_unpack(buf, res)))
			continue;

		host_answer = 0;
		addr_answer = 0;

		for(i = 0; i < pkt->hdr.qd_cnt; ++ i) {
			if(!strcmp(pkt->queries[i].name, host_name)) {
				syslog(LOG_INFO, "Asking us for \"%s\" from \"%s\"\n", host_name, inet_ntoa(recvaddr.sin_addr));
				host_answer = 1;
			}

			if(!strcmp(pkt->queries[i].name, addr_name)) {
				syslog(LOG_INFO, "Asking us for \"%s\" from \"%s\"\n", host_name, inet_ntoa(recvaddr.sin_addr));
				addr_answer = 1;
			}
		}


#ifndef NDEBUG
		mdns_pkt_dump(pkt);
#endif
		mdns_pkt_destroy(pkt);
		pkt = NULL;

		if(host_answer) {
			pkt = mdns_pkt_init();

			mdns_pkt_add_answer_in(pkt, 30, host_name, &mreq.imr_interface);
		}

		if(addr_answer) {
			if(!pkt)
				pkt = mdns_pkt_init();

			mdns_pkt_add_answer_name(pkt, 30, addr_name, host_name);
		}

		if(!pkt)
			continue;

		memset(&recvaddr, 0, sizeof(recvaddr));
		recvaddr.sin_family = AF_INET;
		recvaddr.sin_addr = mreq.imr_multiaddr;
		recvaddr.sin_port = htons(5353);

		pkt->hdr.flags = MDNS_FLAG_QUERY | MDNS_FLAG_AUTH;

		len = mdns_pkt_pack(pkt, buf, sizeof(buf));

		if(sendto(sockfd, buf, len, 0, (struct sockaddr*)&recvaddr, sizeof(recvaddr)) == -1)
			perror("sendto()");

		mdns_pkt_destroy(pkt);
	} while(!terminate);

	exit_code = 0;

error:
	close(sockfd);

	closelog();

	return(exit_code);
}
