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

#include <yamdns/yamdns.h>

#include "network.h"

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
	socklen_t recvaddr_len;
	struct in_addr ifaddr;
	uint8_t buf[1500];
	int sockfd;
	int res;

	if(narg != 2) {
		puts("Interface not specificaited");
		return(1);
	}

	/* interface address validation */
	if(!inet_aton(argv[1], &ifaddr)) {
		printf("%s: unknown interface %s\n", argv[0], argv[1]);

		return(exit_code);
	}

	if(!(hostname = getenv("HOSTNAME"))) {
		puts("HOSTNAME not defined");
		return(1);
	}

	/* prepare ip address resolution name */
	snprintf(host_name, sizeof(host_name), "%s.local.", hostname);
	snprintf(addr_name, sizeof(addr_name),
		"%s.in-addr.arpa.",
		inet_ntoa((struct in_addr){__builtin_bswap32(ifaddr.s_addr)})
	);

	/* register signal handlers */
	signal(SIGTERM, on_sigterm);
	signal(SIGINT, on_sigterm);

	openlog(argv[0], LOG_PID, LOG_DAEMON);

	/* create UDP socket for multicasting */
	if((sockfd = mdns_socket(ifaddr, 10)) == -1) {
		perror("socket()");
		return(exit_code);
	}

	memset(&recvaddr, 0, sizeof(recvaddr));
	recvaddr.sin_family = AF_INET;
	recvaddr.sin_port = htons(5353);
	recvaddr.sin_addr = __MDNS_MC_GROUP;

	mdns_packet_init(&buf, sizeof(buf));
	mdns_packet_add_query_in(buf, sizeof(buf), MDNS_RECORD_PTR, MDNS_QUERY_SERVICE_DISCOVERY);
	res = sendto(sockfd, buf, mdns_packet_size(buf, sizeof(buf)), 0, (struct sockaddr*)&recvaddr, sizeof(recvaddr));

	printf("(out) to %s:%d, length: %d\n",
		inet_ntoa(recvaddr.sin_addr), ntohs(recvaddr.sin_port), res);

	mdns_packet_dump(buf, res); fflush(stdout);

	do {
		recvaddr_len = sizeof(recvaddr);

		/* receive packet */
		if((res = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr*)&recvaddr, &recvaddr_len)) == -1) {
			if(errno == EAGAIN)
				continue;

			perror("recvfrom()");
			goto error;
		}

		printf("(in) from %s:%d, length: %d\n",
			inet_ntoa(recvaddr.sin_addr), ntohs(recvaddr.sin_port), res);

		mdns_packet_dump(buf, res); fflush(stdout);
	} while(!terminate);

	exit_code = 0;

error:
	mdns_close(ifaddr, sockfd);

	closelog();

	return(exit_code);
}
