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
static struct in_addr ifaddr;

typedef struct mdns_ctx {
	void* buf;
	size_t len;
} mdns_ctx_t;

/*------------------------------------------------------------------------*/

static void mdns_dump_query_handler(void* ctx, const mdns_query_hdr_t* h, const char* root);

mdns_handlers_t handlers = {
	.q = mdns_dump_query_handler,
};

/*------------------------------------------------------------------------*/

void on_sigterm(int prm)
{
	terminate = 1;
}

/*------------------------------------------------------------------------*/

static void mdns_dump_query_handler(void* ctx, const mdns_query_hdr_t* h, const char* root)
{
	mdns_ctx_t* priv = ctx;

	if(!strcmp(root, host_name)) {
		mdns_packet_add_answer_in(priv->buf, priv->len, 60, root, ifaddr);
	} else if(!strcmp(root, addr_name)) {
		mdns_packet_add_answer_in_ptr(priv->buf, priv->len, 60, root, host_name);
	}
}

/*------------------------------------------------------------------------*/

int main(int narg, char** argv)
{
	struct sockaddr_in sa;
	socklen_t sa_len;
	uint8_t bufin[1500];
	uint8_t bufout[1500];
	mdns_ctx_t ctx = {.buf = bufout, .len = sizeof(bufout),};
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

	do {
		sa_len = sizeof(sa);

		/* receive packet */
		if((res = recvfrom(sockfd, bufin, sizeof(bufin), 0, (struct sockaddr*)&sa, &sa_len)) == -1) {
			if(errno == EAGAIN)
				continue;

			perror("recvfrom()");
			goto error;
		}

		/* process incoming packet */
		printf("(in) from %s:%d, length: %d\n",
			inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), res);
		mdns_packet_dump(bufin, res); fflush(stdout);

		mdns_packet_init(&bufout, sizeof(bufout));
		mdns_packet_process(bufin, res, &handlers, &ctx);

		/* prepare sending */
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		sa.sin_port = htons(__MDNS_PORT);
		sa.sin_addr = __MDNS_MC_GROUP;

		res = sendto(sockfd, bufout, mdns_packet_size(bufout, sizeof(bufout)), 0, (struct sockaddr*)&sa, sizeof(sa));

		/* print sended packet */
		printf("(out) to %s:%d, length: %d\n",
			inet_ntoa(sa.sin_addr), ntohs(sa.sin_port), res);
		mdns_packet_dump(bufout, res); fflush(stdout);
	} while(!terminate);

	exit_code = 0;

error:
	mdns_close(ifaddr, sockfd);

	closelog();

	return(exit_code);
}
