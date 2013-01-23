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

/*------------------------------------------------------------------------*/

int main(int narg, char** argv)
{
	mdns_pkt_t* pkt;

	if((pkt = mdns_pkt_parse(recv_pkt, sizeof(recv_pkt)))) {
		mdns_pkt_dump(pkt);

		mdns_pkt_destroy(pkt);
	}

	return(exit_code);

#if 0
    uint8_t buf[0x10000];
    struct sockaddr_in recvaddr;
    struct sockaddr_in bindaddr;
    socklen_t recvaddr_len;
    int sockfd;
    int res;
    int i;

    /* create raw socket for ICMP */
    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("socket()");
        return(exit_code);
    }

    if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval) {
    10, 0
}, sizeof(struct timeval)) == -1) {
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
    inet_aton("192.168.7.1", &mreq.imr_interface);

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

        hexdump8(buf, res);

        mdns_packet_t* mdns = (mdns_packet_t*)buf;

        printf("   id: 0x%04x\n", mdns->id);
        printf("flags: 0x%04x\n", mdns->flags);
        printf("   qd: 0x%04x\n\n", ntohs(mdns->qd_cnt));

        uint8_t* qd = buf + sizeof(mdns_packet_t);

        for(i = 0; i < ntohs(mdns->qd_cnt); ++ i) {
            char path[0x100];
            int j = 0;

            *path = 0;

            /* check for pointer */
            if((qd[j] & 0xc0) == 0xc0) {
                puts("Name compression not yet supported!");
                printf("%x\n", ntohs((uint16_t)qd[j]));
                break;
            }

            /* path */
            while(qd[j]) {
                char path_chunk[0x100];

                memcpy(path_chunk, qd + j + 1, qd[j]);
                path_chunk[qd[j]] = 0;

                if(*path)
                    strncat(path, ".", sizeof(path));
                strncat(path, path_chunk, sizeof(path));

                printf("%d:%s\n", qd[j], path_chunk);

                j += qd[j] + 1;
            }

            printf("--> %s\n", path);

            mdns_question_t* mdns_q = (mdns_question_t*)(qd + j + 1);

            printf("qtype = 0x%04x, qclass = 0x%04x\n", ntohs(mdns_q->qtype), ntohs(mdns_q->qclass));

            qd += j + 1 + sizeof(*mdns_q);
        }

        printf("\n");
    } while(0);


    uint8_t pkt[] =
        "\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x04\x63\x6f\x6d\x70\x05"
        "\x6c\x6f\x63\x61\x6c\x00\x00\x01\x80\x01\x00\x00\x00\x78\x00\x04\xc0\xa8"
        "\x01\x6e";

    struct sockaddr_in sendaddr;

    sendaddr.sin_family = AF_INET;
    sendaddr.sin_port = htons(5353);
    inet_aton("224.0.0.251", &sendaddr.sin_addr);

    sendto(sockfd, pkt, sizeof(pkt), 0, (struct sockaddr*)&sendaddr, sizeof(sendaddr));

    exit_code = 0;

error:
    close(sockfd);

    return(exit_code);
#endif
}
