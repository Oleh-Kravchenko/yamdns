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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "dump.h"
#include "mdns.h"

/*------------------------------------------------------------------------*/

#define CONV16_N2H(x) do { x = ntohs(x); } while(0);

/*------------------------------------------------------------------------*/

mdns_pkt_t* mdns_pkt_parse(const void* buf, size_t len)
{
	const uint8_t* pos = buf;
	const uint8_t* end = pos + len;
	mdns_pkt_t* res;
	int i;

	/* length of packet is to small for mDNS*/
	if(len <= sizeof(mdns_hdr_t))
		return(NULL);

	if(!(res = malloc(sizeof(*res))))
		return(NULL);

	memcpy(&res->hdr, buf, sizeof(mdns_hdr_t));

	/* convert fields to host byte order */
	CONV16_N2H(res->hdr.id);
	CONV16_N2H(res->hdr.flags);
	CONV16_N2H(res->hdr.qd_cnt);
	CONV16_N2H(res->hdr.an_cnt);
	CONV16_N2H(res->hdr.ns_cnt);
	CONV16_N2H(res->hdr.ar_cnt);

	pos += sizeof(mdns_hdr_t);

	/* check for queries */
	if(res->hdr.qd_cnt) {
		if(!(res->queries = malloc(sizeof(mdns_query_t) * res->hdr.qd_cnt)))
			goto err;

		/* parse queries */
		for(i = 0; i < res->hdr.qd_cnt; ++ i) {
			const uint8_t* c_name = pos;

			*res->queries[i].name = 0;

			/* parse name */
			while(*c_name) {
				/* check if name chunk is compressed */
				if((*c_name & 0xc0) == 0xc0) {
					/* calculate index of name chunk */
					c_name = (uint8_t*)buf + (ntohs(*(uint16_t*)c_name) & 0x3fff);

					if(c_name >= pos)
						goto err_queries;
				}

				if(*c_name > 0x3f)
					goto err_queries;

				char name_chunk[0x40];

				/* safety copying name chunk */
				memcpy(name_chunk, c_name + 1, *c_name);
				name_chunk[*c_name] = 0;

				/* next chunk name */
				c_name += *c_name + 1;

				if(c_name >= end)
					goto err_queries;

				strncat(res->queries[i].name, name_chunk, sizeof(res->queries[i].name) - 1);
				res->queries[i].name[sizeof(res->queries[i].name) - 1] = 0;

				strncat(res->queries[i].name, ".", sizeof(res->queries[i].name) - 1);
				res->queries[i].name[sizeof(res->queries[i].name) - 1] = 0;
			}

			/* moving next */
			if(c_name > pos)
				/* skip last 'dot' */
				pos = c_name + 1;
			else
				/* name was compressed */
				pos += 2;

			/* process query header */
			memcpy(&res->queries[i].hdr, pos, sizeof(mdns_query_hdr_t));
			CONV16_N2H(res->queries[i].hdr.q_class);
			CONV16_N2H(res->queries[i].hdr.q_type);

			/* moving next */
			pos += sizeof(mdns_query_hdr_t);
		}
	}

	/* check for answers */
	if(res->hdr.an_cnt) {
		if(!(res->answers = malloc(sizeof(mdns_answer_t) * res->hdr.an_cnt)))
			goto err_queries;

		/* parse answers */
		for(i = 0; i < res->hdr.an_cnt; ++ i) {
			/* TODO */
		}
	}

	return(res);

err_queries:
	free(res->queries);

err:
	free(res);

	return(NULL);
}

/*------------------------------------------------------------------------*/

void mdns_pkt_destroy(mdns_pkt_t* pkt)
{
	if(!pkt)
		return;

	free(pkt->queries);
	free(pkt);
}

/*------------------------------------------------------------------------*/

void mdns_pkt_dump(mdns_pkt_t* pkt)
{
	int i;

	puts("<<");
	printf("   id: 0x%04x\n", pkt->hdr.id);
	printf("flags: 0x%04x\n", pkt->hdr.flags);
	printf("   qd: 0x%04x\n", pkt->hdr.qd_cnt);
	printf("   an: 0x%04x\n", pkt->hdr.an_cnt);
	printf("   ns: 0x%04x\n", pkt->hdr.ns_cnt);
	printf("   ar: 0x%04x\n", pkt->hdr.ar_cnt);

	if(pkt->hdr.qd_cnt) {
		printf("queries = %d [\n", pkt->hdr.qd_cnt);

		/* printing queries */
		for(i = 0; i < pkt->hdr.qd_cnt; ++ i) {
			printf("\ttype: 0x%04x q_class: 0x%04x name: %s\n",
				pkt->queries[i].hdr.q_type,
				pkt->queries[i].hdr.q_class,
				pkt->queries[i].name
			);
		}

		printf("]\n");
	}

	puts(">>");
}
