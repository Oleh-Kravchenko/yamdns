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

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "dump.h"
#include "mdns.h"

/*------------------------------------------------------------------------*/

#define CONV16_N2H(x) do { x = ntohs(x); } while(0);

#define CONV32_N2H(x) do { x = ntohl(x); } while(0);

#define CONV16_H2N(x) do { x = htons(x); } while(0);

#define CONV32_H2N(x) do { x = htonl(x); } while(0);

/*------------------------------------------------------------------------*/

static const void* mdns_name_unpack(const uint8_t* buf, const uint8_t* pos, const uint8_t* end, char* name, size_t len)
{
	const uint8_t* cur = pos;
	char label[0x40];

	*name = 0;

	/* parse name */
	while(*cur && cur < end) {
		/* check if label is compressed */
		if((*cur & 0xc0) == 0xc0) {
			uint16_t index;
			
			/* calculate index of label */
			index = ntohs(*(uint16_t*)cur) & 0x3fff;

			/* check for invalid index */
			if(&buf[index] >= cur || &buf[index] >= pos)
				return(NULL);

			cur = &buf[index];
		}

		/* check length of label */
		if(*cur > 0x3f)
			/* invalid length, failed */
			return(NULL);

		/* safety copying label */
		memcpy(label, cur + 1, *cur);
		label[*cur] = 0;

		/* add label */
		strncat(name, label, len - 1);
		name[len - 1] = 0;

		/* dot */
		strncat(name, ".", len - 1);
		name[len - 1] = 0;

		/* next chunk name */
		cur += *cur + 1;

		if(cur > pos)
			/* save position of parse process */
			pos = cur;
	}

	if(cur > end)
		return(NULL);

	if(cur < pos)
		/* name was compressed, skip index (two octets) */
		return(pos + 2);

	/* skip last 'dot' */
	return(cur + 1);

}

/*------------------------------------------------------------------------*/

#if 0
static const void* mdns_name_pack(const uint8_t* buf, const uint8_t* pos, const uint8_t* end, char* name, size_t len);
#endif /* TODO */

/*------------------------------------------------------------------------*/

mdns_pkt_t* mdns_pkt_unpack(const void* buf, size_t len)
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

	/* initialize pointers */
	res->queries = NULL;
	res->answers = NULL;

	memcpy(&res->hdr, buf, sizeof(mdns_hdr_t));

	/* convert header fields to host byte order */
	CONV16_N2H(res->hdr.id);
	CONV16_N2H(res->hdr.flags);
	CONV16_N2H(res->hdr.qd_cnt);
	CONV16_N2H(res->hdr.an_cnt);
	CONV16_N2H(res->hdr.ns_cnt);
	CONV16_N2H(res->hdr.ar_cnt);

	pos += sizeof(mdns_hdr_t);

	/* check for range */
	if(pos >= end)
		goto err_queries;

	/* check for queries */
	if(res->hdr.qd_cnt) {
		if(!(res->queries = malloc(sizeof(mdns_query_t) * res->hdr.qd_cnt)))
			goto err;

		/* parse queries */
		for(i = 0; i < res->hdr.qd_cnt; ++ i) {
			pos = mdns_name_unpack(buf, pos, end,
				res->queries[i].name,
				sizeof(res->queries[i].name)
			);

			/* if failed to checkout name from labels */
			if(!pos)
				/* packet is invalid */
				goto err_queries;

			/* process query header */
			memcpy(&res->queries[i].hdr, pos, sizeof(mdns_query_hdr_t));
			CONV16_N2H(res->queries[i].hdr.q_class);
			CONV16_N2H(res->queries[i].hdr.q_type);

			/* moving next */
			pos += sizeof(mdns_query_hdr_t);

			/* check for range */
			if(pos > end)
				goto err_queries;
		}
	}

	/* check for answers */
	if(res->hdr.an_cnt) {
		if(!(res->answers = malloc(sizeof(mdns_answer_t) * res->hdr.an_cnt)))
			goto err_queries;

		/* parse answers */
		for(i = 0; i < res->hdr.an_cnt; ++ i) {
			pos = mdns_name_unpack(buf, pos, end,
				res->answers[i].owner,
				sizeof(res->answers[i].owner)
			);

			/* if failed to checkout owner from labels */
			if(!pos)
				/* packet is invalid */
				goto err_answers;

			/* process answer header */
			memcpy(&res->answers[i].hdr, pos, sizeof(mdns_answer_hdr_t));
			CONV16_N2H(res->answers[i].hdr.a_type);
			CONV16_N2H(res->answers[i].hdr.a_class);
			CONV32_N2H(res->answers[i].hdr.a_ttl);
			CONV16_N2H(res->answers[i].hdr.rd_len);

			/* moving next */
			pos += sizeof(mdns_answer_hdr_t);

			/* check for range */
			if(pos >= end)
				goto err_answers;

			/* parse rdata */
			switch(res->answers[i].hdr.a_type) {
				case MDNS_QUERY_TYPE_A:
					if(sizeof(res->answers[i].rdata.in) != res->answers[i].hdr.rd_len)
						/* invalid rdata length */
						goto err_answers;

					memcpy(&res->answers[i].rdata.in, pos, res->answers[i].hdr.rd_len);
					break;

				case MDNS_QUERY_TYPE_PTR:
					if(!mdns_name_unpack(
							buf, pos, end,
							res->answers[i].rdata.name,
							sizeof(res->answers[i].rdata.name)
						)
					)
						goto err_answers;
					break;

				default:
					if(sizeof(res->answers[i].rdata.raw) < res->answers[i].hdr.rd_len)
						/* invalid rdata length */
						goto err_answers;

					memcpy(&res->answers[i].rdata.raw, pos, res->answers[i].hdr.rd_len);
					break;
			}

			pos += res->answers[i].hdr.rd_len;

			/* check for range */
			if(pos > end)
				goto err_answers;
		}
	}

	return(res);

err_answers:
	free(res->answers);

err_queries:
	free(res->queries);

err:
	free(res);

	return(NULL);
}

/*------------------------------------------------------------------------*/

int mdns_pkt_pack(mdns_pkt_t* pkt, void* buf, size_t* len)
{
	size_t raw_len = sizeof(mdns_hdr_t);
	mdns_hdr_t* hdr = buf;
	int i;

	if(*len < raw_len)
		return(-1);

	/* TODO: not supported */
	if(hdr->ns_cnt || hdr->ar_cnt)
		return(-1);

	memcpy(hdr, &pkt->hdr, sizeof(mdns_hdr_t));

	for(i = 0; i < hdr->qd_cnt; ++ i) {
	}

	for(i = 0; i < hdr->an_cnt; ++ i) {
	}

	/* convert header fields to network byte order */
	CONV16_H2N(hdr->id);
	CONV16_H2N(hdr->flags);
	CONV16_H2N(hdr->qd_cnt);
	CONV16_H2N(hdr->an_cnt);
	CONV16_H2N(hdr->ns_cnt);
	CONV16_H2N(hdr->ar_cnt);

	/* packed length of packet */
	*len = raw_len;

	return(0);
}

/*------------------------------------------------------------------------*/

void mdns_pkt_destroy(mdns_pkt_t* pkt)
{
	if(!pkt)
		return;

	free(pkt->answers);
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

	if(pkt->hdr.an_cnt) {
		printf("answers = %d [\n", pkt->hdr.an_cnt);

		/* printing queries */
		for(i = 0; i < pkt->hdr.an_cnt; ++ i) {
			printf("\ttype: 0x%04x q_class: 0x%04x owner: %s rdata(%d): ",
				pkt->answers[i].hdr.a_type,
				pkt->answers[i].hdr.a_class,
				pkt->answers[i].owner,
				pkt->answers[i].hdr.rd_len
			);

			switch(pkt->answers[i].hdr.a_type) {
				case MDNS_QUERY_TYPE_A:
					puts(inet_ntoa(pkt->answers[i].rdata.in));
					break;

				case MDNS_QUERY_TYPE_PTR:
					puts(pkt->answers[i].rdata.name);
					break;

				default:
					strdump(pkt->answers[i].rdata.name, pkt->answers[i].hdr.rd_len);
					putchar('\n');
					break;
			}
		}

		printf("]\n");
	}

	puts(">>");
}
