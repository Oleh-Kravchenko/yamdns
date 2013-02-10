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

static void* mdns_name_pack(void* buf, size_t len, const char* name)
{
	uint8_t* pos = buf;
	const char* label;

	/* check for buffer length */
	if(strlen(name) + 1 > len)
		return(NULL);

	while((label = strchr(name, '.'))) {
		/* put label length */
		*pos = label - name;

		/* put label */
		memcpy(pos + 1, name, *pos);

		/* moving next */
		name = label + 1;
		pos += *pos + 1;
	}

	/* terminate packed name by 0 */
	*pos ++ = 0;

	return(pos);
}

/*------------------------------------------------------------------------*/

mdns_pkt_t* mdns_pkt_init(void)
{
	mdns_pkt_t* res;

	if(!(res = malloc(sizeof(*res))))
		return(NULL);

	/* initialize by 0 */
	memset(res, 0, sizeof(*res));

	return(res);
}

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

int mdns_pkt_pack(mdns_pkt_t* pkt, void* buf, size_t len)
{
	mdns_hdr_t* hdr = buf;
	mdns_query_hdr_t* q_hdr;
	mdns_answer_hdr_t* a_hdr;
	uint8_t* pos = buf;
	int i;

	if(len < sizeof(mdns_hdr_t))
		return(-1);

	/* TODO: not supported */
	if(pkt->hdr.ns_cnt || pkt->hdr.ar_cnt)
		return(-1);

	memcpy(hdr, &pkt->hdr, sizeof(mdns_hdr_t));

	/* convert header fields to network byte order */
	CONV16_H2N(hdr->id);
	CONV16_H2N(hdr->flags);
	CONV16_H2N(hdr->qd_cnt);
	CONV16_H2N(hdr->an_cnt);
	CONV16_H2N(hdr->ns_cnt);
	CONV16_H2N(hdr->ar_cnt);

	pos += sizeof(mdns_hdr_t);

	for(i = 0; i < pkt->hdr.qd_cnt; ++ i) {
		if(!(q_hdr = mdns_name_pack(pos, len - (size_t)pos - (size_t)buf, pkt->queries[i].name)))
			return(0);

		memcpy(q_hdr, &pkt->queries[i].hdr, sizeof(mdns_query_hdr_t));
		CONV16_H2N(q_hdr->q_class);
		CONV16_H2N(q_hdr->q_type);

		pos = (uint8_t*)(q_hdr + 1);
	}

	for(i = 0; i < pkt->hdr.an_cnt; ++ i) {
		if(!(a_hdr = mdns_name_pack(pos, len - (size_t)pos - (size_t)buf, pkt->answers[i].owner)))
			return(0);

		memcpy(a_hdr, &pkt->answers[i].hdr, sizeof(mdns_answer_hdr_t));
		CONV16_N2H(a_hdr->a_type);
		CONV16_N2H(a_hdr->a_class);
		CONV32_N2H(a_hdr->a_ttl);
		CONV16_N2H(a_hdr->rd_len);

		pos = (uint8_t*)(a_hdr + 1);

		switch(pkt->answers[i].hdr.a_type) {
			case MDNS_QUERY_TYPE_PTR:
				if(!mdns_name_pack(pos, len - (size_t)pos - (size_t)buf, pkt->answers[i].rdata.name))
					return(-1);
				break;

			default:
				memcpy(pos, &pkt->answers[i].rdata.raw, pkt->answers[i].hdr.rd_len);
				break;
		}

		pos += pkt->answers[i].hdr.rd_len;
	}

	/* packed length of packet */
	return((size_t)pos - (size_t)buf);
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
			printf("\ttype: 0x%04x class: 0x%04x name: %s\n",
				pkt->queries[i].hdr.q_type,
				pkt->queries[i].hdr.q_class,
				pkt->queries[i].name
			);
		}

		printf("]\n");
	}

	if(pkt->hdr.an_cnt) {
		printf("answers = %d [\n", pkt->hdr.an_cnt);

		/* printing answers */
		for(i = 0; i < pkt->hdr.an_cnt; ++ i) {
			printf("\ttype: 0x%04x class: 0x%04x ttl: %d owner: %s rdata(%d): ",
				pkt->answers[i].hdr.a_type,
				pkt->answers[i].hdr.a_class,
				pkt->answers[i].hdr.a_ttl,
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

/*------------------------------------------------------------------------*/

int mdns_pkt_add_query_in(mdns_pkt_t* pkt, uint16_t q_type, const char* name)
{
	mdns_query_t* q;

	if(!(q = realloc(pkt->queries, (pkt->hdr.qd_cnt + 1) * sizeof(*q))))
		return(-1);

	pkt->queries = q;

	/* receiving pointer to added item */
	q = pkt->queries + pkt->hdr.qd_cnt;

	/* query header */
	q->hdr.q_type = q_type;
	q->hdr.q_class = 1;

	/* query name */
	strncpy(q->name, name, sizeof(q->name) - 1);
	q->name[sizeof(q->name) - 1] = 0;

	++ pkt->hdr.qd_cnt;

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_pkt_add_answer_in(mdns_pkt_t* pkt, int32_t ttl, const char* owner, struct in_addr* in)
{
	mdns_answer_t* a;

	if(!(a = realloc(pkt->answers, (pkt->hdr.an_cnt + 1) * sizeof(*a))))
		return(-1);

	pkt->answers = a;

	/* receiving pointer to added item */
	a = pkt->answers + pkt->hdr.an_cnt;

	/* answer header */
	a->hdr.a_type = MDNS_QUERY_TYPE_A;
	a->hdr.a_class = 1;
	a->hdr.a_ttl = ttl;
	a->hdr.rd_len = sizeof(*in);

	/* answer inet address */
	a->rdata.in.s_addr = in->s_addr;

	/* owner */
	strncpy(a->owner, owner, sizeof(a->owner) - 1);
	a->owner[sizeof(a->owner) - 1] = 0;

	++ pkt->hdr.an_cnt;

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_pkt_add_answer_name(mdns_pkt_t* pkt, int32_t ttl, const char* owner, const char* name)
{
	mdns_answer_t* a;

	if(!(a = realloc(pkt->answers, (pkt->hdr.an_cnt + 1) * sizeof(*a))))
		return(-1);

	pkt->answers = a;

	/* receiving pointer to added item */
	a = pkt->answers + pkt->hdr.an_cnt;

	/* answer header */
	a->hdr.a_type = MDNS_QUERY_TYPE_PTR;
	a->hdr.a_class = 1;
	a->hdr.a_ttl = ttl;
	a->hdr.rd_len = strlen(name) + 1;

	/* answer name */
	strncpy(a->rdata.name, name, sizeof(a->rdata.name) - 1);
	a->rdata.name[sizeof(a->rdata.name) - 1] = 0;

	/* owner */
	strncpy(a->owner, owner, sizeof(a->owner) - 1);
	a->owner[sizeof(a->owner) - 1] = 0;

	++ pkt->hdr.an_cnt;

	return(0);
}
