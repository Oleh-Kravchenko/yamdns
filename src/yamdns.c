/**
 * @file yamdns.c
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

#include <yamdns/yamdns.h>

#include "dump.h"

/*------------------------------------------------------------------------*/

static const char* mdns_str_type(mdns_record_t rec)
{
	switch(rec)
	{
		case MDNS_RECORD_A:
			return("A");

		case MDNS_RECORD_PTR:
			return("PTR");

		case MDNS_RECORD_TEXT:
			return("TEXT");

		case MDNS_RECORD_AAAA:
			return("AAAA");

		case MDNS_RECORD_SRV:
			return("SRV");

		default:
			return("Unknown");
	}
}

/*------------------------------------------------------------------------*/

static const void* mdns_name_unpack(const uint8_t* buf, const uint8_t* pos, const uint8_t* end, char* name, size_t len)
{
	char label[MDNS_MAX_LABEL_NAME];
	const uint8_t* cur;

	*name = 0;
	cur = pos;

	/* parse name */
	while(*cur && cur < end) {
		/* check if label is compressed */
		if((*cur & 0xc0) == 0xc0) {
			uint16_t index;

			/* calculate index of label */
			index = ntohs(*(uint16_t*)cur) & 0x3fff;

			/* check for invalid index */
			if(&buf[index] >= cur || &buf[index] >= pos) {
				return(NULL);
			}

			cur = &buf[index];
		}

		/* check length of label */
		if(*cur > 0x3f) {
			/* invalid length, failed */
			return(NULL);
		}

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

		if(cur > pos) {
			/* save position of parse process */
			pos = cur;
		}
	}

	if(cur > end) {
		return(NULL);
	}

	if(cur == end) {
		return(cur);
	}

	if(cur < pos) {
		/* name was compressed, skip index (two octets) */
		return(pos + 2);
	}

	/* skip last 'dot' */
	return(cur + 1);
}


/*------------------------------------------------------------------------*/

static void* mdns_name_pack(void* buf, size_t* len, const char* name)
{
	const char* label;
	size_t namelen;
	uint8_t* pos;

	/* TODO: implement compress */
	pos = buf;
	namelen = strlen(name) + 1;

	/* check for buffer length */
	if(namelen > *len) {
		return(NULL);
	}

	/* update length, descrement length of buffer */
	*len -= namelen;

	while((label = strchr(name, '.'))) {
		/* put label length */
		*pos = label - name;

		/* put label */
		memcpy(pos + 1, name, *pos);

		/* moving next */
		name = label + 1;
		pos += *pos + 1;
	}

	/* if user forget about last dot */
	if(*name) {
		*pos = namelen - ((uintptr_t)pos - (uintptr_t)buf + 1);

		/* put label */
		memcpy(pos + 1, name, *pos);

		/* moving next */
		pos += *pos + 1;
	}

	/* terminate packed name by 0 */
	*pos ++ = 0;

	return(pos);
}

/*------------------------------------------------------------------------*/

static void mdns_packet_current(void** buf, size_t* len)
{
	size_t cur;

	/* calculate end position in packet */
	cur = mdns_packet_size(*buf, *len);
	*buf = (void*)((uintptr_t)*buf + cur);
	len -= cur;
}

/*------------------------------------------------------------------------*/

int mdns_packet_init(void* buf, size_t len)
{
	mdns_hdr_t* hdr = buf;

	if(len < sizeof(*hdr)) {
		return(-1);
	}

	memset(hdr, 0, sizeof(*hdr));

	return(0);
}

/*------------------------------------------------------------------------*/

size_t mdns_packet_process(const void* buf, size_t len, mdns_handlers_t* handlers, void* ctx)
{
	const mdns_hdr_t* hdr;
	const mdns_query_hdr_t* query_hdr;
	const mdns_answer_hdr_t* answer_hdr;
	const uint8_t *pos, *cur, *end;
	char root[MDNS_MAX_NAME];
	mdns_record_srv_t* srv;
	int i;

	pos = buf;
	hdr = buf;
	end = pos + len;

	/* length of packet is to small for mDNS*/
	if(len < sizeof(*hdr)) {
		goto err;
	}

	pos += sizeof(mdns_hdr_t);

	/* check for range */
	if(pos >= end) {
		goto err;
	}

	/* check for queries */
	if(hdr->qd_cnt) {
		/* parse queries */
		for(i = ntohs(hdr->qd_cnt); i > 0; -- i) {
			pos = mdns_name_unpack(buf, pos, end, root, sizeof(root));

			/* if failed to checkout root name from labels */
			if(!pos) {
				/* packet is invalid */
				goto err;
			}

			query_hdr = (mdns_query_hdr_t*)pos;

			/* moving next */
			pos += sizeof(mdns_query_hdr_t);

			/* check for range */
			if(pos > end) {
				goto err;
			}

			/* call query handler */
			if(handlers->q) {
				handlers->q(ctx, query_hdr, root);
			}
		}
	}

	/* check for answers */
	if(hdr->an_cnt) {
		/* parse answers */
		for(i = ntohs(hdr->an_cnt); i > 0; -- i) {
			pos = mdns_name_unpack(buf, pos, end, root, sizeof(root));

			/* if failed to checkout owner from labels */
			if(!pos) {
				/* packet is invalid */
				goto err;
			}

			answer_hdr = (mdns_answer_hdr_t*)pos;

			/* moving next */
			pos += sizeof(mdns_answer_hdr_t);

			/* check for range */
			if(pos > end) {
				goto err;
			}

			/* parse rdata */
			switch(ntohs(answer_hdr->a_type)) {
				case MDNS_RECORD_A: {
					cur = pos + sizeof(struct in_addr);

					/* check for range */
					if(cur > end) {
						goto err;
					}

					/* call a type handler */
					if(handlers->a) {
						handlers->a(ctx, answer_hdr, root, (struct in_addr*)pos);
					}

					break;
				}

				case MDNS_RECORD_TEXT: {
					char text[MDNS_MAX_NAME];

					cur = mdns_name_unpack(buf, pos, pos + ntohs(answer_hdr->rd_len), text, sizeof(text));

					/* check for range */
					if(!cur || cur > end) {
						goto err;
					}

					/* call text handler */
					if(handlers->text) {
						handlers->text(ctx, answer_hdr, root, text);
					}

					break;
				}

				case MDNS_RECORD_PTR: {
					char target[MDNS_MAX_NAME];

					cur = mdns_name_unpack(buf, pos, pos + ntohs(answer_hdr->rd_len), target, sizeof(target));

					/* check for range */
					if(!cur || cur > end) {
						goto err;
					}

					/* call pointer handler */
					if(handlers->ptr) {
						handlers->ptr(ctx, answer_hdr, root, target);
					}

					break;
				}

				case MDNS_RECORD_SRV: {
					char service[MDNS_MAX_NAME];

					srv = (mdns_record_srv_t*)pos;
					cur = pos + sizeof(mdns_record_srv_t);

					/* check for range */
					if(cur > end) {
						goto err;
					}

					cur = mdns_name_unpack(buf, (void*)&srv->name, pos + ntohs(answer_hdr->rd_len), service, sizeof(service));

					/* check for range */
					if(!cur || cur > end) {
						goto err;
					}

					/* call service handler */
					if(handlers->srv) {
						handlers->srv(ctx, answer_hdr, root, srv, service);
					}

					break;
				}

				default: {
					cur = pos + ntohs(answer_hdr->rd_len);

					/* call raw handler */
					if(handlers->raw) {
						handlers->raw(ctx, answer_hdr, root, pos, ntohs(answer_hdr->rd_len));
					}

					break;
				}
			}

			pos += ntohs(answer_hdr->rd_len);

			/* check for range */
			if(pos != cur || pos > end) {
				goto err;
			}
		}
	}

err:
	return((uintptr_t)pos - (uintptr_t)buf);
}

/*------------------------------------------------------------------------*/

static void mdns_dump_query_handler(void* ctx, const mdns_query_hdr_t* h, const char* root)
{
	/* display query header */
	printf("[Q] class: 0x%04x type: %s (0x%04x) [%s]\n",
		ntohs(h->q_class), mdns_str_type(ntohs(h->q_type)), ntohs(h->q_type), root
	);
}

static void mdns_dump_answer(const mdns_answer_hdr_t* h, const char* root)
{
	/* display answer header */
	printf("[A] class: 0x%04x type: %s (0x%04x) ttl: %d len: %d [%s] [",
		ntohs(h->a_class), mdns_str_type(ntohs(h->a_type)),
		ntohs(h->a_type), ntohl(h->a_ttl), ntohs(h->rd_len), root
	);
}

static void mdns_dump_answer_handler_a(void* ctx, const mdns_answer_hdr_t* h, const char* root, struct in_addr* in)
{
	mdns_dump_answer(h, root);

	/* IPv4 address */
	printf("%s]\n", inet_ntoa(*in));
}

static void mdns_dump_answer_handler_ptr_text(void* ctx, const mdns_answer_hdr_t* h, const char* root, const char* ptr)
{
	mdns_dump_answer(h, root);

	/* text or pointer */
	printf("%s]\n", ptr);
}

static void mdns_dump_answer_handler_srv(void* ctx, const mdns_answer_hdr_t* h, const char* root, mdns_record_srv_t* srv, const char* target)
{
	mdns_dump_answer(h, root);

	/* dump service */
	printf("priority: %d weight: %d port: %d target: \"%s\"]\n",
		ntohs(srv->priority), ntohs(srv->weight), ntohs(srv->port), target
	);
}

static void mdns_dump_answer_handler_raw(void* ctx, const mdns_answer_hdr_t* h, const char* root, const void* buf, size_t len)
{
	mdns_dump_answer(h, root);

	/* unknown type, just print printable symbols */
	strdump(buf, len);
	printf("]\n");
}

void mdns_packet_dump(const void* buf, size_t len)
{
	const mdns_hdr_t* hdr = buf;
	size_t ret;

	mdns_handlers_t handlers = {
		.q = mdns_dump_query_handler,
		.a = mdns_dump_answer_handler_a,
		.ptr = mdns_dump_answer_handler_ptr_text,
		.text = mdns_dump_answer_handler_ptr_text,
		.srv = mdns_dump_answer_handler_srv,
		.raw = mdns_dump_answer_handler_raw,
	};

	if(sizeof(*hdr) > len) {
		ret = 0;
		goto err;
	}

	/* print header */
	printf("     id: 0x%04x\n", ntohs(hdr->id));
	printf("  flags: 0x%04x\n", ntohs(hdr->flags));
	printf("queries: 0x%04x\n", ntohs(hdr->qd_cnt));
	printf("answers: 0x%04x\n", ntohs(hdr->an_cnt));
	printf("auth_rr: 0x%04x\n", ntohs(hdr->ns_cnt));
	printf(" add_rr: 0x%04x\n", ntohs(hdr->ar_cnt));

	/* process mdns packet */
	ret = mdns_packet_process(buf, len, &handlers, NULL);
	if(ret != len) {
		goto err;
	}

	return;

err:
	printf("failed to parse packet on offset 0x%zx (%p):\n",
		ret, (uint8_t*)buf + ret
	);

	hexdump8(buf, len);
}

/*------------------------------------------------------------------------*/

size_t mdns_packet_size(const void* buf, size_t len)
{
	mdns_handlers_t handlers = {0};

	/* calculate packet size by processing */
	return(mdns_packet_process(buf, len, &handlers, NULL));
}

/*------------------------------------------------------------------------*/

int mdns_packet_add_query_in(void* buf, size_t len, uint16_t q_type, const char* name)
{
	mdns_hdr_t* hdr = buf;
	mdns_query_hdr_t* query_hdr;

	/* we can't add query if another data present */
	if(hdr->an_cnt || hdr->ns_cnt || hdr->ar_cnt) {
		return(-1);
	}

	/* calculate end position in packet */
	mdns_packet_current(&buf, &len);

	/* pack name */
	if(!(buf = mdns_name_pack(buf, &len, name))) {
		return(-1);
	}

	/* check free space for query header */
	if(sizeof(*query_hdr) > len) {
		return(-1);
	}

	/* fill query header */
	query_hdr = (mdns_query_hdr_t*)buf;
	query_hdr->q_class = htons(MDNS_CLASS_IN);
	query_hdr->q_type = htons(q_type);
	len -= sizeof(*query_hdr);

	/* increment query count */
	hdr->flags = htons(ntohs(hdr->flags) | MDNS_FLAG_QUERY);
	hdr->qd_cnt = htons(ntohs(hdr->qd_cnt) + 1);

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_packet_add_answer_in(void* buf, size_t len, uint32_t ttl, const char* root, struct in_addr in)
{
	mdns_hdr_t* hdr = buf;
	mdns_answer_hdr_t* answer_hdr;

	/* we can't add query if another data present */
	if(hdr->ns_cnt || hdr->ar_cnt) {
		return(-1);
	}

	/* calculate end position in packet */
	mdns_packet_current(&buf, &len);

	/* pack root name */
	if(!(buf = mdns_name_pack(buf, &len, root))) {
		return(-1);
	}

	/* check free space for answer header */
	if(sizeof(*answer_hdr) > len) {
		return(-1);
	}

	/* fill answer header */
	answer_hdr = (mdns_answer_hdr_t*)buf;
	answer_hdr->a_class = htons(MDNS_CLASS_IN);
	answer_hdr->a_type = htons(MDNS_RECORD_A);
	answer_hdr->a_ttl = htonl(ttl);
	answer_hdr->rd_len = htons(sizeof(in));
	buf = (void*)((uintptr_t)buf + sizeof(*answer_hdr));
	len -= sizeof(*answer_hdr);

	/* check free space for in addr */
	if(sizeof(in) > len) {
		return(-1);
	}

	/* put in addr */
	memcpy(buf, &in, sizeof(in));
	len -= sizeof(in);

	/* increment answer count */
	hdr->flags = htons(ntohs(hdr->flags) | MDNS_FLAG_ANSWER);
	hdr->an_cnt = htons(ntohs(hdr->an_cnt) + 1);

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_packet_add_answer_in_ptr(void* buf, size_t len, uint32_t ttl, const char* root, const char* name)
{
	mdns_hdr_t* hdr = buf;
	mdns_answer_hdr_t* answer_hdr;

	/* we can't add answer if another data present */
	if(hdr->ns_cnt || hdr->ar_cnt) {
		return(-1);
	}

	/* calculate end position in packet */
	mdns_packet_current(&buf, &len);

	/* pack root name */
	if(!(buf = mdns_name_pack(buf, &len, root))) {
		return(-1);
	}

	/* check free space for answer header */
	if(sizeof(*answer_hdr) > len) {
		return(-1);
	}

	/* fill answer header */
	answer_hdr = (mdns_answer_hdr_t*)buf;
	answer_hdr->a_class = htons(MDNS_CLASS_IN);
	answer_hdr->a_type = htons(MDNS_RECORD_PTR);
	answer_hdr->a_ttl = htonl(ttl);
	answer_hdr->rd_len = htons(strlen(name) + 1); /* TODO: implement compress */
	buf = (void*)((uintptr_t)buf + sizeof(*answer_hdr));
	len -= sizeof(*answer_hdr);

	/* put in pointer name */
	if(!(buf = mdns_name_pack(buf, &len, name))) {
		return(-1);
	}

	/* increment answer count */
	hdr->flags = htons(ntohs(hdr->flags) | MDNS_FLAG_ANSWER);
	hdr->an_cnt = htons(ntohs(hdr->an_cnt) + 1);

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_packet_add_answer_in_text(void* buf, size_t len, uint32_t ttl, const char* root, const char* text)
{
	mdns_hdr_t* hdr = buf;
	mdns_answer_hdr_t* answer_hdr;

	/* we can't add answer if another data present */
	if(hdr->ns_cnt || hdr->ar_cnt) {
		return(-1);
	}

	/* calculate end position in packet */
	mdns_packet_current(&buf, &len);

	/* pack root name */
	if(!(buf = mdns_name_pack(buf, &len, root))) {
		return(-1);
	}

	/* check free space for answer header */
	if(sizeof(*answer_hdr) > len) {
		return(-1);
	}

	/* fill answer header */
	answer_hdr = (mdns_answer_hdr_t*)buf;
	answer_hdr->a_class = htons(MDNS_CLASS_IN);
	answer_hdr->a_type = htons(MDNS_RECORD_TEXT);
	answer_hdr->a_ttl = htonl(ttl);
	answer_hdr->rd_len = htons(strlen(text) + 1); /* TODO: implement compress */
	buf = (void*)((uintptr_t)buf + sizeof(*answer_hdr));
	len -= sizeof(*answer_hdr);

	/* put in text name */
	if(!(buf = mdns_name_pack(buf, &len, text))) {
		return(-1);
	}

	/* increment answer count */
	hdr->flags = htons(ntohs(hdr->flags) | MDNS_FLAG_ANSWER);
	hdr->an_cnt = htons(ntohs(hdr->an_cnt) + 1);

	return(0);
}

/*------------------------------------------------------------------------*/

int mdns_packet_add_answer_in_srv(void* buf, size_t len, uint32_t ttl, const char* root, uint16_t prio, uint16_t weight, uint16_t port, const char* name)
{
	mdns_hdr_t* hdr = buf;
	mdns_answer_hdr_t* answer_hdr;
	mdns_record_srv_t* srv;

	/* we can't add answer if another data present */
	if(hdr->ns_cnt || hdr->ar_cnt) {
		return(-1);
	}

	/* calculate end position in packet */
	mdns_packet_current(&buf, &len);

	/* pack root name */
	if(!(buf = mdns_name_pack(buf, &len, root))) {
		return(-1);
	}

	/* check free space for answer header */
	if(sizeof(*answer_hdr) > len) {
		return(-1);
	}

	/* fill answer header */
	answer_hdr = (mdns_answer_hdr_t*)buf;
	answer_hdr->a_class = htons(MDNS_CLASS_IN);
	answer_hdr->a_type = htons(MDNS_RECORD_SRV);
	answer_hdr->a_ttl = htonl(ttl);
	answer_hdr->rd_len = htons(sizeof(*srv) + strlen(name) + 1); /* TODO: implement compress */
	buf = (void*)((uintptr_t)buf + sizeof(*answer_hdr));
	len -= sizeof(*answer_hdr);

	/* fill service record */
	srv = (mdns_record_srv_t*)buf;
	srv->priority = htons(prio);
	srv->weight = htons(weight);
	srv->port = htons(port);
	buf = (void*)((uintptr_t)buf + sizeof(*srv));
	len -= sizeof(*srv);

	/* put in service name */
	if(!(buf = mdns_name_pack(buf, &len, name))) {
		return(-1);
	}

	/* increment answer count */
	hdr->flags = htons(ntohs(hdr->flags) | MDNS_FLAG_ANSWER);
	hdr->an_cnt = htons(ntohs(hdr->an_cnt) + 1);

	return(0);
}
