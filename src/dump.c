/**
 * @file dump.c
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
#include <ctype.h>
#include <stdint.h>

#include "dump.h"

/*------------------------------------------------------------------------*/

/** length of column for cdump8() */
#define __CDUMP8_ALIGN 12

/** length of column for hexdump8() */
#define __HEXDUMP8_ALIGN 16

/** length of group for hexdump8() */
#define __HEXDUMP8_GROUP 4

/*------------------------------------------------------------------------*/

void strdump(const void* buf, size_t len)
{
	const uint8_t* str = buf;

	if(!len) {
		return;
	}

	while(len --) {
		putchar(isprint(*str) ? *str : '.');

		++ str;
	}
}

/*------------------------------------------------------------------------*/

void hexdump8(const void* buf, size_t len)
{
	const uint8_t* data = buf;
	size_t i, spaces, tail;

	if(!len) {
		return;
	}

	for(i = 0; i < len; ++ i) {
		/* print data like a string */
		if(i % __HEXDUMP8_ALIGN == 0) {
			if(i) {
				printf(" | ");
				strdump(data - __HEXDUMP8_ALIGN, __HEXDUMP8_ALIGN);
				putchar('\n');
			}

			printf("%p |", data);
		}

		/* group by __HEXDUMP8_GROUP bytes */
		if(i % __HEXDUMP8_GROUP == 0) {
			putchar(' ');
		}

		printf("%02x", *data ++);
	}

	/* calculate size of align */
	spaces = len;
	tail = len % __HEXDUMP8_ALIGN;

	if(tail) {
		spaces += __HEXDUMP8_ALIGN - tail;
	} else {
		tail = __HEXDUMP8_ALIGN;
	}

	/* print spaces to align tail */
	while(i < spaces) {
		/* group by __HEXDUMP8_GROUP byte */
		if(i % __HEXDUMP8_GROUP == 0) {
			putchar(' ');
		}

		++ i;

		printf("  ");
	}

	/* print data tail */
	printf(" | ");
	strdump(data - tail, tail);
	putchar('\n');
}

/*------------------------------------------------------------------------*/

void cdump8(const char* name, const void* buf, size_t len)
{
	const uint8_t* data = buf;
	size_t i;

	if(!len) {
		return;
	}

	printf("uint8_t %s[%zd] = {\n\t0x%02x", name, len, *data ++);

	for(i = 1; i < len; ++ i) {
		printf(i % __CDUMP8_ALIGN ? ", " : ",\n\t");

		printf("0x%02x", *data ++);
	}

	printf("\n};\n");
}
