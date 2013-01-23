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
#include <ctype.h>
#include <stdint.h>

#include "dump.h"

/*------------------------------------------------------------------------*/

void strdump(const void* buf, size_t len)
{
	const uint8_t* str = buf;

	if(!len)
		return;

	while(len --) {
		putchar(isprint(*str) ? *str : '.');

		++ str;
	}
}

/*------------------------------------------------------------------------*/

void hexdump8(const void* buf, size_t len)
{
	const uint8_t* data = buf;
	size_t i;

	if(!len)
		return;

	printf("%p | ", data);
	printf("%02x", *data ++);

	for(i = 1; i < len; ++ i) {
		if(i % 20 == 0)
			printf("\n%p |", data);

		printf(" %02x", *data ++);
	}

	printf("\n");
}

/*------------------------------------------------------------------------*/

void cdump8(const char* name, const void* buf, size_t len)
{
	const uint8_t* data = buf;
	size_t i;

	if(!len)
		return;

	printf("uint8_t %s[%zd] = {\n\t0x%02x", name, len, *data);

	for(i = 1; i < len; ++ i) {
		printf(i % 12 ? ", " : ",\n\t");

		printf("0x%02x", data[i]);
	}

	printf("\n};\n");
}
