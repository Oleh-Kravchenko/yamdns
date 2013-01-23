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

#ifndef __DUMP_H
#define __DUMP_H

void strdump(const void* str, size_t len);

/**
 * @brief print hexdump
 * @param buf pointer to data
 * @param len length of data
 */
void hexdump8(const void* buf, size_t len);

/**
 * @brief print data like a C array
 * @param name name of C array
 * @param buf pointer to data
 * @param len length of data
 **/
void cdump8(const char* name, const void* buf, size_t len);

#endif /* __DUMP_H */
