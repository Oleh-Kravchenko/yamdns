#ifndef __MDNS_NETWORK_H
#define __MDNS_NETWORK_H

#include <arpa/inet.h>

int mdns_socket(struct in_addr mcaddr, struct in_addr ifaddr, uint16_t port, int ttl, int timeout);

int mdns_close(struct in_addr mcaddr, struct in_addr ifaddr, int sockfd);

#endif /* __MDNS_NETWORK_H */
