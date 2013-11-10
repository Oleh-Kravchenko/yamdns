#ifndef __MDNS_NETWORK_H
#define __MDNS_NETWORK_H

#include <arpa/inet.h>

int mdns_socket(struct ip_mreq* mreq, uint16_t port, int ttl, int timeout);

int mdns_close(struct ip_mreq* mreq, int sockfd);

#endif /* __MDNS_NETWORK_H */
