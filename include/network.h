#ifndef __MDNS_NETWORK_H
#define __MDNS_NETWORK_H

#include <arpa/inet.h>

/**
 * @brief create and bind socket for mdns
 * @param ifaddr interface address
 * @param timeout default timeout for socket read ops
 * @return zero, if successful
 */
int mdns_socket(struct in_addr ifaddr, int timeout);

/**
 * @brief close mdns socket
 * @param ifaddr interface address
 * @param sockfd socket desctriptor
 * @return zero, if successful
 */
int mdns_close(struct in_addr ifaddr, int sockfd);

#endif /* __MDNS_NETWORK_H */
