#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*------------------------------------------------------------------------*/

int mdns_socket(struct in_addr mcaddr, struct in_addr ifaddr, uint16_t port, int ttl, int timeout)
{
	struct sockaddr_in saaddr;
	struct ip_mreq mreq;
	int sockfd;

	/* mDNS multicasting address */
	mreq.imr_multiaddr = mcaddr;
	mreq.imr_interface = ifaddr;

	/* create UDP socket for multicasting */
	if((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		return(-1);
	}

	memset(&saaddr, 0, sizeof(saaddr));
	saaddr.sin_family = AF_INET;
	saaddr.sin_port = htons(port);

	if(bind(sockfd, (struct sockaddr*)&saaddr, sizeof(saaddr)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_LOOP, &(uint8_t){0}, sizeof(uint8_t)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&ifaddr, sizeof(ifaddr)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &(struct timeval) {timeout, 0}, sizeof(struct timeval)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
		goto error;
	}

	if(setsockopt(sockfd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		goto error;
	}

	return(sockfd);

error:
	close(sockfd);

	return(-1);
}

/*------------------------------------------------------------------------*/

int mdns_close(struct in_addr mcaddr, struct in_addr ifaddr, int sockfd)
{
	struct ip_mreq mreq;

	mreq.imr_multiaddr = mcaddr;
	mreq.imr_interface = ifaddr;

	if(setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		return(-1);
	}

	return(close(sockfd));
}
