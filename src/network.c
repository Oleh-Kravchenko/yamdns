#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/*------------------------------------------------------------------------*/

int mdns_socket(struct ip_mreq* mreq, uint16_t port, int ttl, int timeout)
{
	struct sockaddr_in saaddr;
	int sockfd;

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

	/* send multicasting from interface */
	if(setsockopt(sockfd, IPPROTO_IP, IP_MULTICAST_IF, (char*)&mreq->imr_interface, sizeof(mreq->imr_interface)) == -1) {
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

int mdns_close(struct ip_mreq* mreq, int sockfd)
{
	if(setsockopt(sockfd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (char*)&mreq, sizeof(mreq)) == -1) {
		/* TODO print warning? */;
	}

	return(close(sockfd));
}
