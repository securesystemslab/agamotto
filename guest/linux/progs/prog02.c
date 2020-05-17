#include <stdio.h>
#include <stdlib.h>
#include <string.h> // strcpy, memset(), and memcpy()
#include <unistd.h> // close()

#include <arpa/inet.h> // inet_pton() and inet_ntop()
//#include <bits/ioctls.h> // defines values for argument "request" of ioctl.
#include <linux/if_ether.h> // ETH_P_ARP = 0x0806
#include <linux/if_packet.h> // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>
#include <net/if.h> // struct ifreq
#include <netdb.h> // struct addrinfo
#include <netinet/in.h> // IPPROTO_RAW, INET_ADDRSTRLEN
#include <netinet/ip.h> // IP_MAXPACKET (which is 65535)
#include <sys/ioctl.h> // macro ioctl is defined
#include <sys/socket.h> // needed for socket()
#include <sys/types.h> // needed for socket(), uint8_t, uint16_t

#include <errno.h> // errno, perror()

#include <net/route.h>
#include <netinet/in.h>

#include <agamotto.h>

int ifup(int sockfd, char* iface_name);

/**
 * Create socket function
 */
int create_socket()
{

	int sockfd = 0;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd == -1) {
		fprintf(stderr, "Could not get socket.\n");
		return -1;
	}

	return sockfd;
}

/**
 * Generic ioctrlcall to reduce code size
 */
int generic_ioctrlcall(int sockfd, u_long* flags, struct ifreq* ifr)
{

	if (ioctl(sockfd, (long unsigned int)flags, &ifr) < 0) {
		fprintf(stderr, "ioctl: %s\n", (char*)flags);
		return -1;
	}
	return 1;
}

/**
 * Set route with metric 100
 */
int set_route(int sockfd, char* gateway_addr, struct sockaddr_in* addr)
{
	struct rtentry route;
	int err = 0;
	memset(&route, 0, sizeof(route));
	addr = (struct sockaddr_in*)&route.rt_gateway;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr(gateway_addr);
	addr = (struct sockaddr_in*)&route.rt_dst;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	addr = (struct sockaddr_in*)&route.rt_genmask;
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = inet_addr("0.0.0.0");
	route.rt_flags = RTF_UP | RTF_GATEWAY;
	route.rt_metric = 100;
	err = ioctl(sockfd, SIOCADDRT, &route);
	if ((err) < 0) {
		fprintf(stderr, "ioctl: %d\n", err);
		return -1;
	}
	return 1;
}

/**
 * Set ip function
 */
int set_ip(char* iface_name, char* ip_addr, char* gateway_addr)
{
	if (!iface_name)
		return -1;
	struct ifreq ifr;
	struct sockaddr_in sin;
	int sockfd = create_socket();

	ifup(sockfd, iface_name);
	sin.sin_family = AF_INET;

	// Convert IP from numbers and dots to binary notation
	inet_aton(ip_addr, &sin.sin_addr.s_addr);

	/* get interface name */
	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

	/* Read interface flags */
	generic_ioctrlcall(sockfd, (u_long*)"SIOCGIFFLAGS", &ifr);
	/*
    * Expected in <net/if.h> according to
    * "UNIX Network Programming".
    */
#ifdef ifr_flags
#define IRFFLAGS ifr_flags
#else /* Present on kFreeBSD */
#define IRFFLAGS ifr_flagshigh
#endif
	// If interface is down, bring it up
	if (ifr.IRFFLAGS | ~(IFF_UP)) {
		ifr.IRFFLAGS |= IFF_UP;
		generic_ioctrlcall(sockfd, (u_long*)"SIOCSIFFLAGS", &ifr);
	}
	// Set route
	//set_route(sockfd, gateway_addr    ,  &sin);
	memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
	// Set interface address
	if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
		fprintf(stderr, "Cannot set IP address. ");
		perror(ifr.ifr_name);
		return -1;
	}
#undef IRFFLAGS

	return 0;
}

int ifup(int sockfd, char* iface_name)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));

	strncpy(ifr.ifr_name, iface_name, IFNAMSIZ);

	ifr.ifr_flags |= IFF_UP;
	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
		fprintf(stderr, "ifup: ");
		perror("SIOCGIFCONF");
		close(sockfd);
		return -1;
	}
}

int main(int argc, char** argv)
{
	//while(1)
	int ret = set_ip("wlp2s0", "192.168.181.128", "192.168.181.1");
}
