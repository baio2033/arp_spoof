#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <pthread.h>
#include <stdint.h>
#include <pcap.h>


#define ETHER_ADDR_LEN 6
#define ETHERNET 1
#define ETH_ARP 0x0806
#define ETHERTYPE_IP 0x0800



/* Ethernet header */
struct __attribute__((packed)) etherhdr {
	u_char dst[ETHER_ADDR_LEN];
	u_char src[ETHER_ADDR_LEN];
	u_int16_t ether_type; // ARP : 0x0806
};

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1   /* ARP Request             */
#define ARP_REPLY 2     /* ARP Reply               */
struct __attribute__((packed)) arphdr {
    u_int16_t htype;    /* Hardware Type           */
    u_int16_t ptype;    /* Protocol Type           */
    u_char hlen;        /* Hardware Address Length */
    u_char plen;        /* Protocol Address Length */
    u_int16_t oper;     /* Operation Code          */
    u_char sha[6];      /* Sender hardware address */
    u_char spa[4];      /* Sender IP address       */
    u_char tha[6];      /* Target hardware address */
    u_char tpa[4];      /* Target IP address       */
};

struct __attribute__((packed)) iphdr{
    u_char  ip_v:4,         /* version */
        ip_hl:4;        /* header length */
    u_char  ip_tos;         /* type of service */
    short   ip_len;         /* total length */
    u_short ip_id;          /* identification */
    short   ip_off;         /* fragment offset field */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
    u_char  ip_ttl;         /* time to live */
    u_char  ip_p;           /* protocol */
    u_short ip_sum;         /* checksum */
    struct  in_addr ip_src,ip_dst;  /* source and dest address */
};

struct __attribute__((packed)) icmphdr{
  u_int8_t type;        /* message type */
  u_int8_t code;        /* type sub-code */
  u_int16_t checksum;
  union
  {
    struct
    {
      u_int16_t id;
      u_int16_t sequence;
    } echo;         /* echo datagram */
    u_int32_t   gateway;    /* gateway address */
    struct
    {
      u_int16_t __unused;
      u_int16_t mtu;
    } frag;         /* path mtu discovery */
  } un;
};

struct __attribute__((packed)) argu_list{
	pcap_t *handle;
	u_char *my_mac;
	u_char *sender_mac;
	struct in_addr *senderIP;
	struct in_addr *targetIP;
};

typedef struct __attribute__((packed)) _argu{
    pcap_t *handle;
    struct in_addr *senderIP;
    u_char *sender_mac;
    struct in_addr *targetIP;
    u_char *target_mac;
}argu_group;

u_char* GetSvrMacAddress(char* dev_name)
{
    int         mib[6], len;
    char            *buf;
    unsigned char       *ptr;
    struct if_msghdr    *ifm;
    struct sockaddr_dl  *sdl;
    char *dev;

    dev = dev_name;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(dev)) == 0) {
        perror("if_nametoindex error");
        exit(2);
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        perror("sysctl 1 error");
        exit(3);
    }

    if ((buf = malloc(len)) == NULL) {
        perror("malloc error");
        exit(4);
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        perror("sysctl 2 error");
        exit(5);
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    return ptr;
}

int s_get_IPAddress(const char *ifr,u_char *out){
	int sockfd;
	struct ifreq ifrq;
	struct sockaddr_in *sin;

	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	strcpy(ifrq.ifr_name,ifr);
	if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        	perror( "ioctl() SIOCGIFADDR error");
		return -1;
	}

	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy(out,(void*)&sin->sin_addr,sizeof(sin->sin_addr));

	close(sockfd);

	return 4;
}
