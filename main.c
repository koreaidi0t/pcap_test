#include <pcap.h>
#include <stdio.h>
#include "libnet.h"
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>



int main(int argc, char *argv[])
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "port 80";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr *header;	/* The header that pcap gives us */
	struct libnet_ethernet_hdr* ethr;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */
	struct libnet_ipv4_hdr* ip;
	uint8_t ip_addr[16];
	struct libnet_tcp_hdr* tcp;
	/* Define the device */

	if(argc<2) {printf("Select the device!!\n");exit(0);}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
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
	while(1)
	{
	
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
	

	ethr->ether_type=ntohs(*(ethr->ether_shost+sizeof(ethr->ether_dhost)));


//	printf("ether_type : %x \n",ethr->ether_type);

	printf("===========================================================================\n");
	if(ethr->ether_type!=ETHERTYPE_IP){printf("It doesn't seem IP Packet\n");continue;}

	ip=((struct libnet_ipv4_hdr*)&packet[sizeof(struct libnet_ethernet_hdr)]);
			
	inet_ntop(AF_INET,&(ip->ip_src.s_addr),ip_addr,INET_ADDRSTRLEN);

	printf("ip.src : %s\n",ip_addr);
	
	inet_ntop(AF_INET,&(ip->ip_dst.s_addr),ip_addr,INET_ADDRSTRLEN);

	printf("ip.dst : %s\n",ip_addr);

//	printf("ip_hl test : %x\n",ip->ip_hl);

//	printf("test hlen : %d\n",(ip->ip_hl)*4);
	
	printf("===========================================================================\n");
	

	if(!(ip->ip_p==IPPROTO_TCP)) {printf("It doesn't seem tcp packet\n\n"); continue;}
	
	
	tcp=(struct libnet_tcp_hdr*)&packet[14+(ip->ip_hl)*4];
	
	
	tcp->th_sport=ntohs(tcp->th_sport);

	
	tcp->th_dport=ntohs(tcp->th_dport);
	
	
	printf("ip.sport : %d\n",tcp->th_sport);

	
	printf("ip.dport : %d\n",tcp->th_dport);
	
	
	ip->ip_len=ntohs(ip->ip_len);
	
	printf("===========================================================================\n");
//	
//	printf("ip_len : %d\n",ip->ip_len);
	
	int k=sizeof(struct libnet_ethernet_hdr)+(ip->ip_hl+tcp->th_off)*4;

	printf("DATA\n\n");	

	int size_data=ip->ip_len-(tcp->th_off+ip->ip_hl)*4;
		
	for(int i=0;i<size_data;i++)
		printf("%c",packet[k++]);
	
	printf("\n");

	
	printf("===========================================================================\n");
	
	
	printf("\n\n\n\n\n\n");
	
	}
	
	pcap_close(handle);
	
	return(0);
	
}

