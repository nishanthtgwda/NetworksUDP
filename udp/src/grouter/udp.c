#include "protocols.h"
#include "icmp.h"
#include "ip.h"
#include "message.h"
#include "grouter.h"
#include <slack/err.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <string.h>
#include "udp.h"
#include "queue.h"

TTLcounter=1;
int count=0;

PCB_structure process_block[1000];
traceroute_table tracert_table[1000];

//Called when a traceroute is called
void udptraceroute(uchar *ip_addr)
{
struct timezone tz;
struct timeval tv;
char buffer[]="",size=0;
int bytes_sent;
int socketid;
socketid=assign_socket(2);
tracert_table[1].socket_id=socketid;
tracert_table[1].TTL=1;
tracert_table[1].dport=33434;
gettimeofday(&tracert_table[1].tp1, &tz);
bytes_sent=outputprocessingudp(socketid,buffer,size,ip_addr,33434,1);
socketid=assign_socket(2);
tracert_table[2].socket_id=socketid;
tracert_table[2].TTL=1;
tracert_table[2].dport=33435;
gettimeofday(&tracert_table[2].tp1, &tz);
bytes_sent=outputprocessingudp(socketid,buffer,size,ip_addr,33435,1);
socketid=assign_socket(2);
tracert_table[3].socket_id=socketid;
tracert_table[3].TTL=1;
tracert_table[3].dport=33436;
gettimeofday(&tracert_table[3].tp1, &tz);
bytes_sent=outputprocessingudp(socketid,buffer,size,ip_addr,33436,1);
}


//When a destination port unreachable is received, it checks whether the addressed port is the one for the udp traceroute or any other operation
void UDPtraceroutereply(gpacket_t *in_pkt)
{
double elapsed_time;
struct timezone tz;
struct timeval tv;
int destination,i;
char tmpbuf[MAX_TMPBUF_LEN];
uchar des[4];
	ip_packet_t *ipkt = (ip_packet_t *)in_pkt->data.data;
	int iphdrlen = ipkt->ip_hdr_len *4;
	icmphdr_t *icmphdr = (icmphdr_t *)((uchar *)ipkt + iphdrlen);
	ip_packet_t *ipsecondpacket= (ip_packet_t *)((uchar *)ipkt + iphdrlen+8);
	udp_packet_t *udp_packet=(udp_packet_t *)ipsecondpacket->data;
destination=ntohs(udp_packet->udp_dst);
if(ntohs(udp_packet->udp_dst)>=33434)
{
for(i=0;i<10;i++)
{
if(tracert_table[i].dport==destination)
{
tracert_table[i].TTL=tracert_table[i].TTL+1;
gettimeofday(&tv, &tz);
elapsed_time = subTimeVal(&tv,&tracert_table[i].tp1 );
gettimeofday(&tracert_table[i].tp1, &tz);
printf("\n %s \t%6.3f ms",IP2Dot(tmpbuf,gNtohl(tmpbuf+20,ipkt->ip_src)),elapsed_time);
freesocket(tracert_table[i].socket_id);
}
}
}
else
verbose(1,"The port is unreachable");
}


//When a ttl expired is received, send back with an increased TTL, if the port is in the one used by the operation
void udpTTLexpired(uchar *ipaddr,uchar *ipsrc, int destination)
{
char tmpbuf[MAX_TMPBUF_LEN],buffer[]="";
double elapsed_time;
int i,bytes_sent,size=0;
struct timezone tz;
struct timeval tv;
for(i=0;i<10;i++)
{
if(tracert_table[i].dport==destination)
{
tracert_table[i].TTL=tracert_table[i].TTL+1;
gettimeofday(&tv, &tz);
elapsed_time = subTimeVal(&tv,&tracert_table[i].tp1 );
gettimeofday(&tracert_table[i].tp1, &tz);
printf("\n %s \t%6.3f ms",IP2Dot(tmpbuf,ipsrc),elapsed_time);
bytes_sent=outputprocessingudp(tracert_table[i].socket_id,buffer,size,ipaddr,tracert_table[i].dport,1);
}
}
}


//Called in the udpoutputprocessing to get the TTL value to stick in the field value
int getTTLvalue(int port)
{
int i;
for(i=0;i<10;i++)
{
if(tracert_table[i].dport==port)
return(tracert_table[i].TTL);
}
}


//Used for assigning the socket
int assign_socket(int type)
{
int i;
if(type==2)
{
for(i=1;i<MAX_PROC_BLOCK;i++)
{
if(process_block[i].is_occupied==FALSE)
{
process_block[i].socket_number=i;
process_block[i].port_number=i;
process_block[i].is_occupied=TRUE;
return(i);
}
}
return(0);
}
else
{
printf("Not yet implemented");
return(0);
}
}


//Called when a socket needs to be freed after the operaton
void freesocket(int socketid)
{
process_block[socketid].is_occupied=FALSE;
}


//Used to bind a socket to a particular port
void bindport(int socketid,int port)
{
process_block[socketid].port_number=port;
}


//Used to check if a particular port is open or not
int checkforopenport(int port)
{
	int i;
	for(i=1;i<MAX_PROC_BLOCK;i++)
	{
		if(process_block[i].is_occupied==TRUE)
		{
			if(process_block[i].port_number==port)
			return(1);
		}
	}
return(0);
}


//Close a port when a "nc close" command is parsed
void closeport(int cport)
{
int i;
	for(i=1;i<MAX_PROC_BLOCK;i++)
	{
		if(process_block[i].is_occupied==TRUE)
		{
			if(process_block[i].port_number==cport)
			process_block[i].is_occupied=FALSE;
		}
	}
}


//Used to create the pseudoheader and find the checksum and then send to the IP layer, the traceroute_flag is used to distinguish between normal and traceroute packets
int outputprocessingudp(int socketid,char message[],int length,uchar *ip_addr,int dport,int traceroute_flag)
{
	printf("The length is %d",length);
	int udp_length,i,TTL;
	char tmpbuf[200],source[]="192.168.1.2",temporary[4];
	Dot2IP(source,temporary);
	ushort cksum;
	gpacket_t *out_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *ipkt = (ip_packet_t *)(out_pkt->data.data);	
//Duplicate packets created to retrieve the outgoing source interface
	gpacket_t *duplicate_pkt = (gpacket_t *) malloc(sizeof(gpacket_t));
	ip_packet_t *duplicateipkt = (ip_packet_t *)(duplicate_pkt->data.data);	

	ipkt->ip_hdr_len = 5;                                  // no IP header options!!
	udp_packet_t *udphdr = (udp_packet_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);
	udp_length=createudpdatagram(udphdr,ip_addr,socketid,message,length,dport);
	
	pseudo_header *ip_pseudo= (pseudo_header *) malloc(sizeof(pseudo_header));
	COPY_IP(ip_pseudo->destination_address,gHtonl(tmpbuf,ip_addr));
	get_the_IP_address(duplicate_pkt,ip_addr);
	COPY_IP(ip_pseudo->source_address,duplicateipkt->ip_src);		
	ip_pseudo->zero=0;
	ip_pseudo->protocol=UDP_PROTOCOL;
	ip_pseudo->length=htons(udp_length);
	ip_pseudo->udp_src=(udphdr->udp_src);
	ip_pseudo->udp_dst=(udphdr->udp_dst);
	ip_pseudo->udp_len=(udphdr->udp_len);
	for(i=0;i<length;i++)
	{
	ip_pseudo->data[i]=(message[i]);
	}
	verbose (2,"\nThe Pseudo header contents are \n")	;
	verbose(2,"\nSource IP %s Destination IP is %s",IP2Dot(tmpbuf+20,ip_pseudo->source_address),IP2Dot(tmpbuf+40,ip_pseudo->destination_address));
	verbose(2,"\nThe zeros are %d The protcol is %d The length is %d",ip_pseudo->zero,ip_pseudo->protocol,ip_pseudo->length);
	verbose(2,"\nThe source port number is %d The destination port number is %d",ntohs(ip_pseudo->udp_src),ntohs(ip_pseudo->udp_dst));
	verbose(2,"\nThe length of the udp packet is %d",ntohs(ip_pseudo->udp_len));
	
	int newlength=length;
	if(length%2!=0)
	newlength=length+1;
	cksum = checksum((uchar *)ip_pseudo, (18+newlength+2)/2);
	udphdr->udp_chk=htons(cksum);
	if(traceroute_flag==1)
	{
	TTL=getTTLvalue(dport);
	IPOutgoingUDPPacket(out_pkt,ip_addr,ntohs(udphdr->udp_len) , 1, UDP_PROTOCOL,TTL);
	}
	else
	IPOutgoingPacket(out_pkt, ip_addr, ntohs(udphdr->udp_len), 1, UDP_PROTOCOL);
	return(length);
	
}


//Creating the actual udp datagram
int createudpdatagram(udp_packet_t *udphdr,uchar ip_addr[4], int socketid, char message[],int length,int dport)
{
int i;
udphdr->udp_dst=htons(dport);
udphdr->udp_src=htons(process_block[socketid].port_number);
udphdr->udp_len=htons(8+length);
for(i=0;i<length;i++)
{
udphdr->data[i]=message[i];
}
return(length+8);
}

//Processing the UDP packet when it is received from the IP layer above
void ProcessUDPpacket(gpacket_t *in_pkt)
{
int i,port,length,cksum;
ip_packet_t *ipkt = (ip_packet_t *)(in_pkt->data.data);
udp_packet_t *udphdr = (udp_packet_t *)((uchar *)ipkt + ipkt->ip_hdr_len*4);
port=ntohs(udphdr->udp_dst);
pseudo_header *ip_pseudo= (pseudo_header *) malloc(sizeof(pseudo_header));
COPY_IP(ip_pseudo->destination_address,ipkt->ip_dst);
COPY_IP(ip_pseudo->source_address,ipkt->ip_src);
ip_pseudo->protocol=UDP_PROTOCOL;
ip_pseudo->length=(udphdr->udp_len);
ip_pseudo->udp_src=(udphdr->udp_src);
ip_pseudo->udp_dst=(udphdr->udp_dst);
ip_pseudo->udp_len=(udphdr->udp_len);
ip_pseudo->udp_chk=udphdr->udp_chk;
length=ntohs(ip_pseudo->udp_len);
	for(i=0;i<length;i++)
	{
	ip_pseudo->data[i]=(udphdr->data[i]);
	}
cksum = checksum((uchar *)ip_pseudo, (18+length+2)/2);
if(cksum!=0)
{
verbose(2,"Bad checksum");
free(in_pkt);
return;
}
port=ntohs(udphdr->udp_dst);
if(checkforopenport(port)==0)
{
DestinationUnreachableICMP(in_pkt);
return;
}
int queue;
queue=getinputqueue(port);
enqueueudp(queue,udphdr->data,length);
}






