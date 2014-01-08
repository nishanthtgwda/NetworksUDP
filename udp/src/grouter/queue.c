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
#include "queue.h"
#include "udp.h"

queue_list all_list[100];


//Creating a queue for the specific port
int createqueue(int port)
{
	queue_structure *queue = (queue_structure *) malloc(sizeof(queue_structure));
	queue->port_number=port;
	addtolist(queue,port);
	return(queue);
}


//Addinf the queue and the associated port number to the table contained
void addtolist(int queue,int port)
{
int i;
for(i=0;i<100;i++)
{
if(all_list[i].is_exists==FALSE)
{
all_list[i].is_exists=TRUE;
all_list[i].queue_number=queue;
all_list[i].port_number=port;
verbose(2,"\nThe queue number is %d and its port number is %d",all_list[i].queue_number,all_list[i].port_number);
break;
}
}
}


//Called by the UDP processing function to get the inputqueue as per the port number
int getinputqueue(int port)
{
int i;
for(i=0;i<100;i++)
{
if(all_list[i].is_exists==TRUE)
{
if(all_list[i].port_number==port)
return(all_list[i].queue_number);
}
}
}

//Enqueinig the contents of the packet to the queue
void enqueueudp(int queue,char data[],int length)
{
	int i;
	queue_structure *present_queue = (queue_structure *) queue;
	//printf("\n The port number of the queue is %d",present_queue->port_number);
	for(i=0;i<length-8;i++)
	present_queue->data[i]=data[i];
	present_queue->length=length-8;
	present_queue->data_present=TRUE;
}


void scanningfunctioninudp(int queue)
{
	int i;
	queue_structure *scanning_queue = (queue_structure *) queue;
	while(1)
	{
	if(scanning_queue->data_present==TRUE)
		{
		for(i=0;i<scanning_queue->length;i++)
		printf("%c",scanning_queue->data[i]);
		scanning_queue->length=0;
		scanning_queue->data_present=FALSE;
		}
	}		
}
