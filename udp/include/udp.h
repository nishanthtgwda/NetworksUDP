
#define MAX_PROC_BLOCK 1000


typedef struct _udpstat_t
{
int number;
int TTL;
} udpstat_t;

typedef struct udp
{
        //! The source port.
      uint16_t udp_src;
       //! The destination port.
       uint16_t udp_dst;
      //! The packet length.
        uint16_t udp_len;
       //! The UDP checksum.
      uint16_t udp_chk;
	char data[200];
} udp_packet_t;

typedef struct PCB_structure_t
{
	bool is_occupied;
	uint16_t socket_number;
	uint16_t port_number;
} PCB_structure;

typedef struct _pseudo_header_t
{
	uchar source_address[4];
	uchar destination_address[4];
	uint8_t zero;
	uint8_t protocol;
	uint16_t length;
	uint16_t udp_src;
	uint16_t udp_dst;
	uint16_t udp_len;
	uint16_t udp_chk;
	char data[200];
}pseudo_header;


typedef struct _traceroute_table_t
{
	int socket_id;
	int dport;
	struct timeval tp1;
	int TTL;
}traceroute_table;

int TTLcounter;
struct timeval tp1;
struct timeval tp2;
struct timeval tp3;
void udptraceroute(uchar *ipaddr);
void SendUDPPacket(uchar *dst_ip, int size, int seq,int destination,int TTL);
int assign_socket(int type);
int outputprocessingudp(int socketid,char message[],int length,uchar *ip_addr,int destination_port,int traceroute_flag);
int createudpdatagram(udp_packet_t *udphd,uchar ip_addr[4], int socketid, char message[],int length,int dport);
void bindport(int socektid,int port);
void ProcessUDPpacket(gpacket_t *in_pkt);
