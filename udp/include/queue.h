typedef struct queue_structure_t
{
	bool data_present;
	uint16_t port_number;
	char data[200];
	int length;
	
} queue_structure;

typedef struct queue_list_t
{
	bool is_exists;
	uint16_t port_number;
	int queue_number;
} queue_list;


int getinputqueue(int port);
void addtolist(int queue,int port);
int createqueue(int port);
void scanningfunctioninudp(int queue);
