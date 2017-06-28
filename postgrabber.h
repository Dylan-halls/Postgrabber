const u_char *ip_header;
const u_char *tcp_header;
const u_char *payload;

int ethernet_header_length = 14;
int ip_header_length;
int tcp_header_length;
int payload_length;

struct ip_packet {
	u_char ip_vhl;
	u_char ip_tos;   
	u_short ip_len;   
	u_short ip_id;     
	u_short ip_off;    
	#define IP_RF 0x8000       
	#define IP_DF 0x4000     
	#define IP_MF 0x2000  
	#define IP_OFFMASK 0x1fff 
	u_char ip_ttl;    
	u_char ip_p;  
	u_short ip_sum; 
	struct in_addr ip_src;
	struct in_addr ip_dst;
	};

void debug(const char* text) {
	printf("[DEBUG] %s\n", text);
}

void fatal(const char *text) {
	printf("[FATAL] %s\n", text);
	exit(-1);
}

int getipheader_len(const u_char *packet){
	ip_header = packet + ethernet_header_length;
	ip_header_length = ((*ip_header) & 0x0F);
	ip_header_length = ip_header_length * 4;
	return ip_header_length;
}

int gettcpheader_len(const u_char *packet){
	tcp_header = packet + ethernet_header_length + ip_header_length;
	tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
	tcp_header_length = tcp_header_length * 4;
	return tcp_header_length;
}

void PrintData (const u_char *data , int Size)
{
    for(int i=0 ; i < Size ; i++)
    {
        if( i!=0 && i%16==0)   //if one line of hex printing is complete...
        {
            //printf("         ");
            for(int j=i-16 ; j<i ; j++)
            {
                if(data[j]>=32 && data[j]<=128) {
                    printf("%c",(unsigned char)data[j]); //if its a number or alphabet
                }
                 
            //    else printf("."); //otherwise print a dot
            	}
            //printf("\n");
        } 
         
        if(i%16==0) printf("   ");
            //printf(" %02X",(unsigned int)data[i]);
                 
        if( i==Size-1)  //print the last spaces
        {
            for(int j=0;j<15-i%16;j++) //printf("   "); //extra spaces
            //printf("         ");
             
            for(int j=i-i%16 ; j<=i ; j++)
            {
                //if(data[j]>=32 && data[j]<=128)  //printf("%c",(unsigned char)data[j]);
               // else //printf(".");
           	}
           // printf("\n");
        }
    }
}

void getpayload(const u_char *packet, const struct pcap_pkthdr* header){
	int total_headers_size;
	total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
	payload_length = header->caplen -(ethernet_header_length + ip_header_length + tcp_header_length);
	payload = packet + total_headers_size;
	PrintData(payload, payload_length);
}