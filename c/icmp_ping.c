
#include <stdio.h>


#define ICMP_ECHO       8
#define ICMP_ECHOREPLY  0
#define IP_MAXPACKET 65535

#pragma pack(1)

#pragma pack()

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/time.h> // gettimeofday()
#include <sys/timeb.h>


// IPv4 header len without options
#define IP4_HDRLEN 20

// ICMP header len for echo req
#define ICMP_HDRLEN 8

// Checksum algo
unsigned short calculate_checksum(unsigned short * paddress, int len);

#define SOURCE_IP "172.17.0.36"
// i.e the gateway or ping to google.com for their ip-address
// #define DESTINATION_IP "139.130.4.5"

int main (int argc, char* argv[])
{
    // IPv4 header (for ping purposes we're not going to
    // touch it, kernel will take care of that for us)
    struct ip iphdr; 
    
    struct icmp icmphdr; // ICMP-header
    char data[IP_MAXPACKET] = "Elad's ping!!!!\n";
    
    int datalen = strlen(data) + 1;

    struct timeval pingSent_t;
    struct timeval echo_rply_t;
    struct timeb sendtime, replytime;
    

    char *DESTINATION_IP; 
    // now set DESTINATION IP from command-line
    if(argc > 1) {
        DESTINATION_IP = *(argv+1);
    }
    
    
    //==================
    // IP header -- not for use right now the kernel will take care.
    //==================

    // copy for origin
    
    
    //===================
    // ICMP header
    //===================
    
    icmphdr.icmp_type = ICMP_ECHO;
    
    icmphdr.icmp_code = 0;
    
    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    icmphdr.icmp_id = 18; // hai
    
    // Sequence Number (16 bits): starts at 0
    icmphdr.icmp_seq = 0;
    
    // ICMP header checksum (16 bits): set to 0 not to include into checksum calculation
    icmphdr.icmp_cksum = 0;
    
    // define packet
    char packet[IP_MAXPACKET];
    
    // First, IP header.
    //memcpy (packet, &iphdr, IP4_HDRLEN);
    
    // Next, ICMP header
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    
    // After ICMP header, add the ICMP data.
    memcpy (packet + ICMP_HDRLEN, data, datalen);
    
    // Calculate the ICMP header checksum
    icmphdr.icmp_cksum = calculate_checksum((unsigned short *) (packet), ICMP_HDRLEN + datalen);
    memcpy ((packet), &icmphdr, ICMP_HDRLEN);
    
    
    // socketaddress for destination
    struct sockaddr_in dest_in;
    memset (&dest_in, 0, sizeof (struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    
    // The port is irrelant for Networking and therefore was zeroed.
    inet_pton(AF_INET, DESTINATION_IP, &dest_in.sin_addr);

    

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;
    if ((sock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        fprintf (stderr, "socket() failed with error: %d" , errno );
        fprintf (stderr, "To create a raw socket, the process needs to be run by Admin/root user.\n\n");
        return -1;
    }
    

    // Send the packet using sendto() for sending datagrams.
    if (sendto (sock, packet, ICMP_HDRLEN + datalen, 0, (struct sockaddr *) &dest_in, sizeof (dest_in)) == -1)
    {
        fprintf (stderr, "sendto() failed with error: %d", errno );
        return -1;
    }
    
    
    // capture current time onSend in millisec as well.
    gettimeofday(&pingSent_t, NULL);
    ftime(&sendtime);
    
    
    printf("sent packet from: %s to  %s \n", SOURCE_IP, DESTINATION_IP);
    int msg_count = 1;
    
    // listen for echo reply
    size_t addrlen = sizeof(dest_in);
    int bytes_received;
    char* buffer = malloc(sizeof(struct iphdr) + sizeof(struct icmphdr));
    struct iphdr* ip_rply;
    struct icmphdr* icmp_rply;
    printf("Waiting for echo-reply...\n");
    while(1)
    {
        
        if (( bytes_received = recvfrom(sock, buffer, sizeof(struct iphdr) + sizeof(struct icmphdr), 0, (struct sockaddr *)&dest_in, &addrlen)) == -1)
        {
             perror("recv\n");
        }
        else
        {
            char* from_addr[20];

	    icmp_rply = (struct icmphdr*) (buffer + sizeof(struct iphdr));
	    ip_rply = (struct iphdr*) buffer;

	    // trying to get source ip as string, Arrrr....
	    struct sockaddr_in ip_src;
	    memset(&ip_src,0,sizeof(ip_src));
            ip_src.sin_addr.s_addr = ip_rply->saddr;	
   	    char srcAddress[INET_ADDRSTRLEN];
	    strcpy(srcAddress, inet_ntoa(ip_src.sin_addr));
	
	    if(icmp_rply->type == ICMP_ECHOREPLY){
	        
	        // capture current time when recieved ICMP echo-reply
	        gettimeofday(&echo_rply_t, NULL);
	        ftime(&replytime);
            
	        printf("Received %d byte reply from %s \n", bytes_received , srcAddress);
            printf("ID: %d\n", ntohs(ip_rply->id));
            printf("TTL: %d\n", ip_rply->ttl);
	        printf("ICMP type: %d \n", icmp_rply->type);
	        printf("RTT: %ld sec, %ld millisec  %ld micrs \n", echo_rply_t.tv_sec - pingSent_t.tv_sec , replytime.millitm - sendtime.millitm , echo_rply_t.tv_usec - pingSent_t.tv_usec );
            break;
	    }
           
        }
        sleep(1);
    }
    // Close the raw socket descriptor.
    close(sock);
    free(buffer);

    return 0;
}

unsigned short calculate_checksum(unsigned short * paddress, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short * w = paddress;
    unsigned short answer = 0;
    
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }
    
    if (nleft == 1)
    {
        *((unsigned char *)&answer) = *((unsigned char *)w);
        sum += answer;
    }
    
    // add back carry outs from top 16 bits to low 16 bits
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    answer = ~sum;                      // truncate to 16 bits
    
    return answer;
}


