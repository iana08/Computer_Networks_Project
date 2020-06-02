#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>	      // for int16_t for the id for the payload.
#include <unistd.h>           // close()
#include <string.h>           // strcpy, memset(), and memcpy()

#include <netdb.h>            // struct addrinfo
#include <sys/types.h>        // needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>       // needed for socket()
#include <netinet/in.h>       // IPPROTO_RAW, IPPROTO_UDP, INET_ADDRSTRLEN
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/tcp.h>      // struct tcphdr
#include <netinet/udp.h>
#include <arpa/inet.h>        // inet_pton() and inet_ntop()
#include <sys/ioctl.h>        // macro ioctl is defined
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/if.h>           // struct ifreq
#include <net/ethernet.h>
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/ethernet.h>

#include <errno.h>            // errno, perror()

#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data
#define TCP_HDRLEN 20
#define MAXDATASIZE 65535
#define IPADDSIZE 32

//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
	uint32_t srcAddr;
	uint32_t dstAddr;
	uint8_t zero;
	uint8_t protocol;
	uint16_t TCP_len;
};

// function prototypes
uint16_t checksum (uint16_t *addr, int len);
uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

struct socket_values{
	char ip_addr[IPADDSIZE];
	int s_port_udp;
	int d_port_udp;
	int tcp_h_port;
	int tcp_t_port;
	int client_addr; // change this to be only an int
	int udp_payload;
	int inter_mes_time;
	int num_udp_pack;
	int ttl;
};

void fill_struct(char * buf, struct socket_values * sock_val) {
	char cpy_buf[MAXDATASIZE];
	memset(cpy_buf, 0, MAXDATASIZE);
	int i;
	int j = 0;
	for(i = 0 ; i < 10 ; i += 1) {
		strcpy(cpy_buf, buf);
		char * token = strtok(cpy_buf, "\n");
		token = strtok(NULL, "\n"); 
		int reps = 0;
		while (token!=NULL) {
			if (reps == j) {
				char * new_tok = strtok(token, ":");
				new_tok = strtok(NULL, ": ");
				int len = strlen(new_tok);
				len -= 1;
				new_tok[len] = '\0';
				if (i == 0) {
					// ip address
					len -= 1;
					new_tok[len] = '\0';
					new_tok = strtok(new_tok, "\"");
					strcpy(sock_val->ip_addr, new_tok);
				}
				if (i == 1) {
					// port soruce udp
					sock_val->s_port_udp = atoi(new_tok);
				}
				if (i == 2) {
					sock_val->d_port_udp = atoi(new_tok);
					// dest udp
				}
				if (i == 3) {
					sock_val->tcp_h_port = atoi(new_tok);
					// tcp head
				}
				if (i == 4) {
					sock_val->tcp_t_port = atoi(new_tok);
					// tcp tail
				}
				if (i == 5) {
					sock_val->client_addr = atoi(new_tok);
					// port_tcp
				}
				if (i == 6) {
					sock_val -> udp_payload = atoi(new_tok);
					// size of udp
				}
				if (i == 7) {
					sock_val->inter_mes_time = atoi(new_tok);
					// imt
				}
				if (i == 8) {
					sock_val->num_udp_pack = atoi(new_tok);
					// number of udp packets
				}
				if (i == 9) {
					sock_val->ttl = atoi(new_tok);
					// ttl
				}

				// printf("new:%s\n", new_tok);
			}
			token = strtok(NULL, "\n");
			reps += 1;
		}
		j += 1;
	}
}

// Function prototypes
uint16_t checksum (uint16_t *addr, int len);
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr);

int main(int argc, char *argv[]) {

	if (argc < 3) {
		perror("hostip: myconfig.json <host_ip>");
		return -1;
	}

	FILE *fp;
	char buf[MAXDATASIZE];
	memset(&buf, 0, MAXDATASIZE);
	char ch; 
	struct socket_values sock_val;
	memset(&sock_val, 0 , sizeof(sock_val));
	memset(&sock_val.ip_addr, 0, IPADDSIZE);

	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		perror("Error while opening the file\n");
		exit(1);
	}
	int i;
	i = 0;
	
	while((ch = fgetc(fp)) != EOF) {
		buf[i] = ch;
		i += 1;
	}
	buf[i] = '\0';

	fclose(fp);

	if (buf[0] == '0') {
		fprintf(stderr, "usage: file is empty\n");
		return -1;
	}

	fill_struct(buf, &sock_val);
	// grabing code from cooked udp and changing it to tcp because the previous did not save the packet.
	
	int status, datalen, frame_length, sd, bytes, *ip_flags;
	char *interface, *target, *src_ip, *dst_ip;
	struct ip iphdr;
	struct tcphdr tcphdr;
	uint8_t *data, *src_mac, *dst_mac, *ether_frame;
	struct addrinfo hints, *res;
	struct sockaddr_in sin, *ipv4;
	struct sockaddr_ll device;
//  struct ifreq ifr;
	void *tmp;

  // Allocate memory for various arrays.
	src_mac = allocate_ustrmem (6);
	dst_mac = allocate_ustrmem (6);
	data = allocate_ustrmem (IP_MAXPACKET);
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	target = allocate_strmem (40);
	src_ip = allocate_strmem (INET_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	ip_flags = allocate_intmem (4);

  // Interface to send packet through.
	strcpy (interface, "enp0s3");

	memcpy (src_mac, "08:00:27:df:42:bc", 6);
	src_mac[0] = 0x08;
	src_mac[1] = 0x00;
	src_mac[2] = 0x27;
	src_mac[3] = 0xdf;
	src_mac[4] = 0x42;
	src_mac[5] = 0xbc;

 // Find interface index from interface name and store index in
	memset (&device, 0, sizeof (device));
	memset (&sin, 0, sizeof(sin));

	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}

  // Set destination MAC address: you need to fill this out
	dst_mac[0] = 0x08;
	dst_mac[1] = 0x00;
	dst_mac[2] = 0x27;
	dst_mac[3] = 0xf0;
	dst_mac[4] = 0x1c;
	dst_mac[5] = 0xb5;

    // Source IPv4 address: you need to fill this out
	strcpy (src_ip, argv[2]);// host ip

  // Destination URL or IPv4 address: you need to fill this out
	strcpy (target, sock_val.ip_addr); // son
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;

  // printf("port: %d  \n",  sock_val.tcp_h_port);
	char port[65535];

  
	snprintf(port, sizeof(port), "%d", sock_val.tcp_h_port);
  // Resolve target using getaddrinfo().
	if ((status = getaddrinfo (target, port, &hints, &res)) != 0) {
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}

	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
  
	if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

    // Replace sockaddr_ll  to sockaddr_in
	sin.sin_family = AF_INET;
	sin.sin_port = htons(sock_val.tcp_h_port);
	sin.sin_addr.s_addr = inet_addr(target);
  
	datalen = 0;

  // IPv4 header

  // IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);

  // Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

  // Type of service (8 bits)
	iphdr.ip_tos = 0;

  // Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
    
  // ID sequence number (16 bits): unused, since single datagram
	iphdr.ip_id = htons (23);

  // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram

  // Zero (1 bit)
	ip_flags[0] = 0;

  // Do not fragment flag (1 bit)
	ip_flags[1] = 1;

  // More fragments following flag (1 bit)
	ip_flags[2] = 0;

  // Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
			+ (ip_flags[1] << 14)
			+ (ip_flags[2] << 13)
			+  ip_flags[3]);

  // Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = sock_val.ttl;

  // Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_TCP;

  // Source IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

  // Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

  // IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

  // TCP header:
        // printf("port number: %d\n", sock_val.tcp_h_port);
        tcphdr.th_sport = htons(sock_val.tcp_h_port);
        tcphdr.th_dport = htons(sock_val.tcp_h_port);
        tcphdr.th_seq =  0x0;
        tcphdr.th_ack = 0x0;
        tcphdr.th_off = 5;
        tcphdr.th_x2 = 0;
        short tcp_flags = 0x02; // SYN PACKET SET HERE
        tcphdr.th_flags = tcp_flags;
        tcphdr.th_win = htons(MAXDATASIZE);
        tcphdr.th_sum =  0;
        tcphdr.th_urp = htons(0);

// ethernet frame header 

  // Fill out ethernet frame header.
  // Ethernet frame length = ethernet data (IP header + UDP header + UDP data)
	frame_length = IP4_HDRLEN + TCP_HDRLEN + datalen;

  // IPv4 header
	memcpy (ether_frame, &iphdr, IP4_HDRLEN);

  // UDP header
	memcpy (ether_frame + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);

  // UDP data
	memcpy (ether_frame + IP4_HDRLEN + TCP_HDRLEN, data, datalen);

    // Open raw socket descriptor.
	if ((sd = socket (PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	if ((connect(sd, (struct sockaddr *) &sin, sizeof(sin))) < 0) {
		perror("Connect() failed \n");
		exit(EXIT_FAILURE);
	}

  // Send ethernet frame to socket.
	printf("Sending tcp packet\n");
	if ((bytes = send (sd, ether_frame, frame_length, 0)) < 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}

//    char buffer[65535];
//    memset(&buffer, 0, 65535);

	printf("Sent %d bytes\n", bytes);

    /*
    // sockaddr_ll temp_sin;
    struct sockaddr_in temp_sin;
    memset(&temp_sin, 0, sizeof(temp_sin));
    int len = sizeof(temp_sin);
    if ((bytes = recvfrom(sd, buffer, 65536, 0, (struct sockaddr *)&temp_sin ,&len)) < 0) {
	    perror("REcvfrom failed\n");
    }
    printf("Got something back");
*/
	freeaddrinfo(res);
	close (sd);
//        freeaddrinfo(res);

// NOW FOR UDP
	struct udphdr udphdr;
	memset(ether_frame ,0, IP_MAXPACKET);
	memset (&device, 0, sizeof (device));
	memset (&sin, 0, sizeof(sin));
    
	if ((device.sll_ifindex = if_nametoindex (interface)) == 0) {
		perror ("if_nametoindex() failed to obtain interface index ");
		exit (EXIT_FAILURE);
	}
    
	dst_mac[0] = 0x08;
	dst_mac[1] = 0x00;
	dst_mac[2] = 0x27;
	dst_mac[3] = 0xf0;
	dst_mac[4] = 0x1c;
	dst_mac[5] = 0xb5;
    
	strcpy (src_ip, argv[2]); // mom

    // Destination URL or IPv4 address: you need to fill this out 
	strcpy (target, sock_val.ip_addr); // son
    
    // Fill out hints for getaddrinfo().
	// memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	// freeaddr(res);
	// memset(res, 0, sizeof(struct addrinfo));


	if ((status = getaddrinfo (target, port, &hints, &res)) != 0) {
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
    
	ipv4 = (struct sockaddr_in *) res->ai_addr;
	tmp = &(ipv4->sin_addr);
	if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf (stderr, "inet_ntop() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
	freeaddrinfo(res);
    
    
	sin.sin_family = AF_INET;
    //udp port
	sin.sin_port = htons(sock_val.d_port_udp);
	sin.sin_addr.s_addr = inet_addr(target);
	datalen = sock_val.udp_payload; // PAYLOAD SIZE SET HERE
	memset(data, 0, datalen);

    // SET up is done, now for the headers.

    // IPv4 header length (4 bits): Number of 32-bit words in header = 5
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
    // Internet Protocol version (4 bits): IPv4
	iphdr.ip_v = 4;

    // Type of service (8 bits)
	iphdr.ip_tos = 0;

    // Total length of datagram (16 bits): IP header + UDP header + datalen
	iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);
    
    // Flags, and Fragmentation offset (3, 13 bits): 0 since single datagram
    // Zero (1 bit)
	ip_flags[0] = 0;

    // Do not fragment flag (1 bit)
	ip_flags[1] = 1;

    // More fragments following flag (1 bit)
	ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
			+ (ip_flags[1] << 14)
			+ (ip_flags[2] << 13)
			+  ip_flags[3]);
    
    // Time-to-Live (8 bits): default to maximum value
	iphdr.ip_ttl = sock_val.ttl;// TTL SET HERE FOR UDP

    // Transport layer protocol (8 bits): 17 for UDP
	iphdr.ip_p = IPPROTO_UDP;

    // Source IPv4 address (32 bits)
    
	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}
    
    // Destination IPv4 address (32 bits)
	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

    // IPv4 header checksum (16 bits): set to 0 when calculating checksum
	iphdr.ip_sum = 0;
    
    // UDP header
    
    // Source port number (16 bits): pick a number
	udphdr.uh_sport = htons (sock_val.s_port_udp);
    
    // Destination port number (16 bits): pick a number
	udphdr.uh_dport = htons (sock_val.d_port_udp);

    // Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);

    // UDP checksum (16 bits)
	udphdr.uh_sum = 0;
    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet data (IP header + UDP header + UDP data)
	frame_length = IP4_HDRLEN + UDP_HDRLEN + datalen;
    // Open raw socket descriptor.

    	if ((sd = socket (PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
    		perror ("socket() failed ");
    		exit (EXIT_FAILURE);
	}
    
	printf("Sending low entropy data\n");
    
	int index;
	index = 0;
	char p_id[16];
	memset(p_id, 0 , 16);
	uint16_t packet_id = 0;
	int num_pack;
	num_pack = rand(); // sock_val.num_udp_pack
	
	while (index < sock_val.num_udp_pack) {
	    
		iphdr.ip_id = htons (num_pack);
	
		iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
	    
		udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);

	    // IPv4 header
		memcpy (ether_frame, &iphdr, IP4_HDRLEN);

	    // UDP header
		memcpy (ether_frame + IP4_HDRLEN, &udphdr, UDP_HDRLEN);

	    // UDP data
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, data, datalen);
	    
		sprintf(p_id, "%hu", packet_id);
	    // UPD iD
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, p_id, 16);

		num_pack += 1;
		packet_id += 1;
	    // Send ethernet frame to socket.
	    // printf("Sending udp packet\n");
	    
		if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &sin, sizeof (sin))) < 0) {
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		index += 1;
	}
	printf("Finished sending low entropy data\n");
    // Read from /dev/random/
	fp = fopen("/dev/urandom", "r");
        
	if (fp == NULL) {
		perror("Error while opening the file\n");
		exit(1); 
	}

	i = 0;
	printf("Reading dev/random\n");
	while( i < sock_val.udp_payload) {
		ch = fgetc(fp);
		data[i] = ch;
		i += 1;   
	}
    
	data[i] = '\0';    
    
	fclose(fp);
    
	memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, data, datalen);// DAT SET HERE
    
	index = 0;
	printf("Now I must sleep for %d, for the packets to get to the destination\n", sock_val.inter_mes_time);
	
	sleep(sock_val.inter_mes_time);
	printf("Waking up and sending random data\n");
	num_pack = rand(); // sock_val.num_udp_pack

	printf("Starting to send the high entropy data\n");
	packet_id = 0;
	while (index < sock_val.num_udp_pack) {
        
	    	iphdr.ip_id = htons (num_pack);
		iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
		udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);
		
		// IPv4 header
		memcpy (ether_frame, &iphdr, IP4_HDRLEN);
            
		// UDP header
		memcpy (ether_frame + IP4_HDRLEN, &udphdr, UDP_HDRLEN);
            
		// UDP data
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

		sprintf(p_id, "%hu", packet_id);
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, p_id, 16);
	    
		num_pack += 1;
            // Send ethernet frame to socket.
            // printf("Sending udp packet\n");
            
		if ((bytes = sendto (sd, ether_frame, frame_length, 0, (struct sockaddr *) &sin, sizeof (sin))) < 0) {
                    
			perror ("sendto() failed");
			exit (EXIT_FAILURE);
		}
		packet_id += 1;
		index += 1;
	}
    
	printf("Done sending random udp packets\n");
    
	close (sd);
	
	printf("Now sending TCP tail packet\n");
  // Destination URL or IPv4 address: you need to fill this 
 	
        strcpy (target, sock_val.ip_addr); // son
	memset(port, '\0', 65535);
	sprintf(port, "%d", sock_val.tcp_t_port);
	// Fill out hints for getaddrinfo().
        
	memset (&hints, 0, sizeof (struct addrinfo));
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;
	struct addrinfo *servinfo;
	if ((status = getaddrinfo (target, port, &hints, &servinfo)) != 0) {
		fprintf (stderr, " error code :%d getaddrinfo() failed: %s\n", status ,gai_strerror (status));
		exit (EXIT_FAILURE);
	}
	ipv4 = (struct sockaddr_in *) servinfo->ai_addr;
	tmp = &(ipv4->sin_addr);
  
	if (inet_ntop (AF_INET, tmp, dst_ip, INET_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf (stderr, "inet_ntop() error code :%dfailed.\nError message: %s", status,strerror (status));
		exit (EXIT_FAILURE);
	}
	sin.sin_family = AF_INET;
	sin.sin_port = htons(sock_val.tcp_h_port);
	sin.sin_addr.s_addr = inet_addr(target);
	datalen = 0;

	memset(&iphdr, 0, sizeof(struct iphdr));
	
	iphdr.ip_hl = IP4_HDRLEN / sizeof (uint32_t);
	
	iphdr.ip_v = 4;

	iphdr.ip_tos = 0;

	iphdr.ip_len = htons (IP4_HDRLEN + UDP_HDRLEN + datalen);

	iphdr.ip_id = htons (24);

	ip_flags[0] = 0;

	ip_flags[1] = 1;

	ip_flags[2] = 0;

	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
			+ (ip_flags[1] << 14)
			+ (ip_flags[2] << 13)
			+  ip_flags[3]);

	iphdr.ip_ttl = sock_val.ttl;

	iphdr.ip_p = IPPROTO_TCP;

	if ((status = inet_pton (AF_INET, src_ip, &(iphdr.ip_src))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	if ((status = inet_pton (AF_INET, dst_ip, &(iphdr.ip_dst))) != 1) {
		fprintf (stderr, "inet_pton() failed.\nError message: %s", strerror (status));
		exit (EXIT_FAILURE);
	}

	iphdr.ip_sum = 0;
	iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);
	memset(&tcphdr, 0, sizeof(tcphdr));
	tcphdr.th_sport = htons(sock_val.tcp_h_port);
	tcphdr.th_dport = htons(sock_val.tcp_h_port);
	tcphdr.th_seq =  0x0;
	tcphdr.th_ack = 0x0;
	tcphdr.th_off = 5;
	tcphdr.th_x2 = 0;
	short tcp_flag = 0x02; // set syn flag set here
	tcphdr.th_flags = tcp_flag;// syn flag set here
	tcphdr.th_win = htons(MAXDATASIZE);
	tcphdr.th_sum =  0;
	tcphdr.th_urp = htons(0);

	frame_length = IP4_HDRLEN + TCP_HDRLEN + datalen;

	memset(ether_frame, 0, sizeof(IP_MAXPACKET));

	memcpy (ether_frame, &iphdr, IP4_HDRLEN);
	
	memcpy (ether_frame + IP4_HDRLEN, &tcphdr, TCP_HDRLEN);

	if ((sd = socket (PF_INET, SOCK_RAW,IPPROTO_RAW)) < 0) {// changed this to be raw instead of tcp
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
	}

	if ((connect(sd, (struct sockaddr *) &sin, sizeof(sin))) < 0) {
		perror("Connect() failed \n");
		exit(EXIT_FAILURE);
	}
	
	printf("Sending tcp packet\n");
	if ((bytes = send (sd, ether_frame, frame_length, 0)) < 0) {
		perror ("sendto() failed");
		exit (EXIT_FAILURE);
	}

	printf("Sent %d bytes\n", bytes);

	close (sd);
	
	// Free allocated memory.

	free (src_mac);
	free (dst_mac);
	free (data);
	free (ether_frame);
	free (interface);
	free (target);
	free (src_ip);
	free (dst_ip);
	free (ip_flags);
	freeaddrinfo(res);
	return 0;
}


// Computing the internet checksum (RFC 1071).
// Note that the internet checksum does not preclude collisions.
uint16_t checksum (uint16_t *addr, int len) { 
  int count = len;
  register uint32_t sum = 0;
  uint16_t answer = 0;
  
  // Sum up 2-byte values until none or only one byte left.
  while (count > 1) {
    sum += *(addr++);
    count -= 2;
  }
  
  // Add left-over byte, if any.
  if (count > 0) {
    sum += *(uint8_t *) addr;
  }
  
  // Fold 32-bit sum into 16 bits; we lose information by doing this,
  // increasing the chances of a collision. 
  // sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
  while (sum >> 16) {
    sum = (sum & 0xffff) + (sum >> 16);
  }
  
  // Checksum is one's compliment of sum.
  answer = ~sum;
  
  return (answer);
}

// Allocate memory for an array of chars.
char * allocate_strmem (int len) { 
  void *tmp;
  
  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_strmem().\n", len);
    exit (EXIT_FAILURE);
  }
  
  tmp = (char *) malloc (len * sizeof (char));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (char));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_strmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of unsigned chars.
uint8_t * allocate_ustrmem (int len) {
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_ustrmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (uint8_t *) malloc (len * sizeof (uint8_t));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (uint8_t));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_ustrmem().\n");
    exit (EXIT_FAILURE);
  }
}

// Allocate memory for an array of ints.
int * allocate_intmem (int len) {
  void *tmp;

  if (len <= 0) {
    fprintf (stderr, "ERROR: Cannot allocate memory because len = %i in allocate_intmem().\n", len);
    exit (EXIT_FAILURE);
  }

  tmp = (int *) malloc (len * sizeof (int));
  if (tmp != NULL) {
    memset (tmp, 0, len * sizeof (int));
    return (tmp);
  } else {
    fprintf (stderr, "ERROR: Cannot allocate memory for array allocate_intmem().\n");
    exit (EXIT_FAILURE);
  }
}


// Build IPv4 TCP pseudo-header and call checksum function.
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr) {
  uint16_t svalue;
  char buf[IP_MAXPACKET], cvalue;
  char *ptr;
  int chksumlen = 0;

  // ptr points to beginning of buffer buf
  ptr = &buf[0];

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);

  // Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy TCP length to buf (16 bits)
  svalue = htons (sizeof (tcphdr));
  memcpy (ptr, &svalue, sizeof (svalue));
  ptr += sizeof (svalue);
  chksumlen += sizeof (svalue);

  // Copy TCP source port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_sport, sizeof (tcphdr.th_sport));
  ptr += sizeof (tcphdr.th_sport);
  chksumlen += sizeof (tcphdr.th_sport);

  // Copy TCP destination port to buf (16 bits)
  memcpy (ptr, &tcphdr.th_dport, sizeof (tcphdr.th_dport));
  ptr += sizeof (tcphdr.th_dport);
  chksumlen += sizeof (tcphdr.th_dport);

  // Copy sequence number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_seq, sizeof (tcphdr.th_seq));
  ptr += sizeof (tcphdr.th_seq);
  chksumlen += sizeof (tcphdr.th_seq);

  // Copy acknowledgement number to buf (32 bits)
  memcpy (ptr, &tcphdr.th_ack, sizeof (tcphdr.th_ack));
  ptr += sizeof (tcphdr.th_ack);
  chksumlen += sizeof (tcphdr.th_ack);

  // Copy data offset to buf (4 bits) and
  // copy reserved bits to buf (4 bits)
  cvalue = (tcphdr.th_off << 4) + tcphdr.th_x2;
  memcpy (ptr, &cvalue, sizeof (cvalue));
  ptr += sizeof (cvalue);
  chksumlen += sizeof (cvalue);

  // Copy TCP flags to buf (8 bits)
  memcpy (ptr, &tcphdr.th_flags, sizeof (tcphdr.th_flags));
  ptr += sizeof (tcphdr.th_flags);
  chksumlen += sizeof (tcphdr.th_flags);

  // Copy TCP window size to buf (16 bits)
  memcpy (ptr, &tcphdr.th_win, sizeof (tcphdr.th_win));
  ptr += sizeof (tcphdr.th_win);
  chksumlen += sizeof (tcphdr.th_win);

  // Copy TCP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy urgent pointer to buf (16 bits)
  memcpy (ptr, &tcphdr.th_urp, sizeof (tcphdr.th_urp));
  ptr += sizeof (tcphdr.th_urp);
  chksumlen += sizeof (tcphdr.th_urp);

  return checksum ((uint16_t *) buf, chksumlen);
}


// Build IPv4 UDP pseudo-header and call checksum function.
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen) {

  char buf[IP_MAXPACKET];
  char *ptr;
  int chksumlen = 0;
  int i;

  ptr = &buf[0];  // ptr points to beginning of buffer buf

  // Copy source IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_src.s_addr, sizeof (iphdr.ip_src.s_addr));
  ptr += sizeof (iphdr.ip_src.s_addr);
  chksumlen += sizeof (iphdr.ip_src.s_addr);

  // Copy destination IP address into buf (32 bits)
  memcpy (ptr, &iphdr.ip_dst.s_addr, sizeof (iphdr.ip_dst.s_addr));
  ptr += sizeof (iphdr.ip_dst.s_addr);
  chksumlen += sizeof (iphdr.ip_dst.s_addr);
// Copy zero field to buf (8 bits)
  *ptr = 0; ptr++;
  chksumlen += 1;

  // Copy transport layer protocol to buf (8 bits)
  memcpy (ptr, &iphdr.ip_p, sizeof (iphdr.ip_p));
  ptr += sizeof (iphdr.ip_p);
  chksumlen += sizeof (iphdr.ip_p);

  // Copy UDP length to buf (16 bits)
  memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
  ptr += sizeof (udphdr.uh_ulen);
  chksumlen += sizeof (udphdr.uh_ulen);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.uh_sport, sizeof (udphdr.uh_sport));
  ptr += sizeof (udphdr.uh_sport);
  chksumlen += sizeof (udphdr.uh_sport);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.uh_dport, sizeof (udphdr.uh_dport));
  ptr += sizeof (udphdr.uh_dport);
  chksumlen += sizeof (udphdr.uh_dport);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.uh_ulen, sizeof (udphdr.uh_ulen));
  ptr += sizeof (udphdr.uh_ulen);
  chksumlen += sizeof (udphdr.uh_ulen);

  // Copy UDP checksum to buf (16 bits)
  // Zero, since we don't know it yet
  *ptr = 0; ptr++;
  *ptr = 0; ptr++;
  chksumlen += 2;

  // Copy payload to buf
  memcpy (ptr, payload, payloadlen);
  ptr += payloadlen;
  chksumlen += payloadlen;

  // Pad to the next 16-bit boundary
  for (i=0; i<payloadlen%2; i++, ptr++) {
    *ptr = 0;
    ptr++;
    chksumlen++;
  }

  return checksum ((uint16_t *) buf, chksumlen);
}
