    /*
** client.c -- a stream socket client demo
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>	      // for int16_t for the id for the payload.
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/ip.h>       // struct ip and IP_MAXPACKET (which is 65535)
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>   
#include <bits/ioctls.h>      // defines values for argument "request" of ioctl.
#include <net/ethernet.h>
#include <linux/if_ether.h>   // ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>  // struct sockaddr_ll (see man 7 packet)
#include <net/if.h>           // struct ifreq


#define IP4_HDRLEN 20         // IPv4 header length
#define UDP_HDRLEN  8         // UDP header length, excludes data
#define IPADDSIZE 32

#define MAXDATASIZE 65535 // max number of bytes we can get at once 

struct socket_values{
	char ip_addr[IPADDSIZE];
	int s_port_udp;
	int d_port_udp;
	int tcp_h_port;
	int tcp_t_port;
	int client_addr;
	int udp_payload;
	int inter_mes_time;
	int num_udp_pack;
	int ttl;
};

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


// change ttl here
//

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

void get_address(char* buf, char* ip_add) {
	
	char cpy_buf[MAXDATASIZE];
	strcpy(cpy_buf, buf);

	char* token = strtok(cpy_buf, "\n");
	token = strtok(NULL, "\n");

	strtok(token,":");
	char* t_ip_add = strtok(NULL,": \"");

	int iplen = strlen(t_ip_add);
	
	t_ip_add[iplen] = '\0';
	strcpy(ip_add, t_ip_add);


}

// uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
uint16_t checksum (uint16_t *addr, int len);
uint16_t udp4_checksum (struct ip iphdr, struct udphdr udphdr, uint8_t *payload, int payloadlen);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);
uint16_t tcp4_checksum (struct ip iphdr, struct tcphdr tcphdr);


int main(int argc, char *argv[]) {
	FILE *fp;
	char ch;
	int sockfd, numbytes;
	char buf[MAXDATASIZE];
	struct addrinfo hints, *servinfo, *p;
	int rv;
	char s[INET6_ADDRSTRLEN];
	char ip_add[INET6_ADDRSTRLEN];
	// struct udphdr udphdr;
	
	if (argc < 3) {
		perror("usage: missing json file, and host ip because I do not know how to get the host IP Needs: myconfig.json <host ip>");
		exit(1);
	}
    
	fp = fopen(argv[1] ,"r");
	if (fp == NULL) {
		perror("Error while opening the file.\n");
		exit(1);
	}

	int i;
	i = 0;

	memset(buf, 0, MAXDATASIZE);

	while((ch = fgetc(fp)) != EOF) {
		buf[i] = ch;
		i += 1;
	}
	buf[i] = '\0';

	fclose(fp);

	if (buf[0] == '0') {
	    fprintf(stderr,"usage: file is empty\n");
	    exit(1);
	}

	get_address(buf, ip_add);// for tcp connection
	struct socket_values sock_val;
	memset(&sock_val, 0 , sizeof(sock_val));
	memset(&sock_val.ip_addr, 0, IPADDSIZE);
	fill_struct(buf, &sock_val);
	
	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char port[65535];
        snprintf(port, sizeof(port), "%d", sock_val.tcp_h_port);
	if ((rv = getaddrinfo(ip_add, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and connect to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}
//        printf("" p->ai_addr);
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			perror("client: connect");
			close(sockfd);
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		return 2;
	}

	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),
			s, sizeof s);
//	printf("client: connecting to %s\n", s);

	freeaddrinfo(servinfo); // all done with this structure

	if (send(sockfd, buf, MAXDATASIZE, 0) == -1) {
		perror("send");
	}
	
	char new_buf[8];

	if ((numbytes = recv(sockfd, new_buf, 7, 0)) == -1) {
	     perror("recv");
	     exit(1);
	}

	new_buf[numbytes] = '\0';

	printf("client: received '%s'\n",new_buf);

	close(sockfd);

	// THIS NEEDS TO BE UDP PACKETS SENT TO THE SERVER . 
	// Ima going to send raw udp packets because I messed up in this project
	
	int status, datalen, frame_length, sd, bytes, *ip_flags;
	char *interface, *target, *src_ip, *dst_ip;
	struct ip iphdr;
	struct udphdr udphdr;
	uint8_t *data, *dst_mac, *ether_frame;
	struct addrinfo *res;
	struct sockaddr_in sin, *ipv4;
	struct sockaddr_ll device;
//  struct ifreq ifr;
	void *tmp;

  // Allocate memory for various arrays.
	// src_mac = allocate_ustrmem (6);
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
	memset(ether_frame ,0, IP_MAXPACKET);
	memset (&sin, 0, sizeof(sin));
	memset (&device, 0, sizeof (device));
	memset (&hints, 0, sizeof(hints));
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
	
	// need the ip address
	// return 0;
	strcpy (src_ip, argv[2]); // mom

	// Destination URL or IPv4 address: you need to fill this out 
	strcpy (target, sock_val.ip_addr); // son
    
    // Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = 0;
	
  // Resolve target using getaddrinfo().
	char port2[65535];
        snprintf(port2, sizeof(port2), "%d", sock_val.tcp_h_port);
	if ((status = getaddrinfo (target, port2, &hints, &res)) != 0) {
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
	
	sin.sin_family = AF_INET;
    //udp port
	sin.sin_port = htons(sock_val.d_port_udp);
	sin.sin_addr.s_addr = inet_addr(target);
sin.sin_port = htons(sock_val.tcp_h_port);
	datalen = sock_val.udp_payload;// payload size set 
	memset(data, 0, datalen);// PACKET DATA SET TO ALL 0s 

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
	ip_flags[1] = 1;// DONT BREAK UP HERE

    // More fragments following flag (1 bit)
	ip_flags[2] = 0;

    // Fragmentation offset (13 bits)
	ip_flags[3] = 0;

	iphdr.ip_off = htons ((ip_flags[0] << 15)
			+ (ip_flags[1] << 14)
			+ (ip_flags[2] << 13)
			+  ip_flags[3]);

    // Time-to-Live (8 bits): increament this by 1
	iphdr.ip_ttl = 0;

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
    // iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    // UDP header
    // Source port number (16 bits): pick a number
	udphdr.uh_sport = htons (sock_val.s_port_udp);

    // Destination port number (16 bits): pick a number
	udphdr.uh_dport = htons (sock_val.d_port_udp);

    // Length of UDP datagram (16 bits): UDP header + UDP data
	udphdr.uh_ulen = htons (UDP_HDRLEN + datalen);

    // UDP checksum (16 bits)
	udphdr.uh_sum = 0;
    // udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);

    // Fill out ethernet frame header.

    // Ethernet frame length = ethernet data (IP header + UDP header + UDP data)
	frame_length = IP4_HDRLEN + UDP_HDRLEN + datalen;
	if ((sd = socket (PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
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
		iphdr.ip_id = htons (num_pack);// ID SET HERE

		iphdr.ip_ttl = packet_id; // packet ttl is set here
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
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, p_id, 16);// PACKET ID SET HERE

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

    
	memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, data, datalen);/// DOES THE RANDOM DATA SET HERE?????????
    
	index = 0;
    
	printf("Now I must sleep for %d, for the packets to get to the destination\n", sock_val.inter_mes_time);
  
	sleep(sock_val.inter_mes_time);
    
	printf("Waking up and sending random data\n");
    
	num_pack = rand(); // sock_val.num_udp_pack
    
	packet_id = 0;
    
    
	printf("Starting to send the high entropy data\n");
    
	while (index < sock_val.num_udp_pack) {
	    
		iphdr.ip_id = htons (num_pack);

		iphdr.ip_ttl = packet_id;// ttl is set here too.

    		iphdr.ip_sum = checksum ((uint16_t *) &iphdr, IP4_HDRLEN);

    
		udphdr.uh_sum = udp4_checksum (iphdr, udphdr, data, datalen);

            // IPv4 header
        
	    	memcpy (ether_frame, &iphdr, IP4_HDRLEN);

            // UDP header
            
		memcpy (ether_frame + IP4_HDRLEN, &udphdr, UDP_HDRLEN);

            // UDP data
            
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, data, datalen);

            
		sprintf(p_id, "%hu", packet_id);
            
		memcpy (ether_frame + IP4_HDRLEN + UDP_HDRLEN, p_id, 16);// PACKET ID SET HERE

            
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
    
	close(sd);

    
	printf("Now sending TCP tail packet to get the answer if there is any compression on the wire.\n");
    
	sleep(3); // for the server to catch up
    
	char message[18];
    
	memset(message, 0, 18);
    
	strcpy(message,"What's the scoop?");
    
    
	memset(&hints, 0, sizeof(hints));
    
	hints.ai_family = AF_UNSPEC;
    
	hints.ai_socktype = SOCK_STREAM;
    
	hints.ai_flags = AI_PASSIVE; // use my IP
    
    
	memset(&servinfo, 0, sizeof(servinfo));

	char client_addr[IPADDSIZE];
	memset(client_addr, 0, IPADDSIZE);
	snprintf(client_addr, sizeof(client_addr), "%d", sock_val.client_addr);
	if ((rv = getaddrinfo(ip_add, client_addr, &hints, &servinfo)) != 0) {   
	    
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
	    
		return 1;
    
	}
    
    // loop through all the results and connect to the first we can

    
	for(p = servinfo; p != NULL; p = p->ai_next) {
	    
		if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                        
			perror("client: socket");
                        
			continue;
	    
		}
	    
		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
		    
			perror("client: connect");
		    
			close(sockfd);
		    
			continue;    
	    
		}    
	    
		break;
        
    
	}

    
	if (p == NULL) {
	    
		fprintf(stderr, "client: failed to connect\n");
	    
		return 2;    
    
	}
    
    
	inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr),s, sizeof s);
    
    
	freeaddrinfo(servinfo); // all done with this structure
    

    
	if (send(sd, message, 18, 0) == -1) {
	    
		perror("send");
    
	}

    
	char compress[30];
    
    
	if ((numbytes = recv(sd, compress, MAXDATASIZE, 0)) == -1) {
	    
		perror("recv");
	    
		exit(1);
    
	}
    
	compress[numbytes] = '\0';
    
	printf("%s\n", compress);

    
	close(sd);

    // Free allocated memory.
    // free (src_mac);
    
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
