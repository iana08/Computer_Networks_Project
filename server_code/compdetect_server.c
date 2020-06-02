/*
** server.c -- a stream socket server demo
*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <bits/ioctls.h>
#include <net/if.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <time.h>

#define PORT "3495"  // the port users will be connecting to
#define MAXDATASIZE 65535
#define BACKLOG 10	 // how many pending connections queue will hold
#define IP4_HDRLEN 20
#define UDP_HDRLEN 8
#define IPADDSIZE 32

uint16_t checksum (uint16_t *addr, int len);
uint16_t udp4_checksum (struct ip, struct udphdr, uint8_t *, int);
char *allocate_strmem (int);
uint8_t *allocate_ustrmem (int);
int *allocate_intmem (int);

void sigchld_handler(int s)
{
	(void)s; // quiet unused variable warning

	// waitpid() might overwrite errno, so we save and restore it:
	int saved_errno = errno;

	while(waitpid(-1, NULL, WNOHANG) > 0);

	errno = saved_errno;
	
	
}

void get_port(char * buf, char port[]) {
	char cpy_buf[MAXDATASIZE];
	memset(cpy_buf, 0, MAXDATASIZE);
	strcpy(cpy_buf, buf);
	char * token = strtok(cpy_buf, "\n");
	token = strtok(NULL, "\n");// {
	token = strtok(NULL, "\n");// ip addrs
	char * new_tok = strtok(token, ":");
	new_tok = strtok(NULL, ": ");
	int len = strlen(new_tok);
	new_tok[len] = '\0';
	len -= 1;
	new_tok[len] = '\0';
	strcpy(port, new_tok);
}


void get_client_addr(char * buf, char client_addr[]) {
	char cpy_buf[MAXDATASIZE];
	memset(cpy_buf, 0, MAXDATASIZE);
	strcpy(cpy_buf, buf);
	char* token = strtok(cpy_buf, "\n");
	int ind = 0;
	while (ind < 6) {
		ind += 1;
		token = strtok(NULL, "\n");
	}
	// printf("%s\n", token);
	char * new_tok = strtok(token, ":");
	new_tok = strtok(NULL, ": ");
	new_tok = strtok(new_tok, "\"");
	// printf("new_tok: %s\n", new_tok);
	int len = strlen(new_tok);
	len -= 1;
	new_tok[len] = '\0';
	strcpy(client_addr, new_tok);
}

void get_num_packets(char * buf, int * num) {
	char cpy_buf[MAXDATASIZE];
	int i = 0;
	memset(cpy_buf, 0, MAXDATASIZE);
	strcpy(cpy_buf, buf);
	char * token = strtok(cpy_buf, "\n");
	while (i < 9) {
		i +=1;
		token = strtok(NULL, "\n");
	}
	// printf("token: %s\n", token); // num udp -packet;
	char * new_tok = strtok(token, ":");
	new_tok = strtok(NULL, ": ");
	int len = strlen(new_tok);
	len -= 1;
	new_tok[len] = '\0';
	*num = atoi(new_tok);
}
// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(int argc, char** argv)
{
	int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information
	socklen_t sin_size;
	struct sigaction sa;
	int yes=1;
	char buf[MAXDATASIZE];
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC; // 4 or 6 
	hints.ai_socktype = SOCK_STREAM; // TCP
	hints.ai_flags = AI_PASSIVE; // use my IP

	if (argc < 2) {
		printf("Missing json file %s \n", *argv);
		exit(1);
	}

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) { // SETTING PORT HERE
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes,
				sizeof(int)) == -1) {
			perror("setsockopt");
			exit(1);
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("server: bind");
			continue;
		}

		break;
	}

	freeaddrinfo(servinfo); // all done with this structure

	if (p == NULL)  {
		fprintf(stderr, "server: failed to bind\n");
		exit(1);
	}

	if (listen(sockfd, BACKLOG) == -1) {
		perror("listen");
		exit(1);
	}

	sa.sa_handler = sigchld_handler; // reap all dead processes
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(1);
	}

	printf("server: waiting for connections...\n");
	
	sin_size = sizeof their_addr;
		
	new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
	if (new_fd == -1) {
		perror("accept");	
	}
		
	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);	
	printf("server: got connection from %s\n", s);
		
	if (!fork()) { // this is the child process	
		close(sockfd); // child doesn't need the listener	
		if ((numbytes = recv(new_fd, buf, MAXDATASIZE, 0)) == -1) {
			perror("recv");
			exit(1);	
		}	
		buf[numbytes] = '\0';	
		if (send(new_fd, "Got It!", 7, 0) == -1){	
			perror("send");
		}	
		close(new_fd); // socket close when done transmiting data.	
		FILE* fptr;	
		fptr = fopen(argv[1], "w+");	
		int i;	
		i = 0;	
		while (buf[i] != '\0') {
			fputc(buf[i], fptr);
			i = i + 1;
		}		
		fclose(fptr);	
		exit(0);
	}	
	close(new_fd);  // parent doesn't need this
	// }
	// get the port number now.
	printf("Now for the UDP packets\n");
	close(sockfd);

	// char buf[MAXDATASIZE];
	memset(&buf, 0, MAXDATASIZE);
	FILE * fptr;
	int i = 0;

	while( (fptr = fopen(argv[1], "r")) == NULL){
		// file is being created by child so pls wait
	}
	
	char ch;
	while ((ch = fgetc(fptr)) != EOF) {
		buf[i] = ch;
		i += 1;
	}
	buf[i] = '\0';

	fclose(fptr);

	if(buf[0] == '0') {
		fprintf(stderr, "usage: file is empty\n");
		return -1;
	}
	char udp_port[16];

	memset(udp_port, 0, 16);

	get_port(buf, udp_port);

	int num_packets;
	num_packets = 0;
	get_num_packets(buf, &num_packets);
	num_packets -= 1;
	int status, sd, bytes, *ip_flags;
  	char *interface, *target, *src_ip, *dst_ip;
  	uint8_t *src_mac, *dst_mac, *ether_frame;
 	struct addrinfo *res;
	struct sockaddr_in servaddr, cliaddr;

	// Allocate memory for various arrays.
	src_mac = allocate_ustrmem (6);
       	dst_mac = allocate_ustrmem (6);
	ether_frame = allocate_ustrmem (IP_MAXPACKET);
	interface = allocate_strmem (40);
	target = allocate_strmem (40);
	src_ip = allocate_strmem (INET_ADDRSTRLEN);
	dst_ip = allocate_strmem (INET_ADDRSTRLEN);
	ip_flags = allocate_intmem (4);

	// Fill out hints for getaddrinfo().
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo (NULL, udp_port ,&hints, &res)) != 0) {
		fprintf (stderr, "getaddrinfo() failed: %s\n", gai_strerror (status));
		exit (EXIT_FAILURE);
	}
        
	if ((sd = socket (PF_INET, SOCK_RAW, IPPROTO_UDP)) < 0) {
		perror ("socket() failed ");
		exit (EXIT_FAILURE);
        }
	
	memset(&cliaddr, 0, sizeof(cliaddr));
        memset(&servaddr, 0 , sizeof(servaddr));

        servaddr.sin_family = AF_INET;
        servaddr.sin_addr.s_addr = INADDR_ANY;
        servaddr.sin_port = htons(atoi(udp_port));
	int tr = 1;
	clock_t start_t, start_h, end_t, total_t, total_h, end_h;
	int second = 0;
	printf("Wating to recieve\n");
	freeaddrinfo (res);
	while(tr) {
		unsigned int len;
		len = sizeof(cliaddr);
		if ((bytes = recvfrom(sd, ether_frame, MAXDATASIZE, 0, (struct sockaddr *) &cliaddr, &len)) < 0) {
			perror("RecvFrom() failed");
			exit(EXIT_FAILURE);
		}
		
		ether_frame[bytes] = '\0';
            // struct iphdr * ip_pack = (struct iphdr *)ether_frame;
	    // struct udphdr * udphdr = (struct udphdr *)(ether_frame + IP4_HDRLEN)
		int boogus_data = 0 ; // boogus data thats in front of the packet data
		char * data = (char *) (ether_frame + IP4_HDRLEN + UDP_HDRLEN + boogus_data);
		int i = 0;
		char id_p[5];
		while (i < 5) {
			id_p[i] = data[i];
			i += 1;
		}
		id_p[5] = '\0';
		int start = 1;
		int id_proc = atoi(id_p);
		if (id_proc == start) {
			if (second){ // should start the timer;
				start_t = clock();
			} else {// should start the second timer;
				start_h = clock();
			}
	    
		}
		if (id_proc == num_packets) {
		    if (second) {
			    end_t = clock();
			    tr = 0; // this will end the while loop, dont touch;
		    } else {
			    end_h = clock();
			    second = 1;
		    }
	    }
	    //printf("Got UDP message\n");
            // i = sizeof(struct ethhdr ) + sizeof(struct iphdr) + sizeof(struct udphdr);
            /*printf("%d\n", i);
	    i = 0;
            for (;i < bytes ; i += 1 ) {
                    printf("%c", ether_frame[i]);
            }
	    printf("\n"); */
	}
	close(sd);

	total_h = (double) (end_h - start_h) / CLOCKS_PER_SEC;
	total_t = (double) (end_t - start_t) / CLOCKS_PER_SEC;
	double total;
	if (total_t < total_h) {
		total = total_h;
	} else {
		total = total_t;
	}

	printf("Now for the tcp connection\n");

	char client_addr[IPADDSIZE];
	memset(client_addr, 0, IPADDSIZE);
	get_client_addr(buf, client_addr);
        // printf("Testing for port: %s\n", client_addr);
	//i just need the port... 
	// use s
	memset(&hints, 0, sizeof hints);
        hints.ai_family = AF_UNSPEC; // 4 or 6 
        hints.ai_socktype = SOCK_STREAM; // TCP
        hints.ai_flags = AI_PASSIVE; // use my IP
        memset(&servinfo, 0, sizeof(servinfo));
        if ((rv = getaddrinfo(NULL, client_addr, &hints, &servinfo)) != 0) { // SETTING PORT HERE
                fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
                return 1;
        }   

	// loop through all the results and connect to the first we can
        for(p = servinfo; p != NULL; p = p->ai_next) {
                if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
                        perror("client: socket");
                        continue;
                }
                
		if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
			perror("setsockopt");
                        exit(1);
                }
		
		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
                        perror("server: bind");
                        continue;
                }

                break;
        }
      
	if (p == NULL)  {
                fprintf(stderr, "server: failed to bind\n");
                exit(1);
       
	}
	
	if (listen(sockfd, BACKLOG) == -1) {
                perror("listen");
                exit(1);
        }
	
	sa.sa_handler = sigchld_handler; // reap all dead processes
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_RESTART;
        if (sigaction(SIGCHLD, &sa, NULL) == -1) {
                perror("sigaction");
                exit(1);
        }
        printf("TCP:server: waiting for connections...\n");

        freeaddrinfo(servinfo); // all done with this structure

	char message[30];
	memset(message,0, 30);
	
	if (total < 0.1) {
		strcpy(message, "No compression was detected");
	}else {
		strcpy(message, "Compression detected.");
	}
	
	sin_size = sizeof their_addr;        
	new_fd = accept(sockfd, (struct sockaddr *)&their_addr, &sin_size);
                
	if (new_fd == -1) {
		perror("accept");
                        // continue;        
	}
        
	inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr *)&their_addr), s, sizeof s);
	printf("server: got connection from %s\n", s);
        
	char new_buf[18];
	if ((numbytes = recv(new_fd, new_buf, MAXDATASIZE, 0)) == -1) {
		perror("recv");
		exit(1);
	}
	new_buf[numbytes] = '\0';
	printf("client: received: %s\n", new_buf);
		
	if (send(new_fd, message, 30, 0) == -1) {
		perror("send");
	}

	close(new_fd);
	// }
//	close(new_fd);  // parent doesn't need this

        close(sockfd);

	// Free allocated memory.
	free (src_mac);
	free (dst_mac);
	free (ether_frame);
	free (interface);
	free (target);
	free (src_ip);
	free (dst_ip);
	free (ip_flags);

	return 0;
}


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
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

  // Copy UDP source port to buf (16 bits)
  memcpy (ptr, &udphdr.source, sizeof (udphdr.source));
  ptr += sizeof (udphdr.source);
  chksumlen += sizeof (udphdr.source);

  // Copy UDP destination port to buf (16 bits)
  memcpy (ptr, &udphdr.dest, sizeof (udphdr.dest));
  ptr += sizeof (udphdr.dest);
  chksumlen += sizeof (udphdr.dest);

  // Copy UDP length again to buf (16 bits)
  memcpy (ptr, &udphdr.len, sizeof (udphdr.len));
  ptr += sizeof (udphdr.len);
  chksumlen += sizeof (udphdr.len);

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
