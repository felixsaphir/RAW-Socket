/*
 * Network.c
 *
 *  Created on: Aug 5, 2018
 *      Author: Yoram Finder
 *
 *      Put all NW related calls in one source file.
 *
 */

#include <stdio.h>
#include <winsock2.h>

#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1) //this removes the need of mstcpip.h

#define MAX_HEX 16
#define SPACE 10
#define MAX_LINE 75 // 3x16 + 10 + 16 + 1


/*
 * set static variables
 */
static WSADATA	wsaData;

typedef struct _IP_HDR
{
	/*
	 * Bytes are organized by Big Endian order
	 */
	unsigned char ihl : 4;
	unsigned char version :4;
	unsigned char dscp :6;
	unsigned char ecn :2;
	unsigned short Total_lenght;
	unsigned short identification;
	unsigned char fragment1 :5;
	unsigned char f_mf :1;
	unsigned char f_df :1;
	unsigned char f_r :1;
	unsigned char fragment2;
	unsigned char time2live;
	unsigned char protocol;
	unsigned short checksum;
	unsigned long Source_IP_add;
	unsigned long Dest_IP_add;
} IP_HDR;

static char const *protocols[8] = {"ICMP", "IGMP", "TCP", "UDP", "ENCAP", "OSPF", "SCTP", "UNDEFINED"};

typedef struct _TCP_HDR
{
	unsigned short source_p;
	unsigned short dest_p;
	unsigned long Sequence;
	unsigned long Ack;
	unsigned char resrv1 :4;
	unsigned char len :4;
	unsigned char resrv2 :2;
	unsigned char flags :6;
	unsigned char window;
	unsigned char checksum;
	unsigned char pointer;
} TCP_HDR;

typedef struct _UDP_HDR
{
	unsigned short source_p;
	unsigned short dest_p;
	unsigned short len;
	unsigned short checksum;
} UDP_HDR;

typedef struct _ICMP_HDR
{
	unsigned char type;
	unsigned char code;
	unsigned short checksum;
	unsigned long rest;
} ICMP_HDR;

static int print_ICMP_HDR (unsigned char *buff)
{
	ICMP_HDR *icmp_hdrp;

	icmp_hdrp = (ICMP_HDR *)buff;

	printf("  | ICMP Header\n");
	printf("  | ===========\n");

	printf("  | Type: %d\n", icmp_hdrp->type);
	printf("  | Code: %d\n", icmp_hdrp->code);
	printf("  | Checksum: %x\n", ntohs(icmp_hdrp->checksum));
	printf("  | Rest of header: %lx\n\n", ntohl(icmp_hdrp->rest));

	return 8; //ICMP header length is fixed 8 bytes
}


static int print_UDP_HDR (unsigned char *buff)
{
	UDP_HDR *udp_hdrp;

	udp_hdrp = (UDP_HDR *)buff;

	printf("  | UDP Header\n");
	printf("  | ============\n");

	printf("  | Source_p: %d\n", ntohs(udp_hdrp->source_p));
	printf("  | Dest_p: %d\n", ntohs(udp_hdrp->dest_p));
	printf("  | UDP Msg length: %d\n", ntohs(udp_hdrp->len));
	printf("  | Checksum: %x\n\n", ntohs(udp_hdrp->checksum));

	return 8; //UDP header length is fixed 8 bytes
}

static int print_TCP_HDR (unsigned char *buff)
{
	TCP_HDR *tcp_hdrp;

	tcp_hdrp = (TCP_HDR *)buff;

	printf("  | TCP Header:\n");
	printf("  | ============\n");
	printf("  | Source_p: %d\n", ntohs(tcp_hdrp->source_p));
	printf("  | Destination_p: %d\n", ntohs(tcp_hdrp->dest_p));
	printf("  | Sequence: %lu\n", ntohl(tcp_hdrp->Sequence));
	printf("  | Ack: %lu\n", ntohl(tcp_hdrp->Ack));
	printf("  | HDR length: %d\n", tcp_hdrp->len*4);
	printf("  | Flags: %x\n", tcp_hdrp->flags);
	printf("  | Window: %d\n", tcp_hdrp->window);
	printf("  | Checksum: %x\n", tcp_hdrp->checksum);
	printf("  | Pointer: %x\n\n", tcp_hdrp->pointer);

	return tcp_hdrp->len*4; //Length represents 32bit words
}

static int print_Proto_HDR(unsigned char *buff, unsigned char protocol)
{
	switch (protocol)
	{
	case 1:
		return print_ICMP_HDR (buff);
	case 6:
		return print_TCP_HDR (buff);
	case 17:
		return print_UDP_HDR (buff);
	default:
		return 0;
	}
}


static char const *proto (unsigned char protocol)
{
	int pid;

	switch (protocol)
	{
	case 1:
		pid = 0;
		break;
	case 2:
		pid = 1;
		break;
	case 6:
		pid = 2;
		break;
	case 17:
		pid = 3;
		break;
	case 41:
		pid = 4;
		break;
	case 89:
		pid = 5;
		break;
	case 132:
		pid = 6;
		break;
	default:
		pid = 7;
	}

	return protocols[pid];
}

/*
 * print the IP header.
 * return the size of the header in bytes - will be used to point to the IP DATA location.
 */
static int print_IP_HDR (unsigned char *buff)
{
	struct sockaddr_in source, dest;
	IP_HDR *ip_hdrp;

	/*
	 * retrieve shource and destination IP addresses
	 */
	ip_hdrp = (IP_HDR *)buff;

	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = ip_hdrp->Source_IP_add;

	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = ip_hdrp->Dest_IP_add;


	printf("================================ IP frame ================================\n");
	printf("IP Header\n");
	printf("-----------\n");
	printf("| IP Version: %d\n", ip_hdrp->version);
	printf("| IP Hdr Length: %d\n", ip_hdrp->ihl*4);
	printf("| DSCP: %0x\n", ip_hdrp->dscp);
	printf("| ECN: %0x\n", ip_hdrp->ecn);
	printf("| Total Length: %d\n", ntohs(ip_hdrp->Total_lenght));
	printf("| Identification: %d\n", ntohs(ip_hdrp->identification));
	printf("| F_MF: %0x\n", ip_hdrp->f_mf);
	printf("| F_DF: %0x\n", ip_hdrp->f_mf);
	printf("| F_R: %0x\n", ip_hdrp->f_r);
	printf("| Time2Live: %d\n", ip_hdrp->time2live);
	printf("| Protocol: %s (%d)\n", proto(ip_hdrp->protocol), ip_hdrp->protocol);
	printf("| Source_IP: %s\n", inet_ntoa(source.sin_addr));
	printf("| Destination_IP: %s\n", inet_ntoa(dest.sin_addr));
	printf("\n\n");

	return ip_hdrp->ihl*4; //IHL holds the heade length in 32bit words
}

static char ascii (char c)
{
	if ((c> 31) && (c < 127))
		return c;
	else
		return '.';
}

static void printData(unsigned char *buff, int length, char *printstr)
{
	int i;
	int hexpos = 0;
	int asciipos = 3*MAX_HEX+SPACE;

	/*
	 * construct HEX and ASCII presentation of input buffer
	 */
	for (i = 0; i < length; i++)
	{
		sprintf(&printstr[hexpos], "%02x ", buff[i]);
		hexpos += 3;
		sprintf(&printstr[asciipos], "%c", ascii(buff[i]));
		asciipos++;
	}

	/*
	 * in case inbput buffer is shorter than MAX_HEX complete empty spaces with space char
	 */
	if (length < MAX_HEX)
	{
		for (i = length; i < MAX_HEX; i++)
		{
			printstr[hexpos++] = ' ';
			printstr[hexpos++] = ' ';
			printstr[hexpos++] = ' ';
			printstr[asciipos++] = ' ';
		}
	}

	/*
	 * Fill the space between HEX and ASCII chars
	 */
	hexpos = 3*MAX_HEX;
	for (i = 0; i < SPACE; i++)
		printstr[hexpos++] = ' ';

	/*
	 * add EOS
	 */
	printstr[MAX_LINE-1] = '\0';

	/*
	 * print out the new string
	 */
	printf("%s\n", printstr);
}


int NW_inint (char *ip_addr)
{
	  int	sock, j;
	  int	stat;
	  char	local_ip[100];
	  struct sockaddr_in dest;
	  int	in;


	  // load WS2_32.DLL
	    if ((stat = WSAStartup(MAKEWORD(2, 2), &wsaData)) != 0)
	    {
	    	printf("Error loading Ws2_32.DLL, error: %d\n", WSAGetLastError());
	    	WSACleanup();
	    	return -1;
	    }

	    if ((sock = socket(PF_INET, SOCK_RAW, IPPROTO_IP)) == INVALID_SOCKET) //Allocate TCP Socket
	    {
	    	printf("Error creating socket, error: %d\n", WSAGetLastError());
	    	WSACleanup();
	    	return -1;
	    }
	    memset(&dest, 0, sizeof(dest)); //clear socket address
		dest.sin_family = AF_INET;
		dest.sin_port = 0;
		dest.sin_addr.s_addr = inet_addr(local_ip);


		if ((stat = bind(sock, (struct sockaddr *) &dest, sizeof(dest))) == SOCKET_ERROR) //(*@\serverBox{1)}@*)
		{
			printf("Error calling bind(), error: %d\n", WSAGetLastError());
			WSACleanup();
			return -1;
	    }

		printf("Binding successful");

		//Enable SIO_RCVALL - to Receive ALL ;)

		j=1;
		printf("\nSetting socket to sniff...");
		if (WSAIoctl(sock, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
		{
			printf("WSAIoctl() failed. Error: %d\n", WSAGetLastError());
			return -1;
		}
		printf("Socket set.");

		//Begin
		printf("\nStarted Sniffing\n");
		printf("Packet Capture Statistics...\n");


	return sock;
}

void NW_close (int sock)
{
	  closesocket(sock);
	  WSACleanup(); //Disconnect WS2_32.DLL
}


void NW_Print_IP (char *buff, int len)
{
	int i, k, l;
	IP_HDR *ip_hdrp;
	char	printstr[MAX_LINE+1];

	/*
	 * print IP Header
	 */
	i = print_IP_HDR((unsigned char *)buff);

	ip_hdrp = (IP_HDR *)buff;
	i += print_Proto_HDR((unsigned char *)&buff[i], ip_hdrp->protocol);

	printf("Packet payload:\n");
	printf("===============\n");

	while (i < len)
	{
		  l = len - i;
		  k = (l > MAX_HEX ? MAX_HEX: l);
		  printData((unsigned char *)&buff[i], k, printstr);
		  i += k;
	}
}

