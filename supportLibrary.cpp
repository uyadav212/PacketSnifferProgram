/*	
*Support library written by Utkarsh yadav 21535035
*
*	Funtions exposed:
*		1)	void processTCPPacket(const u_char *, int)
*				To process and print the TCP header fields into the log file named "logTCP.txt"
*
*		2)	void processUDPPacket(const u_char *, int)
*				To process and print the UDP header fields into the log file named "logUDP.txt"
*
*		3)	void processICMPPacket(const u_char *, int)
*				To process and print the TCP header fields into the log file named "logICMP.txt"
*
*		4)	void processPayload (const u_char *, int, FILE *)
*				To process and dump all the data received in the packet.
*
*		5)	void processIPHeader(const u_char *, int, FILE *)
*				To process and print the IP header fields from the packets into the log files depending on the protocol of packets.
*/

class PacketHandle {

public:
	FILE *tcpLogFile;
	FILE *udpLogFile;
	FILE *icmpLogFile;
	struct sockaddr_in sourceAddr;
	struct sockaddr_in destAddr;

	PacketHandle() {
		memset(&sourceAddr, 0, sizeof(sourceAddr));
		memset(&destAddr, 0, sizeof(destAddr));
	};

	void processTCPPacket(const u_char *  ,int);
	void processUDPPacket(const u_char * ,int);
	void processICMPPacket(const u_char * ,int);
	void processIPHeader(const u_char * ,int ,FILE *);
	void processPayload (const u_char * ,int ,FILE *);
};

void PacketHandle::processIPHeader(const u_char * buffer, int headerSize, FILE *logFile)
{
  	struct ethhdr *ethernetHeader = (struct ethhdr *) buffer;
	
	fprintf(logFile ,"\nEthernet Header\n");
	fprintf(logFile ,"   |Source Address      | %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernetHeader->h_source[0], ethernetHeader->h_source[1], ethernetHeader->h_source[2], ethernetHeader->h_source[3], ethernetHeader->h_source[4], ethernetHeader->h_source[5]);
	fprintf(logFile ,"   |Destination Address | %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", ethernetHeader->h_dest[0], ethernetHeader->h_dest[1], ethernetHeader->h_dest[2], ethernetHeader->h_dest[3], ethernetHeader->h_dest[4], ethernetHeader->h_dest[5]);
	fprintf(logFile ,"   |Protocol            | %u \n",(unsigned short)ethernetHeader->h_proto);

	struct iphdr *ipHeader = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	
	sourceAddr.sin_addr.s_addr = ipHeader->saddr;
	destAddr.sin_addr.s_addr = ipHeader->daddr;
	
	fprintf(logFile, "\nIP Header\n");
	fprintf(logFile, "   |IP Version        | %d\n", (unsigned int)ipHeader->version);
	fprintf(logFile, "   |IP Header Length  | %d Bytes\n",((unsigned int)(ipHeader->ihl)) * 4);
	fprintf(logFile, "   |Type Of Service   | %d\n", (unsigned int)ipHeader->tos);
	fprintf(logFile, "   |IP Total Length   | %d Bytes(Packet Size)\n", ntohs(ipHeader->tot_len));
	fprintf(logFile, "   |Identification    | %d\n", ntohs(ipHeader->id));
	fprintf(logFile, "   |TTL				| %d\n", (unsigned int)ipHeader->ttl);
	fprintf(logFile, "   |Protocol			| %d\n", (unsigned int)ipHeader->protocol);
	fprintf(logFile, "   |Checksum			| %d\n", ntohs(ipHeader->check));
	fprintf(logFile, "   |Source IP        	| %s\n", inet_ntoa(sourceAddr.sin_addr) );
	fprintf(logFile, "   |Destination IP   	| %s\n", inet_ntoa(destAddr.sin_addr) );
}

void PacketHandle::processTCPPacket(const u_char * buffer, int headerSize) {
	
	struct iphdr *ipHeader = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	unsigned short ipHeaderLen = (ipHeader->ihl * 4);
	
	struct tcphdr *tcpHeader = (struct tcphdr*)(buffer + ipHeaderLen + sizeof(struct ethhdr));	
	int tcpHeaderLen =  sizeof(struct ethhdr) + ipHeaderLen + (tcpHeader->doff * 4);
	
	fprintf(tcpLogFile , "\n\n***********************TCP Packet*************************\n");	
		
	processIPHeader(buffer,headerSize, tcpLogFile);
		
	fprintf(tcpLogFile, "\nTCP Header\n");
	fprintf(tcpLogFile, "   |Source Port      		| %u\n", ntohs(tcpHeader->source));
	fprintf(tcpLogFile, "   |Destination Port 		| %u\n", ntohs(tcpHeader->dest));
	fprintf(tcpLogFile, "   |Sequence Number		| %u\n", ntohl(tcpHeader->seq));
	fprintf(tcpLogFile, "   |Acknowledge Number		| %u\n", ntohl(tcpHeader->ack_seq));
	fprintf(tcpLogFile, "   |Header Length			| %d BYTES\n", (unsigned int)tcpHeader->doff * 4);
	fprintf(tcpLogFile, "   |Urgent Flag          	| %d\n", (unsigned int)tcpHeader->urg);
	fprintf(tcpLogFile, "   |Acknowledgement Flag 	| %d\n", (unsigned int)tcpHeader->ack);
	fprintf(tcpLogFile, "   |Push Flag            	| %d\n", (unsigned int)tcpHeader->psh);
	fprintf(tcpLogFile, "   |Reset Flag           	| %d\n", (unsigned int)tcpHeader->rst);
	fprintf(tcpLogFile, "   |Synchronise Flag     	| %d\n", (unsigned int)tcpHeader->syn);
	fprintf(tcpLogFile, "   |Finish Flag          	| %d\n", (unsigned int)tcpHeader->fin);
	fprintf(tcpLogFile, "   |Window         		| %d\n", ntohs(tcpHeader->window));
	fprintf(tcpLogFile, "   |Checksum       		| %d\n", ntohs(tcpHeader->check));
	fprintf(tcpLogFile, "   |Urgent Pointer 		| %d\n", tcpHeader->urg_ptr);
	fprintf(tcpLogFile, "\n                        DATA Dump                         \n");
	
	fprintf(tcpLogFile , "IP Header\n");
	processPayload(buffer, ipHeaderLen, tcpLogFile);
		
	fprintf(tcpLogFile , "TCP Header\n");
	processPayload((buffer + ipHeaderLen), (tcpHeader->doff * 4), tcpLogFile);
		
	fprintf(tcpLogFile , "Data Payload\n");	
	processPayload((buffer + tcpHeaderLen), (headerSize - tcpHeaderLen), tcpLogFile);
						
	fprintf(tcpLogFile , "\n###########################################################");
}

void PacketHandle::processUDPPacket(const u_char *buffer , int headerSize) {

	struct iphdr *ipHeader = (struct iphdr *)(buffer +  sizeof(struct ethhdr));
	unsigned short ipHeaderLen = (ipHeader->ihl * 4);
	
	struct udphdr *udpHeader = (struct udphdr*)(buffer + ipHeaderLen  + sizeof(struct ethhdr));
	int udpHeaderLen =  sizeof(struct ethhdr) + ipHeaderLen + sizeof(udpHeader);
	
	fprintf(udpLogFile , "\n\n***********************UDP Packet*************************\n");
	
	processIPHeader(buffer,headerSize, udpLogFile);			
	
	fprintf(udpLogFile, "\nUDP Header\n");
	fprintf(udpLogFile, "   |Source Port      	| %d\n" , ntohs(udpHeader->source));
	fprintf(udpLogFile, "   |Destination Port 	| %d\n" , ntohs(udpHeader->dest));
	fprintf(udpLogFile, "   |UDP Length       	| %d\n" , ntohs(udpHeader->len));
	fprintf(udpLogFile, "   |UDP Checksum     	| %d\n" , ntohs(udpHeader->check));
	fprintf(udpLogFile, "\n                        DATA Dump                         \n");
	
	fprintf(udpLogFile, "IP Header\n");
	processPayload(buffer, ipHeaderLen, udpLogFile);
		
	fprintf(udpLogFile, "UDP Header\n");
	processPayload((buffer + ipHeaderLen) , sizeof(udpHeader), udpLogFile);
		
	fprintf(udpLogFile, "Data Payload\n");	
	
	//Move the pointer ahead and reduce the size of string
	processPayload((buffer + udpHeaderLen), (headerSize - udpHeaderLen), udpLogFile);
	
	fprintf(udpLogFile, "\n###########################################################");
}

void PacketHandle::processICMPPacket(const u_char * buffer , int headerSize) {
	
	struct iphdr *ipHeader = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	unsigned short ipHeaderLen = (ipHeader->ihl * 4);
	
	struct icmphdr *icmpHeader = (struct icmphdr *)(buffer + ipHeaderLen  + sizeof(struct ethhdr));
	int icmpHeaderLen =  sizeof(struct ethhdr) + ipHeaderLen + sizeof(icmpHeader);
	
	fprintf(icmpLogFile , "\n\n***********************ICMP Packet*************************\n");	
	
	processIPHeader(buffer, headerSize, icmpLogFile);
			
	fprintf(icmpLogFile, "\nICMP Header\n");
	fprintf(icmpLogFile, "   |Type 			| %d", (unsigned int)(icmpHeader->type));	
	if ((unsigned int)(icmpHeader->type) == 11) {
		fprintf(icmpLogFile , "  (TTL Expired)\n");
	}
	else if((unsigned int)(icmpHeader->type) == ICMP_ECHOREPLY) {
		fprintf(icmpLogFile , "  (ICMP Echo Reply)\n");
	}
	
	fprintf(icmpLogFile , "   |Code 		| %d\n",(unsigned int)(icmpHeader->code));
	fprintf(icmpLogFile , "   |Checksum 	| %d\n",ntohs(icmpHeader->checksum));
	fprintf(icmpLogFile, "\n                        DATA Dump                         \n");

	fprintf(icmpLogFile , "IP Header\n");
	processPayload(buffer,ipHeaderLen, icmpLogFile);
		
	fprintf(icmpLogFile , "UDP Header\n");
	processPayload(buffer + ipHeaderLen , sizeof icmpHeader, icmpLogFile);
		
	fprintf(icmpLogFile , "Data Payload\n");
	processPayload((buffer + icmpHeaderLen) , (headerSize - icmpHeaderLen), icmpLogFile);
	
	fprintf(icmpLogFile , "\n###########################################################");
}

void PacketHandle::processPayload (const u_char * payload , int headerSize, FILE *logFile) {
	
	for(int i = 0; i < headerSize; i++)	{
		
		if( (i != 0) && (i%16 == 0)) {   //if one line of hex printing is complete...
		
			fprintf(logFile, "         ");
			for(int j = (i - 16); j < i; j++) {
				
				if(payload[j] >= 32 && payload[j] <= 128)
					fprintf(logFile, "%c", (unsigned char)payload[j]); //if its a number or alphabet
				else 
					fprintf(logFile, "."); //otherwise print a dot
			}
			fprintf(logFile , "\n");
		} 
		
		if(i%16 == 0)
			fprintf(logFile, "   ");
		fprintf(logFile, " %02X",(unsigned int)payload[i]);
				
		if(i == (headerSize - 1)) {  //print the last spaces
		
			for(int j = 0; j < (15 - i%16); j++) 
				fprintf(logFile, "   "); //extra spaces
			
			fprintf(logFile, "         ");
			
			for(int j = (i - i%16); j <= i; j++) {
				
				if(payload[j] >= 32 && payload[j] <= 128) 
					fprintf(logFile, "%c", (unsigned char)payload[j]);
				else 
					fprintf(logFile, ".");
			}
			fprintf(logFile, "\n" );
		}
	}
}
