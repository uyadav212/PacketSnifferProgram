/*	Problem Statement:
*	Write a sniffer program that has following basic functionality:
*			i.		Captures packets and stores them in a file
*			ii.		User can select packets by
*							1.	protocol (TCP, UDP or ICMP) or
*							2.	source address and protocol
*					and display contents of the header fields of the packet.
*
*/

#include<pcap.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>							//ICMP header
#include<netinet/udp.h>								//UDP header
#include<netinet/tcp.h>								//TCP header
#include<netinet/ip.h>								//IP header
#include<bits/stdc++.h>

#include "supportLibrary.cpp"						//Support library written by utkarsh yadav
using namespace std;

PacketHandle *packetOpp;							//defined in support library
string sniffOnSource;
bool sniffTCP = false;
bool sniffUDP = false;
bool sniffICMP = false;

int tcpPacketCount = 0;								//varibles to count the number of packets sniffed
int udpPacketCount = 0;
int icmpPacketCount = 0;
int totalPacketCountOnSource = 0;
int totalPacketCountAnySource = 0;

void packetProcessing(u_char *args, const struct pcap_pkthdr *packetHeader, const u_char *buffer) {
		
	struct iphdr *ipHeader;											//Get IP Header of this packet, not the ethernet header
	ipHeader = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	totalPacketCountAnySource++;

	struct sockaddr_in packetSourceAddr;
	memset(&packetSourceAddr, 0, sizeof(packetSourceAddr));
	packetSourceAddr.sin_addr.s_addr = ipHeader->saddr;

	if ((0 == strcmp(inet_ntoa(packetSourceAddr.sin_addr), sniffOnSource.c_str()))
		||	(0 == strcmp("*", sniffOnSource.c_str()))) {								//check the source address on packet

		totalPacketCountOnSource++;
		switch (ipHeader->protocol) 													//check the packet protocol
		{
			case 1:  //ICMP Protocol
					if (sniffICMP) {
						icmpPacketCount++;
						packetOpp->processICMPPacket(buffer , packetHeader->len);
					}
					break;
			
			case 6:  //TCP Protocol
					if (sniffTCP) {
						tcpPacketCount++;
						packetOpp->processTCPPacket(buffer , packetHeader->len);
					}
					break;
			
			case 17: //UDP Protocol
					if (sniffUDP) {
						udpPacketCount++;
						packetOpp->processUDPPacket(buffer , packetHeader->len);
					}
					break;
			
			default: //Other protocol [ARP, IGMP, etc]
					break;
		}
	}

	printf(": Packet Count ==> TCP [%d]  |  UDP [%d]  |  ICMP [%d]  |  Total packets (source %s) [%d]  |  Total packets (any source) [%d]\r", tcpPacketCount, udpPacketCount, icmpPacketCount, sniffOnSource.c_str(), totalPacketCountOnSource, totalPacketCountAnySource);
}

int main() {
	
	pcap_t *sniffHandler; 														//Handler that will be used while sniffing
	string sniffOnWifi = "wlp3s0";
	char errorBuffer[100];
	
	sniffHandler = pcap_open_live(sniffOnWifi.c_str() ,65536 ,1 ,0 ,errorBuffer);		//Sniffing on WIFI connection
	if(sniffHandler == NULL) {
		
		cout << ": Unable to open " << sniffOnWifi << " [WIFI] for sniffing. \t\t [Error description: " << errorBuffer << " ]\n";
		exit(1);
	}

	cout << ":\n: Sniffing on WIFI ...\t\t\t [Device name: " << sniffOnWifi << "]\n:\n";
	packetOpp = new PacketHandle();

	packetOpp->tcpLogFile = fopen("logTCP.txt", "w");									//open all log files
	packetOpp->udpLogFile = fopen("logUDP.txt", "w");
	packetOpp->icmpLogFile = fopen("logICMP.txt", "w");
	
	if(packetOpp->tcpLogFile == NULL 
		|| packetOpp->udpLogFile == NULL
		|| packetOpp->icmpLogFile == NULL) {
		
		cout << ": Unable to open log files...\t\t\t[Please try again]\n";		//if any log file is not able to open show error
		exit(1);
	}

	cout << ": Enter source address of packets to be sniffed";
	cout << "\n: [NOTE- Enter * to sniff packet from any source address]\n: ";
	cin >> sniffOnSource;

	int tmp = 0;
	cout << ": Do you want to sniff TCP packets [0 means NO else YES]- ";
	cin >> tmp;
	(tmp)? sniffTCP = true:sniffTCP = false;
	tmp = 0;

	cout << ": Do you want to sniff UDP packets [0 means NO else YES]- ";
	cin >> tmp;
	(tmp)? sniffUDP = true:sniffUDP = false;
	tmp = 0;

	cout << ": Do you want to sniff ICMP packets [0 means NO else YES]- ";
	cin >> tmp;
	(tmp)? sniffICMP = true:sniffICMP = false;
	cout << endl;

	if (sniffTCP || sniffUDP || sniffICMP)
		pcap_loop(sniffHandler ,-1 ,packetProcessing ,NULL);						//Sniff in loop using the handler
	else
		cout << ": You don't want to sniff any packet. EXITING....\n";

	return 0;	
}