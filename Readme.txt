NOTE: While compiling we need to point to the directory where we have installed the pcap library.

Use below mentioned cmd in terminal to compile:
	g++ -I/usr/include/pcap snifferProgram.cpp -lpcap -o Snif
