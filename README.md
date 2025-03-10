# Packet Sniffer
## Requirements:
- Linux
- Python 3.1 or higher
- CMake 3.10 or higher
- libpcap
## Usage:
### Packet Sniffer:
- Open open the terminal and execute PacketSniffer with the flags 'live' or 'pcap' followed by 'filename.pcap' if it is used with the pcap flag.
###
live mode: it allows you to sniff packets and record them into a .csv file during runtime. You can specify the number of packets to sniff.
pcap mode: it allows you to sniff packets from a .pcap file and record them into a .csv file.
### Packet Analyzer:
- Run with python through terminal.
- Allows you to analyzer the preivously made .csv file and categorize the recorded traffic according to different characteristics.