# Packet Sniffer
## Requirements:
- Linux
- Python 3.1 or higher
- CMake 3.10 or higher
- libpcap
## Usage:
### Packet Sniffer:
- Open open the terminal and execute PacketSniffer with the flags 'live' or 'pcap' followed by 'filename.pcap' if it is used with the pcap flag.
#### Modes and usage:
- live mode: allows to read packets from a certain interface during runtime and record them into a .csv file. You can specify the number of packets to read.
- pcap mode: allows to read packets from a .pcap file and record them into a .csv file.
### Packet Analyzer:
- Run with python through terminal.
#### Usage:
- Allows you to analyzer the preivously made .csv file and categorize the recorded traffic according to different characteristics (IP, number of packets, size of packets).