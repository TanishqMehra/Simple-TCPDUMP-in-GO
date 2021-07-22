# Simple-TCPDUMP-in-GO
A simplified version of TCPDUMP in Golang

Developed a passive network monitoring application
written in **Go** using the **GoPacket** library. The program, called '**mydump**', will
capture the traffic from a network interface in promiscuous mode (or read the
packets from a pcap trace file) and print a record for each packet in its
standard output, much like a simplified version of tcpdump.

**go run mydump.go [-i interface] [-r file] [-s string] expression**

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format.

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice.

expression is a **BPF filter** that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.
  
---------------------------------------------------------------------------------------------------------
  
Kindly refer to the file mydump.go for the implementation of the passive network monitoring system
using Golang.

Following are the key features regarding the implementation:

1. I have consolidated the main application information as part of a Go struct "commandDetails"
    Description of each field:
     - device : Name of the device for live reading of packets (Updated when "-i" is provided)
     - pcapFile : Name of the pcap file for offline file reading (Updated when "-r" is provided)
     - livePacketCapture : Internal usage. Value initially 0 for not initialized, 1 for live reading,
                            2 for offline file reading.
     - promiscous : promiscous mode. Default value: true (Set in "main" function)
     - snapshot_len : Snapshot Length. Default value: 65535 (Set in "main" function)
     - bpf_expression : BPF filter
     - match_string : String for string matching operation (Updated when "-s" is provided)


2. By default, mydump will perform live reading on "eth0"
    Example: go run mydump.go


3. I have tried to keep the execution and error handlings similar to that of tcpdump.
    Example: If "-i" and "-r" both are provided. Preference will be given to "-r" .
             Any device name provided "-i" does not exist. Appropriate error will be logged.


4. Following are the additional libraries imported and their reasoning:
    - encoding/hex : For hex dump operation on the payload of Application layer
    - fmt : To print the final output on the terminal
    - log : To log fatal errors on the terminal
    - os : Used to fetch the command line arguments while executing mydump
    - strconv : Convert Integer type values to string using its method strconv.itoa 
    - strings : To perform substring check using the method strings.Contains

5. Implementation
    - BPF filter is initially applied on the PCAP session handler.
    - For each packet "preparePacketData" method is invoked that processes the metadata 
        and each layer of the packet to extract the required information.
    - Packet length and Timestamp information is extracted from the packet metadata.
    - From the ethernet layer, source/destination mac addresses and ethertype information is obtained.
    - IPv4 layer is processed to obtain the IP protocol. (Processed for "UDP", "TCP", "ICMPv4", and 
        "OTHER") 
    - For TCP Packets, simple appropriate flag checks are placed to add to the packet output.
    - From the Application layer, the payload is obtained and hex dump is performed.
    - All the details are stored in a variable 'finalDisplayString' which is returned.
    - A simple string match is performed (if "-s" is provided) on the complete display string of
        the processed packet and displayed if true.


6. Output 

Example 1: go run mydump.go -i eth0 tcp

Sample Output:
2021-03-12 23:47:43.111243116 00:15:5d:bf:17:b6 -> 00:15:5d:62:f5:7a type 0x800 len 54 
172.23.16.1 -> 172.23.26.20 TCP ACK

2021-03-12 23:47:43.111243116 00:15:5d:bf:17:b6 -> 00:15:5d:62:f5:7a type 0x800 len 87 
172.23.16.1 -> 172.23.26.20 TCP PSH ACK
00000000  c2 9b fe a8 ac ca fc f1  d0 dd 96 59 dd 16 e8 7b  |...........Y...{|
00000010  02 2e 44 2f 73 a8 24 3d  f0 3d 0f f3 e0 51 6c a3  |..D/s.$=.=...Ql.|
00000020  ac                                                |.|

2021-03-12 23:47:43.111243116 00:15:5d:62:f5:7a -> 00:15:5d:bf:17:b6 type 0x800 len 85 
172.23.26.20 -> 172.23.16.1 TCP PSH ACK
00000000  c2 1d 02 6d 0d 3a c1 c0  b0 ec 3e ee fd 43 e6 e0  |...m.:....>..C..|
00000010  4d 46 27 f1 2b b2 00 2b  3a 85 5f 91 25 03 00     |MF'.+..+:._.%..|




Example 2: How many packets have SYN flag set?

go run mydump.go -r hw1.pcap 'tcp[tcpflags] & tcp-syn!=0' | grep "TCP" | wc -l

Output: 75
