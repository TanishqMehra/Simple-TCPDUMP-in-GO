# Simple-TCPDUMP-in-GO
A simplified version of TCPDUMP in Golang

Developed a passive network monitoring application
written in **Go** using the **GoPacket** library. The program, called '**mydump**', will
capture the traffic from a network interface in promiscuous mode (or read the
packets from a pcap trace file) and print a record for each packet in its
standard output, much like a simplified version of tcpdump. The user should be
able to specify a BPF filter for capturing a subset of the traffic, and/or a
string pattern for capturing only packets with matching payloads.

**go run mydump.go [-i interface] [-r file] [-s string] expression**

-i  Live capture from the network device <interface> (e.g., eth0). If not
    specified, mydump should automatically select a default interface to
    listen on (hint 1). Capture should continue indefinitely until the user
    terminates the program.

-r  Read packets from <file> in tcpdump format (hint 2).

-s  Keep only packets that contain <string> in their payload (after any BPF
    filter is applied). You are not required to implement wildcard or regular
    expression matching. A simple string matching operation should suffice.

<expression> is a **BPF filter** that specifies which packets will be dumped. If
no filter is given, all packets seen on the interface (or contained in the
trace) should be dumped. Otherwise, only packets matching <expression> should
be dumped.
  
  
  
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

2021-03-12 23:47:43.111243116 00:15:5d:62:f5:7a -> 00:15:5d:bf:17:b6 type 0x800 len 1298 
172.23.26.20 -> 172.23.16.1 TCP PSH ACK
00000000  71 55 67 23 d4 38 e4 ad  4a 7b 83 6b be a5 c3 75  |qUg#.8..J{.k...u|
00000010  f8 b6 71 d3 0c 0d 22 80  31 ff 6c 5a 8c fc 45 a4  |..q...".1.lZ..E.|
00000020  e4 52 54 d4 7b 9b ee a3  15 59 c0 3c 5b 43 2e 63  |.RT.{....Y.<[C.c|
00000030  43 29 63 f1 1d 29 d1 b0  5a da 18 61 68 f1 f4 c1  |C)c..)..Z..ah...|
00000040  8d b9 73 5b af dd e7 17  62 77 f6 e1 f2 ad 31 49  |..s[....bw....1I|
00000050  36 14 89 94 29 40 0c cb  4b b3 30 13 fe 26 c4 ae  |6...)@..K.0..&..|
00000060  b5 c6 87 c4 7b bb b3 4f  bd 75 cd b9 ef 9b e4 d4  |....{..O.u......|
00000070  bf fc 76 b6 f0 de 3e 1e  61 f8 ef a7 c3 6f 30 c1  |..v...>.a....o0.|
00000080  73 81 71 27 af b2 ef ea  a4 b1 b5 ec e3 d6 4e 9a  |s.q'..........N.|
00000090  0b be 0d db 39 57 e1 73  f4 db 9b 13 92 ec 18 0f  |....9W.s........|
000000a0  36 59 84 53 9a 17 64 6f  eb e6 fd 66 5e 81 b3 14  |6Y.S..do...f^...|
000000b0  38 2a da d4 38 94 81 db  93 4a e7 a9 7f e4 b3 32  |8*..8....J.....2|
000000c0  10 ae 80 ff d4 25 73 34  51 02 39 5d d5 3a a5 c4  |.....%s4Q.9].:..|
000000d0  4a f7 84 e3 8d b0 b4 1a  04 97 25 6b fc 55 d6 ba  |J.........%k.U..|
000000e0  e1 eb c0 91 f8 e8 60 c5  15 d0 ea a9 48 34 a4 90  |......`.....H4..|
000000f0  ce 80 1d d4 17 fa ff d8  3a ed 96 07 5d 51 15 06  |........:...]Q..|
00000100  05 ec 2e 15 db 01 05 ff  5c 01 0b 55 20 e1 ec ab  |........\..U ...|
00000110  c0 f3 8d d9 ab 10 93 6c  23 f8 e8 ea 2f c4 dc 26  |.......l#.../..&|
00000120  6a 16 d4 a5 ef a8 f6 fd  ce bf de 8f 85 74 2f 44  |j............t/D|
00000130  de 78 6e e2 a7 da 63 b2  9a 90 45 a1 fc bf 18 5f  |.xn...c...E...._|
00000140  c1 04 d5 ab a8 50 23 b8  0e 73 73 7f 8f 3f b9 87  |.....P#..ss..?..|
00000150  1b 32 ac 98 b4 ed 4b aa  80 29 ba 2a 34 d7 15 eb  |.2....K..).*4...|
00000160  4f 0c 06 91 80 2a c2 c7  2c 27 07 1a c5 18 05 2b  |O....*..,'.....+|
00000170  34 61 74 67 cd 07 f6 fa  02 be 81 29 d0 41 1d 2b  |4atg.......).A.+|
00000180  6d 34 8c 94 62 8c 26 f2  f1 48 61 96 00 81 27 7d  |m4..b.&..Ha...'}|
00000190  58 f3 fe 8a bb bf 08 ad  ba c9 d7 78 61 2e 36 80  |X..........xa.6.|
000001a0  29 90 e1 a5 20 a7 da 02  5c 13 3b 48 35 b5 66 5e  |)... ...\.;H5.f^|
000001b0  3f a0 b2 d0 ec 09 a6 8d  cc 85 0f ef b8 2f 4f e9  |?............/O.|
000001c0  e6 7e fc 40 84 c9 ed 35  51 a0 42 cd 56 60 29 1e  |.~.@...5Q.B.V`).|
000001d0  1b 4c d0 ea b5 d1 31 3b  b0 02 7a d6 f9 00 d7 26  |.L....1;..z....&|
000001e0  34 de db 1a 7f 4d 96 d6  6b a2 40 4f f0 4f 0c af  |4....M..k.@O.O..|
000001f0  2b 86 66 e8 1f 4b a1 41  34 b1 85 03 ce 56 55 11  |+.f..K.A4....VU.|
00000200  9c 7a 9a 23 5a c8 2f 7c  9b 6e 69 07 01 51 20 e2  |.z.#Z./|.ni..Q .|
00000210  ee fc bf b5 68 23 cd 28  4a d5 59 c5 76 a8 89 c3  |....h#.(J.Y.v...|
00000220  18 b4 22 66 1f 6d 6a ac  8f e5 13 95 5a ca c5 8a  |.."f.mj.....Z...|
00000230  28 d0 31 ca 6c a0 7e e8  85 a1 43 51 c9 a4 44 61  |(.1.l.~...CQ..Da|
00000240  88 4a 3d 09 0a 42 77 86  29 c1 d5 c5 c3 93 cb ae  |.J=..Bw.).......|
00000250  7c 66 db f9 8a 28 20 85  42 44 a3 8e ec 31 86 74  ||f...( .BD...1.t|
00000260  ae 0e c9 90 81 01 af 8e  91 9d ce ef 8f 6d 14 3e  |.............m.>|
00000270  f5 a5 09 0b 7b 7d c2 b6  dd df 9d 5c 06 68 0a 35  |....{}.....\.h.5|
00000280  02 82 03 9a 98 da 79 c4  9f ad 04 fc 8b 21 b4 84  |......y......!..|
00000290  36 99 02 f2 f4 ef ce fd  b4 ba c7 c2 50 7d 3b ba  |6...........P};.|
000002a0  2c e2 b8 37 db 22 9b 30  96 a8 68 5a 14 6f 25 94  |,..7.".0..hZ.o%.|
000002b0  f1 7a 38 3a ba fc 69 f8  fb 6b bc 5e 56 3c 81 1e  |.z8:..i..k.^V<..|
000002c0  62 a8 fa 76 d0 58 ff 2a  4b e3 9c f0 a7 64 61 11  |b..v.X.*K....da.|
000002d0  eb e5 6b 39 0c db 62 16  ca 27 c3 bb 4d ce b0 59  |..k9..b..'..M..Y|
000002e0  26 1f 3c 81 04 5d 92 36  17 5c 62 6a 73 06 ad 61  |&.<..].6.\bjs..a|
000002f0  1b c9 52 8e 32 55 34 7e  ea f3 2e e8 a7 cd 32 26  |..R.2U4~......2&|
00000300  b3 b6 66 c5 13 f0 8b a4  03 f3 93 4e d8 f0 1b dc  |..f........N....|
00000310  6a d9 17 30 c5 e8 f1 de  6c e8 cb 27 77 de fe c8  |j..0....l..'w...|
00000320  c3 c0 7f fa 15 4f 40 66  88 69 40 b1 63 4c f8 1a  |.....O@f.i@.cL..|
00000330  d0 45 82 d3 91 02 57 98  5b 97 18 ef 27 93 28 d2  |.E....W.[...'.(.|
00000340  57 cc 9f 7e fb 44 3c b2  79 e2 7a 12 f2 a8 4b f2  |W..~.D<.y.z...K.|
00000350  e0 13 02 f9 7a 9e 44 b8  c7 01 9f be 14 91 9c 99  |....z.D.........|
00000360  96 04 c3 d6 af ce 58 24  df 58 6f 9f 5b 7c ea ce  |......X$.Xo.[|..|
00000370  fa 6e 8d 46 d9 26 72 f3  32 60 d7 e0 14 2f 40 3a  |.n.F.&r.2`.../@:|
00000380  11 8b 2a 2b d7 b0 2c df  77 5f 77 5f 17 07 a7 18  |..*+..,.w_w_....|
00000390  0d 5c 9c 2b 7e e0 09 08  5d 27 9d b8 84 86 37 c0  |.\.+~...]'....7.|
000003a0  3b 53 53 d0 a1 83 f1 7f  a7 87 10 d4 e5 60 7a 1a  |;SS..........`z.|
000003b0  9e 3e 71 cf df b8 e3 9f  7b 2b 9a 80 51 f8 06 54  |.>q.....{+..Q..T|
000003c0  7b 11 10 55 5a 19 e4 19  21 0a c4 8f 7a c0 33 2a  |{..UZ...!...z.3*|
000003d0  4e 8f b4 c9 a7 9c f3 07  ed d9 a7 cc f5 57 34 01  |N............W4.|
000003e0  83 56 32 b6 ee 86 aa a4  e1 68 a4 1a a2 ba 48 41  |.V2......h....HA|
000003f0  87 14 2b 5d 4c 79 d4 b7  c2 da b9 b0 f5 c0 15 b3  |..+]Ly..........|
00000400  3c 6a 73 6d 27 a9 d1 06  e1 b1 91 0f 79 8f 11 0d  |<jsm'.......y...|
00000410  01 40 97 14 5a 2d c1 c0  c0 22 f0 db 38 5a df a5  |.@..Z-..."..8Z..|
00000420  a6 5a d1 04 32 70 af 11  eb dd bf 14 57 2c 27 22  |.Z..2p......W,'"|
00000430  57 8f 1c 79 ff ef 86 21  6f 27 1e 2a ff 9e 78 a8  |W..y...!o'.*..x.|
00000440  d5 6b 22 07 23 dc 02 52  c6 c5 ec 1a 15 33 78 a0  |.k".#..R.....3x.|
00000450  d5 8c 93 d2 50 12 57 df  be e9 b7 e0 cc dd 77 67  |....P.W.......wg|
00000460  ef cd 8f 1d 66 21 7e 4f  2b e9 30 3b 5c b1 74 62  |....f!~O+.0;\.tb|
00000470  c3 75 0c 0e b1 92 22 5a  44 4a 05 7e cb 4b f9 8b  |.u...."ZDJ.~.K..|
00000480  9b ff cc a5 18 89 b5 f0  6f f9 73 78 f3 6d 1f fb  |........o.sx.m..|
00000490  db 4d 9f f2 bf a7 41 ea  55 b5 14 7d 50 21 77 c9  |.M....A.U..}P!w.|
000004a0  4c 83 14 d1 05 96 d0 94  93 63 0d d2 4e 90 5d fb  |L........c..N.].|
000004b0  66 e8 d4 fa 0b b7 90 b8  ac 3c 0e 7b 14 23 bc 85  |f........<.{.#..|
000004c0  5c 60 39 84 35 8c d8 28  9d 5e 9c 43 ed ce e7 13  |\`9.5..(.^.C....|
000004d0  77 fe e2 cc 72 4e ff fb  e7 1f ff 05              |w...rN......|

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
