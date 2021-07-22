package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type commandDetails struct {
	device            string
	pcapFile          string
	livePacketCapture int //0 for not initialized, 1 for true, 2 for reading from file
	promiscuous       bool
	snapshot_len      int32
	bpf_expression    string
	match_string      string
}

func main() {

	// Setting the default values for the packet reader
	cDetails := commandDetails{livePacketCapture: 0, promiscuous: false, snapshot_len: 65535}

	bpf_expr := ""

	// Accessing all the commands received during the command line execution
	commandLineArgs := os.Args[1:]

	for j := 0; j < len(commandLineArgs); j++ {
		var value = commandLineArgs[j]
		switch value {
		case "-i":
			if cDetails.livePacketCapture == 0 {
				cDetails.device = commandLineArgs[j+1]
				j += 1
				cDetails.livePacketCapture = 1
			}

		case "-r":
			cDetails.pcapFile = commandLineArgs[j+1]
			j += 1
			cDetails.livePacketCapture = 2

		case "-s":
			cDetails.match_string = commandLineArgs[j+1]
			j = j + 1
		default:
			bpf_expr = bpf_expr + " " + value
		}
	}
	// fmt.Println("BPF Filter expression is ", bpf_expr)
	cDetails.bpf_expression = bpf_expr

	cDetails.readPackets()
}

func (cDetails commandDetails) readPackets() {
	var deviceFound bool = false

	if cDetails.livePacketCapture == 0 {
		cDetails.livePacketCapture = 1
		cDetails.device = "eth0" //default device
	}

	if cDetails.livePacketCapture == 1 { // live reading
		var devices []pcap.Interface

		devices, device_err := pcap.FindAllDevs()
		if device_err != nil {
			log.Fatal(device_err)
		}

		for _, device := range devices {
			if cDetails.device == device.Name {
				deviceFound = true
			}
		}
		if deviceFound == false {
			log.Fatal("mydump: ", cDetails.device, ": No such device exists ")
		}

		handle, err := pcap.OpenLive(cDetails.device, 1600, true, pcap.BlockForever)
		fmt.Println("listening on ", cDetails.device, ",  snapshot length ", cDetails.snapshot_len)
		if err != nil {
			log.Fatal(err)
		}
		cDetails.processAndPrintPacketData(*handle)
	} else { // offline reading
		handle, err := pcap.OpenOffline(cDetails.pcapFile)
		fmt.Println("reading from file ", cDetails.pcapFile, ",  snapshot length ", cDetails.snapshot_len)
		cDetails.processAndPrintPacketData(*handle)
		if err != nil {
			log.Fatal(err)
		}
	}
}

//Final processing and printing of packet
func (cDetails commandDetails) processAndPrintPacketData(handle pcap.Handle) {

	// Add BPF filter
	handle.SetBPFFilter(cDetails.bpf_expression)

	packetSource := gopacket.NewPacketSource(&handle, handle.LinkType())
	var finalOutput string = ""
	for packet := range packetSource.Packets() {
		finalOutput = preparePacketData(packet)
		//String matching
		if cDetails.match_string != "" {
			if strings.Contains(finalOutput, cDetails.match_string) {
				fmt.Println(finalOutput)
			}
		} else {
			fmt.Println(finalOutput)
		}
	}
}

//Layer by layer data processing
func preparePacketData(packet gopacket.Packet) string {

	finalDisplayString := ""
	packetLength := packet.Metadata().Length
	finalDisplayString = finalDisplayString + packet.Metadata().Timestamp.Format("2006-01-02 15:04:05.32536") + " "

	// Ethernet layer
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {

		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		finalDisplayString = finalDisplayString + ethernetPacket.SrcMAC.String() + " -> " + ethernetPacket.DstMAC.String() + " type 0x" + strconv.FormatInt(int64(ethernetPacket.EthernetType), 16)
	}

	finalDisplayString = finalDisplayString + " len " + strconv.Itoa(packetLength) + " \n"

	// IP Layer
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		ipProtocol := ip.Protocol.String()
		if ipProtocol != "UDP" && ipProtocol != "TCP" && ipProtocol != "ICMPv4" {
			ipProtocol = "OTHER"
		}

		finalDisplayString = finalDisplayString + ip.SrcIP.String() + " -> " + ip.DstIP.String() + " " + ipProtocol
	}

	// Tcp Layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		if tcp.SYN == true {
			finalDisplayString = finalDisplayString + " SYN"
		}
		if tcp.PSH == true {
			finalDisplayString = finalDisplayString + " PSH"
		}
		if tcp.ACK == true {
			finalDisplayString = finalDisplayString + " ACK"
		}
		if tcp.RST == true {
			finalDisplayString = finalDisplayString + " RST"
		}
		if tcp.URG == true {
			finalDisplayString = finalDisplayString + " URG"
		}
		if tcp.ECE == true {
			finalDisplayString = finalDisplayString + " ECE"
		}
		if tcp.FIN == true {
			finalDisplayString = finalDisplayString + " FIN"
		}
		if tcp.CWR == true {
			finalDisplayString = finalDisplayString + " CWR"
		}
		if tcp.NS == true {
			finalDisplayString = finalDisplayString + " NS"
		}
	}

	finalDisplayString = finalDisplayString + "\n"

	//Application Layer
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer != nil {
		finalDisplayString = finalDisplayString + hex.Dump(applicationLayer.Payload())
	}

	// Check for errors
	if err := packet.ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	return finalDisplayString
}
