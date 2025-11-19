package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"math"
	"syscall"
	"time"
)

type EthernetHeader struct {
	DestinationMAC [6]byte
	SourceMAC      [6]byte
	EthernetType   uint16
}

type PseudoHeader struct {
	SourceIP      [4]byte
	DestinationIP [4]byte
	Zero          uint8
	Protocol      uint8
	TCPLength     uint16
}

type IPv4Header struct {
	VersionIHL          uint8
	TypeOfService       uint8
	TotalLength         uint16
	Identification      uint16
	FlagsFragmentOffset uint16
	TTL                 uint8
	Protocol            uint8
	HeaderChecksum      uint16
	SourceIP            [4]byte
	DestinationIP       [4]byte
}

type TCPHeader struct {
	SourcePort           uint16
	DestinationPort      uint16
	SequenceNumber       uint32
	AcknowledgmentNumber uint32
	DataOffsetRes        uint8
	Flags                uint8
	WindowSize           uint16
	Checksum             uint16
	UrgentPointer        uint16
}

type Flags struct {
	CWR bool
	ECE bool
	URG bool
	ACK bool
	PSH bool
	RST bool
	SYN bool
	FIN bool
}

func main() {
	// create a TCP socket
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Panicln("Failed to create TCP socket:", err)
	}

	// bind the socket to an available port
	if err := syscall.Bind(socket, &syscall.SockaddrInet4{
		Port: 0,
	}); err != nil {
		syscall.Close(socket)
		log.Panicln("Failed to bind TCP socket:", err)
	}

	// retrieve the assigned port number
	addr, err := syscall.Getsockname(socket)
	if err != nil {
		syscall.Close(socket)
		log.Panicln("Failed to get socket name:", err)
	}
	defer syscall.Close(socket)
	port := uint16(addr.(*syscall.SockaddrInet4).Port)

	// print the reserved address
	log.Printf("Listening on TCP Port: %d", uint16(addr.(*syscall.SockaddrInet4).Port))

	// create socket to listen on
	// htons is needed to convert ETH_P_ALL to network byte order
	listen, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, htonsInt(syscall.ETH_P_ALL))
	if err != nil {
		syscall.Close(listen)
		log.Panicln("Failed to create TCP listener socket:", err)
	}
	// defer syscall.Close(listen)

	// create raw socket to send packets on
	send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(send)
		log.Panicln("Failed to create TCP sender socket:", err)
	}
	defer syscall.Close(send)

	log.Println()

	// unpack address of reserved tcp port and start listening loop
	go startListening(listen, port)

	sendPacket(send, [4]byte{127, 0, 0, 1}, port, port)

	time.Sleep(5 * time.Second)

}

// htons converts a uint16 from host to network byte order
// basically from little-endian to big-endian
// as network uses big-endian and computer uses little-endian
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// htonsInt converts an int from host to network byte order
func htonsInt(i int) int {
	return int(htons(uint16(i)))
}

// converts byte order to big-endian
func htonsIP(b [4]byte) [4]byte {
	return [4]byte{b[3], b[2], b[1], b[0]}
}

// convert uint8 to Flags struct
func uint8ToFlags(flag uint8) Flags {
	return Flags{
		CWR: flag&0x80 != 0,
		ECE: flag&0x40 != 0,
		URG: flag&0x20 != 0,
		ACK: flag&0x10 != 0,
		PSH: flag&0x08 != 0,
		RST: flag&0x04 != 0,
		SYN: flag&0x02 != 0,
		FIN: flag&0x01 != 0,
	}
}

// chesum summation
func sum16(dataToSum []byte) uint16 {
	var sum uint32 // 32-bit sum to handle overflow --> then convert to 16-bit
	for i := 0; i < len(dataToSum)-1; i += 2 {
		word := uint16(dataToSum[i])<<8 | uint16(dataToSum[i+1]) // combine two bytes into one word (<< moves bits over to make room for next byte in word)
		sum += uint32(word)
		if sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16) // add overflow back into sum
		}
	}

	if len(dataToSum)%2 != 0 { // if odd number of bytes, pad last byte with zero
		sum += uint32(dataToSum[len(dataToSum)-1]) << 8
		if sum > 0xFFFF {
			sum = (sum & 0xFFFF) + (sum >> 16)
		}
	}

	return ^uint16(sum) // one's complement
}

// calculate checksum for TCP header
func calculateChecksum(ipHeader IPv4Header, tcpHeader TCPHeader, data []byte) uint16 {
	// var pseudoHeader []byte
	pseudoHeader := PseudoHeader{
		SourceIP:      ipHeader.SourceIP,
		DestinationIP: ipHeader.DestinationIP,
		Zero:          0,
		Protocol:      ipHeader.Protocol,
		TCPLength:     uint16(20 + len(data)), // TCP header length + data length
	}
	buffer := bytes.Buffer{}
	// pseudoHeader = append(pseudoHeader, ipHeader.SourceIP[:]...)
	// pseudoHeader = append(pseudoHeader, ipHeader.DestinationIP[:]...)
	// pseudoHeader = append(pseudoHeader, 0)                   // zero byte
	// pseudoHeader = append(pseudoHeader, ipHeader.Protocol)   // protocol
	// pseudoHeader = append(pseudoHeader, uint8(20+len(data))) // TCP length (header + data))
	binary.Write(&buffer, binary.BigEndian, pseudoHeader)
	binary.Write(&buffer, binary.BigEndian, tcpHeader)
	// dataToSum := append(pseudoHeader, buffer.Bytes()...)
	dataToSum := buffer.Bytes()
	dataToSum = append(dataToSum, data...) // append data if any

	return sum16(dataToSum)
}

// send TCP packet
func sendPacket(sendSocket int, destIP [4]byte, destPort uint16, sourcePort uint16) {
	sockaddr := syscall.SockaddrInet4{
		Port: int(destPort),
		Addr: destIP,
	}

	var packetbuf bytes.Buffer
	ipHeader := IPv4Header{
		VersionIHL:          0x45,
		FlagsFragmentOffset: 0x4000, // Don't Fragment flag
		TTL:                 64,
		Protocol:            6,
		DestinationIP:       destIP,
	}

	tcpHeader := TCPHeader{
		SourcePort:      sourcePort,
		DestinationPort: destPort,
		SequenceNumber:  2 * uint32(math.Pow(10, 9)),
		DataOffsetRes:   0x50,
		Flags:           2, // SYN flag
		WindowSize:      65535,
		Checksum:        0, // will be calculated later
	}

	// calculate checksum
	tcpHeader.Checksum = calculateChecksum(ipHeader, tcpHeader, []byte{})

	binary.Write(&packetbuf, binary.BigEndian, ipHeader)
	binary.Write(&packetbuf, binary.BigEndian, tcpHeader)

	err := syscall.Sendto(sendSocket, packetbuf.Bytes(), 0, &sockaddr)
	if err != nil {
		log.Panicln("Failed to send TCP packet:", err)
		return
	}
}

// listening loop goroutine
func startListening(listener int, listenPort uint16) {
	buf := make([]byte, 1518) // max MTU byte size
	for {
		// Make a copy of buf so that we can modify it in the loop and the next iteration will get back the full slice.
		buf := buf

		n, err := syscall.Read(listener, buf)
		if err != nil {
			log.Printf("syscall.Read(accepted %d): %v", listener, err)
			syscall.Close(listener)
			return
		}
		// Slice off the unused portion of buf.
		buf = buf[:n]

		eth, ip, tcp, err := parsePacket(buf)
		if err == nil {
			if tcp.DestinationPort == listenPort {
				log.Println("TCP Packet Received")
				log.Printf("Listening on TCP Port: %d", listenPort)
				log.Printf("Ethernet Header: {DestinationMAC:[% X] SourceMAC:[% X] EthernetType:0x%X}\n", eth.DestinationMAC, eth.SourceMAC, eth.EthernetType)
				log.Printf("IPv4 Header: %+v\n", ip)
				log.Printf("TCP Header: %+v\n", tcp)
				log.Printf("TCP Flags: %+v\n\n", uint8ToFlags(tcp.Flags))
			}
		}
	}
}

func parsePacket(data []byte) (EthernetHeader, IPv4Header, TCPHeader, error) {
	var eth EthernetHeader
	var ip IPv4Header
	var tcp TCPHeader
	var ipVersionIHL uint8
	var mask4b uint8 = 0x0F

	binary.Read(bytes.NewReader(data[:14]), binary.BigEndian, &eth)
	if eth.EthernetType != 0x0800 { // IPv4
		return eth, ip, tcp, errors.New("Not a IPv4 Packet")
	}

	binary.Read(bytes.NewReader(data[14:15]), binary.BigEndian, &ipVersionIHL)
	// get IHL and convert to amount of bytes in header
	// as IHL is number of 32-bit words in header
	length := int(ipVersionIHL&mask4b) * 4

	binary.Read(bytes.NewReader(data[14:14+length]), binary.BigEndian, &ip)
	if ip.Protocol != 6 { // TCP
		return eth, ip, tcp, errors.New("Not a TCP Packet")
	}

	binary.Read(bytes.NewReader(data[14+length:14+length+20]), binary.BigEndian, &tcp)
	return eth, ip, tcp, nil
}
