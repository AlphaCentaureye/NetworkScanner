package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"syscall"
)

type EthernetHeader struct {
	DestinationMAC [6]byte
	SourceMAC      [6]byte
	EthernetType   uint16
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
	startListening(listen, uint16(addr.(*syscall.SockaddrInet4).Port))

	// time.Sleep(10 * time.Second)

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
				log.Printf("Listening on TCP Port: %d", listenPort)
				log.Printf("Ethernet Header: %+v\n", eth)
				log.Printf("IPv4 Header: %+v\n", ip)
				log.Printf("TCP Header: %+v\n", tcp)
				log.Printf("TCP Flags: %+v\n\n", uint8ToFlags(tcp.Flags))
			}
		}
		// log.Printf("%q\n", buf)
	}
}

func parsePacket(data []byte) (EthernetHeader, IPv4Header, TCPHeader, error) {
	var eth EthernetHeader
	var ip IPv4Header
	var tcp TCPHeader
	var ipVersionIHL uint8
	var mask4b uint8 = 0x0F
	binary.Read(bytes.NewReader(data[:14]), binary.BigEndian, &eth)
	if eth.EthernetType == 0x0800 { // IPv4
		binary.Read(bytes.NewReader(data[14:15]), binary.BigEndian, &ipVersionIHL)
		// get IHL and convert to amount of bytes in header
		// as IHL is number of 32-bit words in header
		length := int(ipVersionIHL&mask4b) * 4
		binary.Read(bytes.NewReader(data[14:14+length]), binary.BigEndian, &ip)
		if ip.Protocol == 6 { // TCP
			binary.Read(bytes.NewReader(data[14+length:14+length+20]), binary.BigEndian, &tcp)
			return eth, ip, tcp, nil
		}
	}
	// if not TCP, return nothing
	return eth, ip, tcp, errors.New("Not a TCP Packet")
}
