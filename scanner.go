package main

import (
	"log"
	"syscall"
)

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
	addr, er := syscall.Getsockname(socket)
	if er != nil {
		syscall.Close(socket)
		log.Panicln("Failed to get socket name:", er)
	}
	defer syscall.Close(socket)

	// print the reserved address
	log.Println(addr)

	// create socket to listen on
	listen, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(listen)
		log.Panicln("Failed to create TCP listener socket:", err)
	}
	defer syscall.Close(listen)

	// create raw socket to send packets on
	send, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		syscall.Close(send)
		log.Panicln("Failed to create TCP sender socket:", err)
	}
	defer syscall.Close(send)

	log.Println(listen)
	log.Println(send)

}
