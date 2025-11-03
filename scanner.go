
package main

import (
	"log",
	"syscall"
)

func main() {
	// create a TCP socket
	socket, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		log.Panicln("Failed to create TCP socket: ", err)
	}

	// bind the socket to an available port
	err := syscall.Bind(socket, &syscall.SockaddrInet4{
		Port: 0
	})
	if err != nil {
		syscall.Close(socket)
		log.Panicln("Failed to bind TCP socket: ", err)
	}

	// retrieve the assigned port number
	addr, er := systcall.Getsockname(socket)
	if er != nil {
		syscall.Close(socket)
		log.Panicln("Failed to get socket name: ", er)
	}



}
