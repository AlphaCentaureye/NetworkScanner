package main

import (
	"math"
	"slices"
	"testing"
)

func TestSum16(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		want uint16
	}{
		// { // old tests
		// 	name: "empty",
		// 	want: 0,
		// },
		// {
		// 	name: "OneOddView",
		// 	data: []byte{1, 9, 0, 5, 4},
		// 	want: 1294,
		// },
		// {
		// 	name: "OneEvenView",
		// 	data: []byte{1, 9, 0, 5},
		// 	want: 270,
		// },
		{ // from packet tracer, extracted values in accordance with data structure for checksum calculation (assumes the structure I'm usng is correct)
			name: "PacketExample",
			data: []byte{0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x14, 0xae, 0xd3, 0xae, 0xd3, 0x77, 0x35, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00},
			want: 0x4903,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := sum16(tc.data), tc.want; got != want {
				t.Errorf("sum16(% X) = 0x%X, want 0x%X", tc.data, got, want)
			}
		})
	}
}

func TestChecksumData(t *testing.T) {
	destIP := [4]byte{127, 0, 0, 1}
	const sourcePort = uint16(44755)
	const destPort = sourcePort
	ipHeader := IPv4Header{
		VersionIHL:          0x45,
		FlagsFragmentOffset: 0x4000, // Don't Fragment flag
		TTL:                 64,
		Protocol:            6,
		DestinationIP:       destIP,
		SourceIP:            destIP,
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

	// test checksum data structure
	got := checksumData(ipHeader, tcpHeader, []byte{})
	want := []byte{0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x14, 0xae, 0xd3, 0xae, 0xd3, 0x77, 0x35, 0x94, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00}

	if !slices.Equal(got, want) {
		t.Errorf("got checksumData = % X, want = % X", got, want)
	}
}

func TestCalculateChecksum(t *testing.T) {
	destIP := [4]byte{127, 0, 0, 1}
	const sourcePort = uint16(44755)
	const destPort = sourcePort
	ipHeader := IPv4Header{
		VersionIHL:          0x45,
		FlagsFragmentOffset: 0x4000, // Don't Fragment flag
		TTL:                 64,
		Protocol:            6,
		DestinationIP:       destIP,
		SourceIP:            destIP,
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

	// test checksum data structure
	got := calculateChecksum(ipHeader, tcpHeader, []byte{})
	const want = 0x4903

	if got != want {
		t.Errorf("got calculateChecksum = %X, want = %X", got, want)
	}
}
