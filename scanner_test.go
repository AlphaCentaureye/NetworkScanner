package main

import (
	"math"
	"testing"
)

func TestSum16(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		want uint16
	}{
		{
			name: "empty",
			want: 0,
		},
		{
			name: "OneOddView",
			data: []byte{1, 9, 0, 5, 4},
			want: 1294,
		},
		{
			name: "OneEvenView",
			data: []byte{1, 9, 0, 5},
			want: 270,
		},
		{
			name: "PacketExample",
			data: []byte{0b10101100, 0b00010000, 0b00000001, 0b00000001, 0b10101100, 0b00010000, 0b00000001, 0b00000010, 0b00000000, 0b00000110, 0b01100100, 0b01010100, 0b01100011, 0b01110000, 0b01100011, 0b01100011, 0b01100101, 0b01110011, 0b01110100, 0b01101001, 0b01101110, 0b01101011, 0b01101001, 0b01101110, 0b01101111, 0b01101110, 0b01101001, 0b01101110, 0b01101011, 0b01101001, 0b01101110, 0b01101011, 0b01101001, 0b01101110, 0b01101011, 0b01101001},
			want: 0b1111001111110011,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := sum16(tc.data), tc.want; got != want {
				t.Errorf("sum16(% X) = %d, want %d", tc.data, got, want)
			}
		})
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
	got := calculateChecksum(ipHeader, tcpHeader, []byte{})
	const want = 0x4903

	if got != want {
		t.Errorf("got calculateChecksum = %X, want = %X", got, want)
	}
}
