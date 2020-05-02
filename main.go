package main

import (
	"fmt"
	"net"
)

func main() {
	// bytes := [512]byte{0x86, 0x2a, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x25, 0x00, 0x04, 0xd8, 0x3a, 0xd3, 0x8e}

	// buffer := BytePacketBuffer{bytes, 0}
	// oldPacket, err := Read(&buffer)
	// if err != nil {
	// 	fmt.Printf("I errored, %s\n", err)
	// }

	// fmt.Println(oldPacket.header)

	// for _, question := range oldPacket.questions {
	// 	fmt.Println(question)
	// }

	// for _, answer := range oldPacket.answers {
	// 	fmt.Println(answer)
	// }

	// for _, authority := range oldPacket.authorities {
	// 	fmt.Println(authority)
	// }

	// for _, resource := range oldPacket.resources {
	// 	fmt.Println(resource)
	// }

	header := Header{id: 6666, questions: 1, recursionDesired: true}
	question := Question{qType: MX, name: "yahoo.com"}
	questions := []Question{question}
	packet := Packet{header: header, questions: questions}

	reqBuffer := BytePacketBuffer{}
	if err := packet.Write(&reqBuffer); err != nil {
		fmt.Println(err)
		return
	}

	raddr, err := net.ResolveUDPAddr("udp", "8.8.8.8:53")
	if err != nil {
		fmt.Println(err)
		return
	}

	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		fmt.Println(err)
		return
	}
	defer conn.Close()

	if _, err := conn.Write(reqBuffer.buf[:reqBuffer.Pos()]); err != nil {
		fmt.Println(err)
		return
	}

	resBuffer := BytePacketBuffer{}
	if _, err := conn.Read(resBuffer.buf[:]); err != nil {
		fmt.Println(err)
		return
	}

	resPacket, err := Read(&resBuffer)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(resPacket.header)

	for _, question := range resPacket.questions {
		fmt.Println(question)
	}

	for _, answer := range resPacket.answers {
		fmt.Println(answer)
	}

	for _, authority := range resPacket.authorities {
		fmt.Println(authority)
	}

	for _, resource := range resPacket.resources {
		fmt.Println(resource)
	}
}
