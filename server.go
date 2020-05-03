package main

import (
	"fmt"
	"log"
	"net"
)

func lookup(qname string, qtype QueryType, host string, port uint16) (Packet, error) {
	raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return Packet{}, err
	}
	conn, err := net.DialUDP("udp", nil, raddr)
	if err != nil {
		return Packet{}, err
	}
	defer conn.Close()

	header := Header{id: 6666, questions: 1, recursionDesired: true}
	question := Question{name: qname, qType: qtype}
	questions := make([]Question, 1)
	questions[0] = question
	packet := Packet{header: header, questions: questions}

	reqBuffer := BytePacketBuffer{}
	if err := packet.Write(&reqBuffer); err != nil {
		return Packet{}, nil
	}

	if _, err := conn.Write(reqBuffer.buf[:reqBuffer.Pos()]); err != nil {
		return Packet{}, nil
	}

	resBuffer := BytePacketBuffer{}
	if _, err := conn.Read(resBuffer.buf[:]); err != nil {
		return Packet{}, nil
	}

	return Read(&reqBuffer)
}

func recursiveLookup(qname string, qtype QueryType) (Packet, error) {
	// Always start with *a.root-servers.net*
	ns := "198.41.0.4"

	for {
		fmt.Printf("Attempting lookup of %s %s with ns %s", qtype, qname, ns)

		nsCopy := ns
		response, err := lookup(qname, qtype, nsCopy, 53)
		if err != nil {
			return response, err
		}

		if len(response.answers) > 0 && response.header.rescode == NOERROR {
			return response, nil
		}

		if response.header.rescode == NXDOMAIN {
			return response, nil
		}

		if newNs := response.GetResolvedNs(qname); len(newNs) > 0 {
			ns = newNs
			continue
		}

		newNsName := response.GetUnresolvedNs(qname)
		if len(newNsName) == 0 {
			return response, nil
		}

		recursiveResponse, err := recursiveLookup(newNsName, A)
		if err != nil {
			return recursiveResponse, err
		}

		if newNs := recursiveResponse.GetRandomARecord(); len(newNs) > 0 {
			ns = newNs
		} else {
			return response, nil
		}
	}
}

func start() {
	laddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	for {
		reqBuffer := BytePacketBuffer{}
		fmt.Println("Waiting for message...")
		if _, err := conn.Read(reqBuffer.buf[:]); err != nil {
			fmt.Println("Failed to read from UDP socket.")
			fmt.Println(err)
			continue
		}

		request, err := Read(&reqBuffer)
		if err != nil {
			fmt.Println("Failed to parse UDP query packet.")
			fmt.Println(err)
		}

		packet := Packet{}
		header := Header{id: request.header.id, recursionDesired: true, recursionAvailable: true, response: true}

		if len(request.questions) == 0 {
			header.rescode = FORMERR
		} else {
			question := request.questions[0]
			fmt.Printf("Received query: %s\n", question)
			if result, err := recursiveLookup(question.name, question.qType); err != nil {
				header.rescode = SERVFAIL
			} else {
				questions := make([]Question, len(request.questions))
				copy(questions, request.questions)
				header.rescode = result.header.rescode

				answers := make([]Record, len(request.answers))
				for idx, record := range result.answers {
					fmt.Printf("Answer: %s\n", record)
					answers[idx] = record
				}

				authorities := make([]Record, len(request.authorities))
				for idx, record := range result.authorities {
					fmt.Printf("Authority: %s\n", record)
					authorities[idx] = record
				}

				resources := make([]Record, len(request.resources))
				for idx, record := range result.resources {
					fmt.Printf("Resource: %s\n", record)
					resources[idx] = record
				}

				packet.answers = answers
				packet.authorities = authorities
				packet.resources = resources
				packet.questions = questions
			}
		}

		packet.header = header

		resBuffer := BytePacketBuffer{}
		if err := packet.Write(&resBuffer); err != nil {
			fmt.Println("Failed to encode UDP response packet.")
			fmt.Println(err)
			continue
		}

		len := resBuffer.Pos()
		data, err := resBuffer.GetRange(0, len)
		if err != nil {
			fmt.Println("Failed to retrieve response buffer.")
			fmt.Println(err)
			continue
		}

		fmt.Println("Sending response...")
		if _, err := conn.Write(data); err != nil {
			fmt.Println("Failed to send response buffer")
			fmt.Println(err)
			continue
		}
	}
}
