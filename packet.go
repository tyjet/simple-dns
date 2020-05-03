package main

import (
	"math/rand"
	"strings"
)

// Packet represents a DNS packet
type Packet struct {
	header      Header
	questions   []Question
	answers     []Record
	authorities []Record
	resources   []Record
}

// Read a buffer into a packet
func Read(buffer *BytePacketBuffer) (Packet, error) {
	header, err := ReadHeader(buffer)
	if err != nil {
		return Packet{}, err
	}

	questions := make([]Question, header.questions)
	for idx := uint16(0); idx < header.questions; idx++ {
		question, err := ReadQuestion(buffer)
		if err != nil {
			return Packet{}, err
		}
		questions[idx] = question
	}

	answers := make([]Record, header.answers)
	for idx := uint16(0); idx < header.answers; idx++ {
		answer, err := ReadRecord(buffer)
		if err != nil {
			return Packet{}, err
		}
		answers[idx] = answer
	}

	authorities := make([]Record, header.authoritativeEntires)
	for idx := uint16(0); idx < header.authoritativeEntires; idx++ {
		authority, err := ReadRecord(buffer)
		if err != nil {
			return Packet{}, err
		}
		authorities[idx] = authority
	}

	resources := make([]Record, header.resourceEntries)
	for idx := uint16(0); idx < header.resourceEntries; idx++ {
		resource, err := ReadRecord(buffer)
		if err != nil {
			return Packet{}, err
		}
		resources[idx] = resource
	}

	return Packet{header, questions, answers, authorities, resources}, nil
}

// Write writes this packet to a buffer
func (packet *Packet) Write(buffer *BytePacketBuffer) error {
	packet.header.questions = uint16(len(packet.questions))
	packet.header.answers = uint16(len(packet.answers))
	packet.header.authoritativeEntires = uint16(len(packet.authorities))
	packet.header.resourceEntries = uint16(len(packet.resources))

	if err := packet.header.Write(buffer); err != nil {
		return err
	}

	for _, question := range packet.questions {
		if err := question.Write(buffer); err != nil {
			return err
		}
	}

	for _, record := range packet.answers {
		if _, err := record.Write(buffer); err != nil {
			return err
		}
	}

	for _, record := range packet.authorities {
		if _, err := record.Write(buffer); err != nil {
			return err
		}
	}

	for _, record := range packet.resources {
		if _, err := record.Write(buffer); err != nil {
			return err
		}
	}

	return nil
}

// GetRandomARecord returns the IP address of a random a record in the answers
func (packet *Packet) GetRandomARecord() string {
	aRecords := make([]ARecord, len(packet.answers))
	idx := 0
	for _, record := range packet.answers {
		if aRecord, ok := record.(ARecord); ok {
			aRecords[idx] = aRecord
			idx++
		}
	}

	if len(aRecords) == 0 {
		return ""
	}

	idx = rand.Intn(len(packet.answers))
	return aRecords[idx].addr.String()
}

// GetResolvedNs returns the IP address for a NS record (if possible)
func (packet *Packet) GetResolvedNs(qname string) string {
	authorities := make([]ARecord, len(packet.authorities))
	idx := 0
	for _, record := range packet.authorities {
		if nsRecord, ok := record.(NsRecord); ok {
			if !strings.HasSuffix(qname, nsRecord.domain) {
				continue
			}

			for _, resource := range packet.resources {
				if aRecord, ok := resource.(ARecord); ok {
					if nsRecord.host != aRecord.domain {
						continue
					}

					newRecord := ARecord{domain: nsRecord.host, addr: aRecord.addr, ttl: aRecord.ttl}
					authorities[idx] = newRecord
					idx++
				}
			}
		}
	}

	if len(authorities) == 0 {
		return ""
	}

	// Just picK the first authority
	return authorities[0].addr.String()
}

// GetUnresolvedNs returns the next address to query for
func (packet *Packet) GetUnresolvedNs(qname string) string {
	authorities := make([]string, len(packet.authorities))
	idx := 0
	for _, auth := range packet.authorities {
		if nsRecord, ok := auth.(NsRecord); ok {
			if !strings.HasSuffix(qname, nsRecord.domain) {
				continue
			}

			authorities[idx] = nsRecord.host
			idx++
		}
	}

	if len(authorities) == 0 {
		return ""
	}
	idx = rand.Intn(len(authorities))
	return authorities[idx]
}
