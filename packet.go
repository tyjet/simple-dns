package main

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
