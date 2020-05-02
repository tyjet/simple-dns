package main

// Header represents a DNS Header.
type Header struct {
	id                  uint16
	recursionDesired    bool
	truncatedMessage    bool
	authoritativeAnswer bool
	opcode              uint8
	response            bool

	rescode            ResultCode
	checkingDisabled   bool
	authedData         bool
	z                  bool
	recursionAvailable bool

	questions            uint16
	answers              uint16
	authoritativeEntires uint16
	resourceEntries      uint16
}

// ReadHeader reads the headers from a byte packet buffer
func ReadHeader(buffer *BytePacketBuffer) (Header, error) {
	id, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	flags, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	lowFlags := uint8(flags >> 8)
	recursionDesired := lowFlags&(1<<0) > 0
	truncatedMessage := lowFlags&(1<<1) > 0
	authoritativeAnswer := lowFlags&(1<<2) > 0
	opcode := (lowFlags >> 3) & 0x0F
	response := lowFlags&(1<<7) > 0

	highFlags := uint8(flags & 0xFF)
	rescode := ResultCode(highFlags & 0x0F)
	checkingDisabled := highFlags&(1<<4) > 0
	authedData := highFlags&(1<<5) > 0
	z := highFlags&(1<<6) > 0
	recursionAvailable := highFlags&(1<<7) > 0

	questions, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	answers, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	authoritativeEntires, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	resourceEntries, err := buffer.ReadU16()
	if err != nil {
		return Header{}, err
	}

	return Header{
		id:                   id,
		recursionDesired:     recursionDesired,
		truncatedMessage:     truncatedMessage,
		authoritativeAnswer:  authoritativeAnswer,
		opcode:               opcode,
		response:             response,
		rescode:              rescode,
		checkingDisabled:     checkingDisabled,
		authedData:           authedData,
		z:                    z,
		recursionAvailable:   recursionAvailable,
		questions:            questions,
		answers:              answers,
		authoritativeEntires: authoritativeEntires,
		resourceEntries:      resourceEntries,
	}, nil
}

// Write writes this header to the Byte Packet Buffer
func (header *Header) Write(buffer *BytePacketBuffer) error {
	if err := buffer.writeU16(header.id); err != nil {
		return err
	}

	lowFlags := byteFlag(header.recursionDesired, 0) |
		byteFlag(header.truncatedMessage, 1) |
		byteFlag(header.authoritativeAnswer, 2) |
		(byte(header.opcode) << 3) |
		byteFlag(header.response, 7)
	if err := buffer.write(lowFlags); err != nil {
		return err
	}

	highFlags := byte(header.rescode) |
		byteFlag(header.checkingDisabled, 4) |
		byteFlag(header.authedData, 5) |
		byteFlag(header.z, 6) |
		byteFlag(header.recursionAvailable, 7)
	if err := buffer.write(highFlags); err != nil {
		return err
	}

	if err := buffer.writeU16(header.questions); err != nil {
		return err
	}

	if err := buffer.writeU16(header.answers); err != nil {
		return err
	}

	if err := buffer.writeU16(header.authoritativeEntires); err != nil {
		return err
	}

	if err := buffer.writeU16(header.resourceEntries); err != nil {
		return err
	}

	return nil
}

func byteFlag(flag bool, shift int) byte {
	val := byte(0)
	if flag {
		val = byte(1) << shift
	}

	return val
}
