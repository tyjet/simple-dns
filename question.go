package main

import "fmt"

// Question represents a question entry in a DNS packet
type Question struct {
	name  string
	qType QueryType
}

// ReadQuestion reads a packet and return the question entry
func ReadQuestion(buffer *BytePacketBuffer) (Question, error) {
	name, err := buffer.ReadQName()
	if err != nil {
		return Question{}, err
	}

	qType, err := buffer.ReadU16()
	if err != nil {
		return Question{}, err
	}

	// TODO class
	_, err = buffer.ReadU16()
	if err != nil {
		return Question{}, err
	}

	return Question{name, QueryType(qType)}, nil
}

// Write writes this question to a packet buffer
func (question Question) Write(buffer *BytePacketBuffer) error {
	if err := buffer.writeQName(question.name); err != nil {
		return err
	}

	if err := buffer.writeU16(uint16(question.qType)); err != nil {
		return err
	}

	// TODO class
	if err := buffer.writeU16(1); err != nil {
		return err
	}

	return nil
}

func (question Question) String() string {
	return fmt.Sprintf("name: %s, qtype: %s", question.name, question.qType)
}
