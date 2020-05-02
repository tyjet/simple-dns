package main

import (
	"fmt"
	"net"
)

// Record does something
type Record interface {
	Write(*BytePacketBuffer) (uint32, error)
}

// UnknownRecord represents a DNS record with an unknown type
type UnknownRecord struct {
	domain  string
	qtype   uint16
	dataLen uint16
	ttl     uint32
}

// ARecord represents a type A DNS record
type ARecord struct {
	domain string
	addr   net.IP
	ttl    uint32
}

// NsRecord represents a type NS DNS record
type NsRecord struct {
	domain string
	host   string
	ttl    uint32
}

// CNameRecord represents a CNAME DNS record
type CNameRecord struct {
	domain string
	host   string
	ttl    uint32
}

// MxRecord represents a type MX DNS record
type MxRecord struct {
	domain   string
	priority uint16
	host     string
	ttl      uint32
}

// AaaaRecord represents a type AAAA DNS Record
type AaaaRecord struct {
	domain string
	addr   net.IP
	ttl    uint32
}

func (record *ARecord) String() string {
	return fmt.Sprintf("domain: %s, addr: %s, ttl: %d", record.domain, record.addr, record.ttl)
}

func readARecord(buffer *BytePacketBuffer, domain string, ttl uint32) (ARecord, error) {
	rawAddress, err := buffer.ReadU32()
	if err != nil {
		return ARecord{}, err
	}

	addr := net.IPv4(byte(rawAddress>>24&0xFF), byte(rawAddress>>16&0xFF), byte(rawAddress>>8&0xFF), byte(rawAddress&0xFF))
	return ARecord{domain, addr, ttl}, nil
}

func readAaaaRecord(buffer *BytePacketBuffer, domain string, ttl uint32) (AaaaRecord, error) {
	rawAddress1, err := buffer.ReadU32()
	if err != nil {
		return AaaaRecord{}, err
	}
	rawAddress2, err := buffer.ReadU32()
	if err != nil {
		return AaaaRecord{}, err
	}
	rawAddress3, err := buffer.ReadU32()
	if err != nil {
		return AaaaRecord{}, err
	}
	rawAddress4, err := buffer.ReadU32()
	if err != nil {
		return AaaaRecord{}, err
	}

	addr := make(net.IP, net.IPv6len)
	addr[0] = byte(rawAddress1>>24) & 0XFF
	addr[1] = byte(rawAddress1>>16) & 0xFF
	addr[2] = byte(rawAddress1>>8) & 0xFF
	addr[3] = byte(rawAddress1>>0) & 0xFF
	addr[4] = byte(rawAddress2>>24) & 0XFF
	addr[5] = byte(rawAddress2>>16) & 0xFF
	addr[6] = byte(rawAddress2>>8) & 0xFF
	addr[7] = byte(rawAddress2>>0) & 0xFF
	addr[8] = byte(rawAddress3>>24) & 0XFF
	addr[9] = byte(rawAddress3>>16) & 0xFF
	addr[10] = byte(rawAddress3>>8) & 0xFF
	addr[11] = byte(rawAddress3>>0) & 0xFF
	addr[12] = byte(rawAddress4>>24) & 0XFF
	addr[13] = byte(rawAddress4>>16) & 0xFF
	addr[14] = byte(rawAddress4>>8) & 0xFF
	addr[15] = byte(rawAddress4>>0) & 0xFF

	return AaaaRecord{domain, addr, ttl}, nil
}

func readNsRecord(buffer *BytePacketBuffer, domain string, ttl uint32) (NsRecord, error) {
	host, err := buffer.ReadQName()
	if err != nil {
		return NsRecord{}, err
	}

	return NsRecord{domain, host, ttl}, nil
}

func readCNameRecord(buffer *BytePacketBuffer, domain string, ttl uint32) (CNameRecord, error) {
	host, err := buffer.ReadQName()
	if err != nil {
		return CNameRecord{}, err
	}
	return CNameRecord{domain, host, ttl}, nil
}

func readMxRecord(buffer *BytePacketBuffer, domain string, ttl uint32) (MxRecord, error) {
	priority, err := buffer.ReadU16()
	if err != nil {
		return MxRecord{}, err
	}

	host, err := buffer.ReadQName()
	if err != nil {
		return MxRecord{}, err
	}

	return MxRecord{domain, priority, host, ttl}, nil
}

// ReadRecord reads a DNS record from a buffer
func ReadRecord(buffer *BytePacketBuffer) (Record, error) {
	domain, err := buffer.ReadQName()
	if err != nil {
		return UnknownRecord{}, err
	}

	qtype, err := buffer.ReadU16()
	if err != nil {
		return UnknownRecord{}, err
	}

	// TODO Class
	if _, err := buffer.ReadU16(); err != nil {
		return UnknownRecord{}, err
	}

	ttl, err := buffer.ReadU32()
	if err != nil {
		return UnknownRecord{}, err
	}

	dataLen, err := buffer.ReadU16()
	if err != nil {
		return UnknownRecord{}, err
	}

	switch QueryType(qtype) {
	case A:
		record, err := readARecord(buffer, domain, ttl)
		if err != nil {
			return UnknownRecord{}, err
		}
		return record, nil
	case AAAA:
		record, err := readAaaaRecord(buffer, domain, ttl)
		if err != nil {
			return UnknownRecord{}, err
		}
		return record, nil
	case NS:
		record, err := readNsRecord(buffer, domain, ttl)
		if err != nil {
			return UnknownRecord{}, err
		}
		return record, nil
	case CNAME:
		record, err := readCNameRecord(buffer, domain, ttl)
		if err != nil {
			return UnknownRecord{}, err
		}
		return record, nil
	case MX:
		record, err := readMxRecord(buffer, domain, ttl)
		if err != nil {
			return UnknownRecord{}, err
		}
		return record, nil
	default:
		if err := buffer.Step(uint32(dataLen)); err != nil {
			return &UnknownRecord{}, err
		}

		return &UnknownRecord{domain, qtype, dataLen, ttl}, nil
	}
}

// Write writes this record to a buffer
func (record ARecord) Write(buffer *BytePacketBuffer) (uint32, error) {
	startPos := buffer.Pos()
	if err := buffer.writeQName(record.domain); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(uint16(A)); err != nil {
		return 0, err
	}

	// TODO class
	if err := buffer.writeU16(1); err != nil {
		return 0, err
	}

	if err := buffer.writeU32(record.ttl); err != nil {
		return 0, err
	}

	// Length
	if err := buffer.writeU16(4); err != nil {
		return 0, err
	}

	for _, octet := range record.addr {
		if err := buffer.write(octet); err != nil {
			return 0, err
		}
	}

	return buffer.Pos() - startPos, nil
}

func (record AaaaRecord) Write(buffer *BytePacketBuffer) (uint32, error) {
	startPos := buffer.Pos()
	if err := buffer.writeQName(record.domain); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(uint16(AAAA)); err != nil {
		return 0, err
	}

	// TODO class
	if err := buffer.writeU16(1); err != nil {
		return 0, err
	}

	if err := buffer.writeU32(record.ttl); err != nil {
		return 0, err
	}

	// Length
	if err := buffer.writeU16(16); err != nil {
		return 0, err
	}

	for _, octet := range record.addr {
		if err := buffer.write(octet); err != nil {
			return 0, err
		}
	}

	return buffer.Pos() - startPos, nil
}

func (record NsRecord) Write(buffer *BytePacketBuffer) (uint32, error) {
	startPos := buffer.Pos()
	if err := buffer.writeQName(record.domain); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(uint16(NS)); err != nil {
		return 0, err
	}

	// Class
	if err := buffer.writeU16(1); err != nil {
		return 0, err
	}

	if err := buffer.writeU32(record.ttl); err != nil {
		return 0, err
	}

	pos := buffer.Pos()
	if err := buffer.writeU16(0); err != nil {
		return 0, err
	}

	if err := buffer.writeQName(record.host); err != nil {
		return 0, err
	}
	size := buffer.Pos() - pos - 2
	if err := buffer.SetU16(pos, uint16(size)); err != nil {
		return 0, err
	}

	return buffer.Pos() - startPos, nil
}

func (record CNameRecord) Write(buffer *BytePacketBuffer) (uint32, error) {
	startPos := buffer.Pos()
	if err := buffer.writeQName(record.domain); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(uint16(CNAME)); err != nil {
		return 0, err
	}

	// Class
	if err := buffer.writeU16(1); err != nil {
		return 0, err
	}

	if err := buffer.writeU32(record.ttl); err != nil {
		return 0, err
	}

	pos := buffer.Pos()
	if err := buffer.writeU16(0); err != nil {
		return 0, err
	}

	if err := buffer.writeQName(record.host); err != nil {
		return 0, err
	}
	size := buffer.Pos() - pos - 2
	if err := buffer.SetU16(pos, uint16(size)); err != nil {
		return 0, err
	}

	return buffer.Pos() - startPos, nil
}

func (record MxRecord) Write(buffer *BytePacketBuffer) (uint32, error) {
	startPos := buffer.Pos()
	if err := buffer.writeQName(record.domain); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(uint16(MX)); err != nil {
		return 0, err
	}

	// Class
	if err := buffer.writeU16(1); err != nil {
		return 0, err
	}

	if err := buffer.writeU32(record.ttl); err != nil {
		return 0, err
	}

	pos := buffer.Pos()
	if err := buffer.writeU16(0); err != nil {
		return 0, err
	}

	if err := buffer.writeU16(record.priority); err != nil {
		return 0, err
	}

	if err := buffer.writeQName(record.host); err != nil {
		return 0, err
	}
	size := buffer.Pos() - pos - 2
	if err := buffer.SetU16(pos, uint16(size)); err != nil {
		return 0, err
	}

	return buffer.Pos() - startPos, nil
}

// Write writes this record to a buffer
func (record UnknownRecord) Write(_ *BytePacketBuffer) (uint32, error) {
	fmt.Printf("Skipping UNKNOWN record %s\n", record.domain)

	return 0, nil
}
