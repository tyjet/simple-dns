package main

import (
	"fmt"
	"strings"
)

// BytePacketBuffer is a structure for manipulating DNS packets.
type BytePacketBuffer struct {
	buf [512]byte
	pos uint32
}

// InvalidInput error
type InvalidInput string

func (e InvalidInput) Error() string {
	return string(e)
}

// Pos reads the current position of our buffer.
func (bytePacketBuffer *BytePacketBuffer) Pos() uint32 {
	return bytePacketBuffer.pos
}

// Step steps through the buffer by the desired number of steps.
func (bytePacketBuffer *BytePacketBuffer) Step(steps uint32) error {
	bytePacketBuffer.pos += steps
	return nil
}

// Seek sets the current position of the buffer to the desired marker.
func (bytePacketBuffer *BytePacketBuffer) Seek(pos uint32) error {
	bytePacketBuffer.pos = pos
	return nil
}

// Read reads a single byte in the buffer and moves one step forward.
func (bytePacketBuffer *BytePacketBuffer) Read() (byte, error) {
	if bytePacketBuffer.pos >= 512 {
		return 0, InvalidInput(fmt.Sprintf("End of buffer. Failed at position %d.", bytePacketBuffer.pos))
	}

	res := bytePacketBuffer.buf[bytePacketBuffer.pos]
	bytePacketBuffer.pos++

	return res, nil
}

// Get one byte without stepping through the buffer
func (bytePacketBuffer *BytePacketBuffer) Get(pos uint32) (byte, error) {
	if pos >= 512 {
		return 0, InvalidInput(fmt.Sprintf("End of buffer. Failed at position %d.", pos))
	}

	return bytePacketBuffer.buf[pos], nil
}

// GetRange retrieves a range of bytes without stepping through the buffer
func (bytePacketBuffer *BytePacketBuffer) GetRange(start uint32, len uint32) ([]byte, error) {
	if start+len >= 512 {
		return nil, InvalidInput(fmt.Sprintf("End of buffer. Failed at between position %d and %d.", start, start+len))
	}

	buf := make([]byte, len)
	copy(buf, bytePacketBuffer.buf[start:start+len])
	return buf, nil
}

// ReadU16 reads two bytes as an unsigned sixteen bit integer and steps through the buffer by two bytes
func (bytePacketBuffer *BytePacketBuffer) ReadU16() (uint16, error) {
	high, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	low, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	return uint16(high)<<8 | uint16(low), nil
}

// ReadU32 reads four bytes as an unsigned 32 bit integer and steps through the buffer by four bytes
func (bytePacketBuffer *BytePacketBuffer) ReadU32() (uint32, error) {
	b0, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	b1, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	b2, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	b3, err := bytePacketBuffer.Read()
	if err != nil {
		return 0, err
	}

	return uint32(b0)<<24 | uint32(b1)<<16 | uint32(b2)<<8 | uint32(b3), nil
}

// ReadQName returns the domain name for the record.
func (bytePacketBuffer *BytePacketBuffer) ReadQName() (string, error) {
	pos := bytePacketBuffer.pos
	jumped := false
	delimiter := ""
	out := ""

	for {
		len, err := bytePacketBuffer.Get(pos)
		if err != nil {
			return "", err
		}

		if len&0xC0 == 0xC0 {
			if !jumped {
				bytePacketBuffer.Seek(pos + 2)
			}

			low, err := bytePacketBuffer.Get(pos + 1)
			if err != nil {
				return "", err
			}
			offset := (uint16(len)^0xC0)<<8 | uint16(low)
			pos = uint32(offset)
			jumped = true
		} else {
			pos++
			if len == 0 {
				break
			}

			out += delimiter
			label, err := bytePacketBuffer.GetRange(pos, uint32(len))
			if err != nil {
				return "", nil
			}
			out += strings.ToLower(string(label))
			delimiter = "."
			pos += uint32(len)
		}
	}

	if !jumped {
		bytePacketBuffer.Seek(pos)
	}

	return out, nil
}

func (bytePacketBuffer *BytePacketBuffer) write(val byte) error {
	if bytePacketBuffer.pos >= 512 {
		return InvalidInput(fmt.Sprintf("End of buffer. Failed at position %d.", bytePacketBuffer.pos))
	}

	bytePacketBuffer.buf[bytePacketBuffer.pos] = val
	bytePacketBuffer.pos++
	return nil
}

func (bytePacketBuffer *BytePacketBuffer) writeU16(val uint16) error {
	if err := bytePacketBuffer.write(byte(val>>8) & 0xFF); err != nil {
		return err
	}

	if err := bytePacketBuffer.write(byte(val) & 0xFF); err != nil {
		bytePacketBuffer.pos--
		return err
	}

	return nil
}

func (bytePacketBuffer *BytePacketBuffer) writeU32(val uint32) error {
	if err := bytePacketBuffer.write(byte(val>>24) & 0xFF); err != nil {
		return err
	}

	if err := bytePacketBuffer.write(byte(val>>16) & 0xFF); err != nil {
		bytePacketBuffer.pos--
		return err
	}

	if err := bytePacketBuffer.write(byte(val>>8) & 0xFF); err != nil {
		bytePacketBuffer.pos -= 2
		return err
	}

	if err := bytePacketBuffer.write(byte(val) & 0xFF); err != nil {
		bytePacketBuffer.pos -= 3
		return err
	}

	return nil
}

func (bytePacketBuffer *BytePacketBuffer) writeQName(qname string) error {
	labels := strings.Split(qname, ".")
	undo := 0
	for idx, label := range labels {
		len := len(label)
		if len > 63 {
			return InvalidInput("Single label exceeds 63 characters of length")
		}

		if err := bytePacketBuffer.write(byte(len)); err != nil {
			bytePacketBuffer.pos -= uint32(idx + undo)
			return err
		}

		for byteIdx, b := range []byte(label) {
			if err := bytePacketBuffer.write(b); err != nil {
				bytePacketBuffer.pos -= uint32(idx + byteIdx + undo + 1)
				return err
			}
		}
		undo += len
	}

	if err := bytePacketBuffer.write(0); err != nil {
		bytePacketBuffer.pos -= uint32(len(labels) + undo)
		return err
	}

	return nil
}

// Set writes a byte at the specified position
func (bytePacketBuffer *BytePacketBuffer) Set(pos uint32, val byte) error {
	bytePacketBuffer.buf[pos] = val
	return nil
}

// SetU16 writes a uint 16 at the specified position
func (bytePacketBuffer *BytePacketBuffer) SetU16(pos uint32, val uint16) error {
	if err := bytePacketBuffer.Set(pos, byte(val>>8)); err != nil {
		return err
	}

	if err := bytePacketBuffer.Set(pos+1, byte(val&0xFF)); err != nil {
		return err
	}

	return nil
}
