package ws

import (
	"encoding/binary"
	"encoding/json"
)

const (
	wireVersion    byte = 1
	wireHeaderSize int  = 17
)

func encodeWireMessage(msg *Message) []byte {
	routeBytes := []byte(msg.Route)
	errorBytes := []byte(msg.Error)
	payloadBytes := msg.Payload
	total := wireHeaderSize + len(routeBytes) + len(errorBytes) + len(payloadBytes)

	frame := make([]byte, total)
	frame[0] = wireVersion
	binary.BigEndian.PutUint64(frame[1:9], msg.ID)
	binary.BigEndian.PutUint16(frame[9:11], uint16(len(routeBytes)))
	binary.BigEndian.PutUint16(frame[11:13], uint16(len(errorBytes)))
	binary.BigEndian.PutUint32(frame[13:17], uint32(len(payloadBytes)))

	offset := wireHeaderSize
	copy(frame[offset:], routeBytes)
	offset += len(routeBytes)
	copy(frame[offset:], errorBytes)
	offset += len(errorBytes)
	copy(frame[offset:], payloadBytes)

	return frame
}

func decodeWireMessage(data []byte) (*Message, error) {
	if len(data) == 0 {
		return nil, ErrInvalidWireMessage
	}

	if data[0] == '{' {
		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			return nil, err
		}

		return &msg, nil
	}

	if len(data) < wireHeaderSize || data[0] != wireVersion {
		return nil, ErrInvalidWireMessage
	}

	id := binary.BigEndian.Uint64(data[1:9])
	routeLen := int(binary.BigEndian.Uint16(data[9:11]))
	errorLen := int(binary.BigEndian.Uint16(data[11:13]))
	payloadLen := int(binary.BigEndian.Uint32(data[13:17]))

	offset := wireHeaderSize
	total := wireHeaderSize + routeLen + errorLen + payloadLen
	if total != len(data) {
		return nil, ErrInvalidWireMessage
	}

	route := string(data[offset : offset+routeLen])
	offset += routeLen
	errText := string(data[offset : offset+errorLen])
	offset += errorLen
	payload := json.RawMessage(data[offset : offset+payloadLen])

	return &Message{
		ID:      id,
		Route:   route,
		Payload: payload,
		Error:   errText,
	}, nil
}
