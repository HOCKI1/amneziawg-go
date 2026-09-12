package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync/atomic"
	"time"
)

type DynamicHeader struct {
	InitHeader uint32
	RespHeader uint32
	CookieHead uint32
	DataHeader uint32
	JunkLen    int
}

var lastLoggedSlot atomic.Int64

func init() {
	lastLoggedSlot.Store(-1)
}

func GetDynamicHeaders(psk []byte, timeOffsetSec int64) DynamicHeader {
	timeSlot := (time.Now().Unix() + timeOffsetSec) / 10

	if timeOffsetSec == 0 {
		if lastLoggedSlot.Swap(timeSlot) != timeSlot {
			fmt.Printf("DEBUG: Dynamic header calculation slot updated: %d\n", timeSlot)
		}
	}

	mac := hmac.New(sha256.New, psk)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timeSlot))
	mac.Write(buf)
	seed := mac.Sum(nil)

	return DynamicHeader{
		InitHeader: binary.BigEndian.Uint32(seed[0:4]),
		RespHeader: binary.BigEndian.Uint32(seed[4:8]),
		CookieHead: binary.BigEndian.Uint32(seed[8:12]),
		DataHeader: binary.BigEndian.Uint32(seed[12:16]),
		JunkLen:    int(seed[16] % 64),
	}
}

func (dh DynamicHeader) MatchHeader(incomingHeader uint32) (bool, uint32) {
	switch incomingHeader {
	case dh.InitHeader:
		return true, MessageInitiationType
	case dh.RespHeader:
		return true, MessageResponseType
	case dh.CookieHead:
		return true, MessageCookieReplyType
	case dh.DataHeader:
		return true, MessageTransportType
	default:
		return false, MessageUnknownType
	}
}

func ValidateIncomingHeader(incomingHeader uint32, psk []byte) (isValid bool, matchedOffset int64) {
	offsets := []int64{0, -10, 10}
	for _, offset := range offsets {
		headers := GetDynamicHeaders(psk, offset)
		if incomingHeader == headers.InitHeader ||
			incomingHeader == headers.RespHeader ||
			incomingHeader == headers.CookieHead ||
			incomingHeader == headers.DataHeader {
			return true, offset
		}
	}
	return false, 0
}

func ValidateIncomingHeaderForType(incomingHeader uint32, psk []byte, msgType uint32) (bool, int64) {
	offsets := []int64{0, -10, 10}
	for _, offset := range offsets {
		headers := GetDynamicHeaders(psk, offset)
		var expected uint32
		switch msgType {
		case MessageInitiationType:
			expected = headers.InitHeader
		case MessageResponseType:
			expected = headers.RespHeader
		case MessageCookieReplyType:
			expected = headers.CookieHead
		case MessageTransportType:
			expected = headers.DataHeader
		default:
			continue
		}
		if incomingHeader == expected {
			return true, offset
		}
	}
	return false, 0
}
