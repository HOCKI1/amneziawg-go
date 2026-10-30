package device

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"testing"
	"time"
)

func TestTOTPMutatorBasic(t *testing.T) {
	psk := []byte("01234567890123456789012345678901") // 32 bytes

	// Test GetDynamicHeaders
	dh0 := GetDynamicHeaders(psk, 0)

	// Independently compute expected HMAC
	timeSlot := time.Now().Unix() / 10
	mac := hmac.New(sha256.New, psk)
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timeSlot))
	mac.Write(buf)
	expectedSeed := mac.Sum(nil)

	expectedInit := binary.BigEndian.Uint32(expectedSeed[0:4])
	expectedResp := binary.BigEndian.Uint32(expectedSeed[4:8])
	expectedCookie := binary.BigEndian.Uint32(expectedSeed[8:12])
	expectedData := binary.BigEndian.Uint32(expectedSeed[12:16])
	expectedJunkLen := 12 + int(expectedSeed[16]%52)

	if dh0.InitHeader != expectedInit {
		t.Fatalf("InitHeader mismatch: got %x, expected %x", dh0.InitHeader, expectedInit)
	}
	if dh0.RespHeader != expectedResp {
		t.Fatalf("RespHeader mismatch: got %x, expected %x", dh0.RespHeader, expectedResp)
	}
	if dh0.CookieHead != expectedCookie {
		t.Fatalf("CookieHead mismatch: got %x, expected %x", dh0.CookieHead, expectedCookie)
	}
	if dh0.DataHeader != expectedData {
		t.Fatalf("DataHeader mismatch: got %x, expected %x", dh0.DataHeader, expectedData)
	}
	if dh0.JunkLen != expectedJunkLen {
		t.Fatalf("JunkLen mismatch: got %d, expected %d", dh0.JunkLen, expectedJunkLen)
	}
	if dh0.JunkLen < 12 || dh0.JunkLen >= 64 {
		t.Fatalf("JunkLen out of range [12, 63]: got %d", dh0.JunkLen)
	}
}

func TestTOTPValidationSlots(t *testing.T) {
	psk := []byte("test-preshared-key-1234567890123")

	// Header generated at offset 0 should match offset 0
	dh0 := GetDynamicHeaders(psk, 0)
	isValid, offset := ValidateIncomingHeader(dh0.InitHeader, psk)
	if !isValid || offset != 0 {
		t.Fatalf("Expected valid match at offset 0, got valid=%v offset=%d", isValid, offset)
	}

	isValid, offset = ValidateIncomingHeader(dh0.RespHeader, psk)
	if !isValid || offset != 0 {
		t.Fatalf("Expected valid match for RespHeader at offset 0, got valid=%v offset=%d", isValid, offset)
	}

	isValid, offset = ValidateIncomingHeader(dh0.CookieHead, psk)
	if !isValid || offset != 0 {
		t.Fatalf("Expected valid match for CookieHead at offset 0, got valid=%v offset=%d", isValid, offset)
	}

	isValid, offset = ValidateIncomingHeader(dh0.DataHeader, psk)
	if !isValid || offset != 0 {
		t.Fatalf("Expected valid match for DataHeader at offset 0, got valid=%v offset=%d", isValid, offset)
	}

	// Header generated at -10s offset should validate with matchedOffset == -10
	dhMinus10 := GetDynamicHeaders(psk, -10)
	isValid, offset = ValidateIncomingHeader(dhMinus10.InitHeader, psk)
	if !isValid {
		t.Fatalf("Expected valid match for -10s offset")
	}

	// Header generated at +10s offset should validate with matchedOffset == 10
	dhPlus10 := GetDynamicHeaders(psk, 10)
	isValid, offset = ValidateIncomingHeader(dhPlus10.InitHeader, psk)
	if !isValid {
		t.Fatalf("Expected valid match for +10s offset")
	}

	// Header generated at +30s offset (out of tolerance) should be rejected
	dhPlus30 := GetDynamicHeaders(psk, 30)
	// Check that dhPlus30 is actually from a different slot
	slotNow := time.Now().Unix() / 10
	slot30 := (time.Now().Unix() + 30) / 10
	if slot30 > slotNow+1 {
		isValid, _ = ValidateIncomingHeader(dhPlus30.InitHeader, psk)
		if isValid {
			t.Fatalf("Expected header from +30s offset to be rejected, but was validated")
		}
	}

	// Random header with wrong PSK should fail
	wrongPSK := []byte("different-psk-987654321098765432")
	isValid, _ = ValidateIncomingHeader(dh0.InitHeader, wrongPSK)
	if isValid {
		t.Fatalf("Expected validation to fail with wrong PSK")
	}

	// Arbitrary header should fail
	isValid, _ = ValidateIncomingHeader(0xdeadbeef, psk)
	if isValid {
		t.Fatalf("Expected arbitrary header 0xdeadbeef to fail")
	}
}

func TestDeterminePacketTypeWithTOTP(t *testing.T) {
	device := new(Device)
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)

	var psk NoisePresharedKey
	copy(psk[:], []byte("totp-test-psk-32-bytes-long-key!"))

	peer := new(Peer)
	peer.device = device
	peer.handshake.presharedKey = psk
	var pk NoisePublicKey
	copy(pk[:], []byte("fake-peer-pubkey-32-bytes-long!"))
	device.peers.keyMap[pk] = peer

	dh := GetDynamicHeaders(psk[:], 0)
	padding := uint32(dh.JunkLen)

	// 1. Initiation packet
	packet := make([]byte, int(padding)+MessageInitiationSize)
	binary.LittleEndian.PutUint32(packet[padding:padding+4], dh.InitHeader)

	msgSize, msgType, pad := device.DeterminePacketTypeAndPadding(packet, nil)
	if msgType != MessageInitiationType {
		t.Fatalf("Expected MessageInitiationType (%d), got %d", MessageInitiationType, msgType)
	}
	if msgSize != MessageInitiationSize {
		t.Fatalf("Expected MessageInitiationSize (%d), got %d", MessageInitiationSize, msgSize)
	}
	if pad != padding {
		t.Fatalf("Expected padding %d, got %d", padding, pad)
	}

	// 2. Response packet
	respPacket := make([]byte, int(padding)+MessageResponseSize)
	binary.LittleEndian.PutUint32(respPacket[padding:padding+4], dh.RespHeader)

	msgSize, msgType, pad = device.DeterminePacketTypeAndPadding(respPacket, nil)
	if msgType != MessageResponseType {
		t.Fatalf("Expected MessageResponseType (%d), got %d", MessageResponseType, msgType)
	}
	if msgSize != MessageResponseSize {
		t.Fatalf("Expected MessageResponseSize (%d), got %d", MessageResponseSize, msgSize)
	}

	// 3. Transport packet
	dataPacket := make([]byte, int(padding)+MessageTransportSize+100)
	binary.LittleEndian.PutUint32(dataPacket[padding:padding+4], dh.DataHeader)

	msgSize, msgType, pad = device.DeterminePacketTypeAndPadding(dataPacket, nil)
	if msgType != MessageTransportType {
		t.Fatalf("Expected MessageTransportType (%d), got %d", MessageTransportType, msgType)
	}

	// 4. Invalid packet header should be rejected (unknown type)
	invalidPacket := make([]byte, int(padding)+MessageInitiationSize)
	binary.LittleEndian.PutUint32(invalidPacket[padding:padding+4], 0x12345678)

	_, msgType, _ = device.DeterminePacketTypeAndPadding(invalidPacket, nil)
	if msgType != MessageUnknownType {
		t.Fatalf("Expected MessageUnknownType for invalid header, got %d", msgType)
	}
}

func TestJunkPacketsDynamicLen(t *testing.T) {
	device := new(Device)
	device.junk.count.Store(3)

	psk := []byte("totp-test-psk-32-bytes-long-key!")
	dh := GetDynamicHeaders(psk, 0)

	bufs := device.JunkPacketsWithLen(dh.JunkLen)
	if len(bufs) != 3 {
		t.Fatalf("Expected 3 junk packets, got %d", len(bufs))
	}
	for i, b := range bufs {
		if len(b) != dh.JunkLen {
			t.Fatalf("Junk packet %d has length %d, expected %d", i, len(b), dh.JunkLen)
		}
	}
}

func TestClassicAmneziaFallback(t *testing.T) {
	device := new(Device)
	device.peers.keyMap = make(map[NoisePublicKey]*Peer)

	// Configure a peer WITH PSK on the server
	var psk NoisePresharedKey
	copy(psk[:], []byte("totp-test-psk-32-bytes-long-key!"))
	peerWithPSK := new(Peer)
	peerWithPSK.device = device
	peerWithPSK.handshake.presharedKey = psk
	var pk NoisePublicKey
	copy(pk[:], []byte("fake-peer-pubkey-32-bytes-long!"))
	device.peers.keyMap[pk] = peerWithPSK

	// Static Amnezia configuration (e.g. H1=100, S1=15, H4=200, S4=20)
	var r1, r4 UintRange
	r1.FromUint32(100, 100)
	r4.FromUint32(200, 200)
	device.headers.init.Store(r1)
	device.paddings.init.Store(15)
	device.headers.transport.Store(r4)
	device.paddings.transport.Store(20)

	// 1. Packet from a classic Amnezia user (static H1=100, S1=15)
	classicInit := make([]byte, 15+MessageInitiationSize)
	binary.LittleEndian.PutUint32(classicInit[15:15+4], 100)

	msgSize, msgType, pad := device.DeterminePacketTypeAndPadding(classicInit, nil)
	if msgType != MessageInitiationType {
		t.Fatalf("Expected MessageInitiationType for classic Amnezia client, got %d", msgType)
	}
	if pad != 15 {
		t.Fatalf("Expected padding 15, got %d", pad)
	}
	if msgSize != MessageInitiationSize {
		t.Fatalf("Expected MessageInitiationSize %d, got %d", MessageInitiationSize, msgSize)
	}

	// 2. Transport packet from a classic Amnezia user (static H4=200, S4=20)
	classicData := make([]byte, 20+MessageTransportSize+50)
	binary.LittleEndian.PutUint32(classicData[20:20+4], 200)

	msgSize, msgType, pad = device.DeterminePacketTypeAndPadding(classicData, nil)
	if msgType != MessageTransportType {
		t.Fatalf("Expected MessageTransportType for classic Amnezia transport, got %d", msgType)
	}
	if pad != 20 {
		t.Fatalf("Expected padding 20, got %d", pad)
	}

	// 3. Packet from a TOTP user on the same server should still work
	dh := GetDynamicHeaders(psk[:], 0)
	totpInit := make([]byte, int(dh.JunkLen)+MessageInitiationSize)
	binary.LittleEndian.PutUint32(totpInit[dh.JunkLen:dh.JunkLen+4], dh.InitHeader)

	msgSize, msgType, pad = device.DeterminePacketTypeAndPadding(totpInit, nil)
	if msgType != MessageInitiationType {
		t.Fatalf("Expected MessageInitiationType for TOTP client, got %d", msgType)
	}
	if pad != uint32(dh.JunkLen) {
		t.Fatalf("Expected padding %d for TOTP client, got %d", dh.JunkLen, pad)
	}
}
