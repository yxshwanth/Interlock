package ebpf

import (
	"encoding/binary"
	"testing"
)

func TestDecode_ConnectIPv4AndIPv6(t *testing.T) {
	raw := make([]byte, connectHeaderLen)
	binary.LittleEndian.PutUint32(raw[0:4], eventTypeConnect)
	binary.LittleEndian.PutUint64(raw[8:16], 100)
	binary.LittleEndian.PutUint32(raw[16:20], 7)
	binary.LittleEndian.PutUint32(raw[20:24], 7)
	raw[24] = afInet
	copy(raw[25:29], []byte{203, 0, 113, 1})
	binary.LittleEndian.PutUint16(raw[41:43], 443)
	binary.LittleEndian.PutUint64(raw[48:56], 99)
	copy(raw[56:72], []byte("curl"))

	ev, err := decodeRingEvent(raw)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Connect == nil || ev.Connect.DestIPString() != "203.0.113.1" || ev.Connect.DestPort != 443 {
		t.Fatalf("ipv4 connect decode: %+v", ev.Connect)
	}

	raw6 := make([]byte, connectHeaderLen)
	copy(raw6, raw)
	raw6[24] = afInet6
	copy(raw6[25:41], netIPBytes("2001:db8::2"))
	ev6, err := decodeRingEvent(raw6)
	if err != nil {
		t.Fatal(err)
	}
	if got := ev6.Connect.DestIPString(); got != "2001:db8::2" {
		t.Fatalf("ipv6 connect decode got %q", got)
	}
}

func TestDecode_WritevAndNamedSendmsg(t *testing.T) {
	w := make([]byte, writeHeaderLen+4)
	binary.LittleEndian.PutUint32(w[0:4], eventTypeWritev)
	binary.LittleEndian.PutUint32(w[4:8], 4)
	binary.LittleEndian.PutUint64(w[8:16], 1)
	binary.LittleEndian.PutUint32(w[16:20], 1)
	binary.LittleEndian.PutUint32(w[24:28], 5)
	binary.LittleEndian.PutUint64(w[32:40], 1)
	copy(w[writeHeaderLen:], []byte("abcd"))
	ev, err := decodeRingEvent(w)
	if err != nil || ev.Writev == nil || string(ev.Writev.Payload) != "abcd" || ev.Writev.Syscall != "writev" {
		t.Fatalf("writev decode: %+v err=%v", ev, err)
	}

	s := make([]byte, sendtoHeaderLen+payloadMax)
	binary.LittleEndian.PutUint32(s[0:4], eventTypeSendmsg)
	binary.LittleEndian.PutUint32(s[4:8], 3)
	s[24] = afInet
	copy(s[25:29], []byte{1, 2, 3, 4})
	binary.LittleEndian.PutUint16(s[41:43], 53)
	binary.LittleEndian.PutUint64(s[48:56], 1)
	copy(s[sendtoHeaderLen:], []byte("dns"))
	ev2, err := decodeRingEvent(s)
	if err != nil || ev2.Sendmsg == nil || ev2.Sendmsg.Syscall != "sendmsg" || ev2.Sendmsg.DestIPString() != "1.2.3.4" {
		t.Fatalf("named sendmsg decode: %+v err=%v", ev2, err)
	}
}

func netIPBytes(ip string) []byte {
	parsed := make([]byte, 16)
	// minimal: only used with 2001:db8::2
	if ip == "2001:db8::2" {
		parsed[0], parsed[1] = 0x20, 0x01
		parsed[2], parsed[3] = 0x0d, 0xb8
		parsed[15] = 2
	}
	return parsed
}
