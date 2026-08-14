// Package lotor is the Go client for the LWP/1 data-plane protocol. A customer's
// backend speaks to lotord over one warm connection for authentication,
// authorization, metering, wallets, allowances, and lifecycle operations.
package lotor

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
)

const protoVersion = 1

const (
	frameREQ   = 1
	frameRESP  = 2
	frameEVENT = 3
	framePONG  = 5
)

const (
	statusOK  = 0
	statusERR = 1
)

const (
	opHELLO                  = 0x0001
	opAUTH                   = 0x0002
	opPING                   = 0x0003
	opQUIT                   = 0x0004
	opAUTHVERIFY             = 0x0010
	opACCESSCHECK            = 0x0020
	opACCESSGRANT            = 0x0021
	opACCESSREVOKE           = 0x0022
	opACCESSEXPAND           = 0x0023
	opMETERCONSUME           = 0x0030
	opMETERRELEASE           = 0x0031
	opMETERGET               = 0x0032
	opSEATCLAIM              = 0x0040
	opSEATRELEASE            = 0x0041
	opCONFGET                = 0x0050
	opWALLETCREDIT           = 0x0070
	opWALLETDEBIT            = 0x0071
	opWALLETGET              = 0x0072
	opALLOWANCEGRANT         = 0x0073
	opALLOWANCEGET           = 0x0074
	opPOLICYCHECK            = 0x0080
	opINVITECREATE           = 0x0090
	opINVITEACCEPT           = 0x0091
	opINVITECANCEL           = 0x0092
	opINVITELIST             = 0x0093
	opMEMBERREMOVE           = 0x0094
	opMEMBERROLESET          = 0x0095
	opSUBJECTKEYREGISTER     = 0x00A0
	opSUBJECTKEYLIST         = 0x00A1
	opSUBJECTKEYREVOKE       = 0x00A2
	opRESOURCEKEYCREATE      = 0x00A3
	opRESOURCEGRANTPREPARE   = 0x00A4
	opRESOURCEENVELOPESUBMIT = 0x00A5
	opRESOURCEENVELOPEGET    = 0x00A6
	opRESOURCEMEMBERLIST     = 0x00A7
	opRESOURCEGRANTREVOKE    = 0x00A8
	opENCRYPTEDINVITECREATE  = 0x00A9
	opENCRYPTEDINVITEACCEPT  = 0x00AA
	opWATCH                  = 0x0060
	opUNWATCH                = 0x0061
)

const (
	tagNull  = 0x00
	tagBool  = 0x01
	tagU64   = 0x02
	tagI64   = 0x03
	tagStr   = 0x04
	tagBytes = 0x05
	tagAddr  = 0x06
	tagList  = 0x07
	tagMap   = 0x08
)

var errShort = errors.New("short read")

// value is a decoded LWP argument (only the kinds the client uses).
type value struct {
	Map   map[string]value
	Str   string
	Bytes []byte
	List  []value
	U64   uint64
	I64   int64
	Kind  byte
	Bool  bool
}

func vU64(n uint64) value        { return value{Kind: tagU64, U64: n} }
func vStr(s string) value        { return value{Kind: tagStr, Str: s} }
func vAddr(s string) value       { return value{Kind: tagAddr, Str: s} }
func vBool(enabled bool) value   { return value{Kind: tagBool, Bool: enabled} }
func vBytes(bytes []byte) value  { return value{Kind: tagBytes, Bytes: bytes} }
func vList(values []value) value { return value{Kind: tagList, List: values} }
func vNull() value               { return value{Kind: tagNull} }
func vMap(values map[string]value) value {
	return value{Kind: tagMap, Map: values}
}

func (v value) asStr() string {
	if v.Kind == tagStr || v.Kind == tagAddr {
		return v.Str
	}
	return ""
}

func (v value) asNum() int64 {
	switch v.Kind {
	case tagU64:
		return uint64ToInt64(v.U64)
	case tagI64:
		return v.I64
	}
	return 0
}

func (v value) asBool() bool { return v.Kind == tagBool && v.Bool }

func uint64ToInt64(n uint64) int64 {
	if n > ^uint64(0)>>1 {
		return 0
	}
	return int64(n)
}

func nonNegativeInt64ToUint64(n int64) uint64 {
	if n < 0 {
		return 0
	}
	return uint64(n)
}

func uint64ToInt(n uint64) (int, bool) {
	if n > uint64(^uint(0)>>1) {
		return 0, false
	}
	return int(n), true
}

func intToUint32(n int) uint32 {
	if n < 0 || n > int(^uint32(0)) {
		panic("frame too large")
	}
	return uint32(n)
}

// Varint.
func putUvarint(b []byte, v uint64) []byte {
	for {
		c := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			c |= 0x80
		}
		b = append(b, c)
		if v == 0 {
			return b
		}
	}
}

func readUvarint(b []byte, p *int) (uint64, error) {
	var result uint64
	var shift uint
	for {
		if *p >= len(b) {
			return 0, errShort
		}
		c := b[*p]
		*p++
		result |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return result, nil
		}
		shift += 7
	}
}

func zigzag(v int64) uint64 {
	if v >= 0 {
		return uint64(v) << 1
	}
	magnitude := -(v + 1)
	return nonNegativeInt64ToUint64(magnitude)*2 + 1
}

func unzigzag(v uint64) int64 {
	half := v >> 1
	if v&1 == 0 {
		return uint64ToInt64(half)
	}
	return -uint64ToInt64(half) - 1
}

// value codec.
func encodeValue(b []byte, v value) []byte {
	switch v.Kind {
	case tagNull:
		return append(b, tagNull)
	case tagBool:
		x := byte(0)
		if v.Bool {
			x = 1
		}
		return append(b, tagBool, x)
	case tagU64:
		return putUvarint(append(b, tagU64), v.U64)
	case tagI64:
		return putUvarint(append(b, tagI64), zigzag(v.I64))
	case tagStr, tagAddr:
		b = append(b, v.Kind)
		b = putUvarint(b, uint64(len(v.Str)))
		return append(b, v.Str...)
	case tagBytes:
		b = append(b, tagBytes)
		b = putUvarint(b, uint64(len(v.Bytes)))
		return append(b, v.Bytes...)
	case tagList:
		b = append(b, tagList)
		b = putUvarint(b, uint64(len(v.List)))
		for _, it := range v.List {
			b = encodeValue(b, it)
		}
		return b
	case tagMap:
		b = append(b, tagMap)
		b = putUvarint(b, uint64(len(v.Map)))
		keys := make([]string, 0, len(v.Map))
		for key := range v.Map {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			b = putUvarint(b, uint64(len(key)))
			b = append(b, key...)
			b = encodeValue(b, v.Map[key])
		}
		return b
	}
	return append(b, tagNull)
}

func decodeValue(b []byte, p *int) (value, error) {
	if *p >= len(b) {
		return value{}, errShort
	}
	tag := b[*p]
	*p++
	switch tag {
	case tagNull:
		return value{Kind: tagNull}, nil
	case tagBool:
		if *p >= len(b) {
			return value{}, errShort
		}
		v := value{Kind: tagBool, Bool: b[*p] != 0}
		*p++
		return v, nil
	case tagU64:
		n, err := readUvarint(b, p)
		return value{Kind: tagU64, U64: n}, err
	case tagI64:
		n, err := readUvarint(b, p)
		return value{Kind: tagI64, I64: unzigzag(n)}, err
	case tagStr, tagAddr:
		s, err := readBytes(b, p)
		return value{Kind: tag, Str: string(s)}, err
	case tagBytes:
		s, err := readBytes(b, p)
		return value{Kind: tagBytes, Bytes: s}, err
	case tagList:
		n, err := readUvarint(b, p)
		if err != nil {
			return value{}, err
		}
		items := make([]value, 0, n)
		for range n {
			it, err := decodeValue(b, p)
			if err != nil {
				return value{}, err
			}
			items = append(items, it)
		}
		return value{Kind: tagList, List: items}, nil
	case tagMap:
		n, err := readUvarint(b, p)
		if err != nil {
			return value{}, err
		}
		m := make(map[string]value, n)
		for range n {
			key, err := readBytes(b, p)
			if err != nil {
				return value{}, err
			}
			val, err := decodeValue(b, p)
			if err != nil {
				return value{}, err
			}
			m[string(key)] = val
		}
		return value{Kind: tagMap, Map: m}, nil
	}
	return value{}, fmt.Errorf("unknown tag %d", tag)
}

func readBytes(b []byte, p *int) ([]byte, error) {
	n, err := readUvarint(b, p)
	if err != nil {
		return nil, err
	}
	length, ok := uint64ToInt(n)
	if !ok || length > len(b)-*p {
		return nil, errShort
	}
	s := b[*p : *p+length]
	*p += length
	return s, nil
}

// Frames.
type frame struct {
	args   []value
	typ    byte
	flags  uint16
	reqID  uint32
	opcode uint16 // REQ: opcode; RESP: status
}

func encodeFrame(f frame) []byte {
	p := make([]byte, 0, 64)
	p = append(p, protoVersion, f.typ)
	p = binary.BigEndian.AppendUint16(p, f.flags)
	p = binary.BigEndian.AppendUint32(p, f.reqID)
	p = binary.BigEndian.AppendUint16(p, f.opcode)
	p = putUvarint(p, uint64(len(f.args)))
	for _, a := range f.args {
		p = encodeValue(p, a)
	}
	out := binary.BigEndian.AppendUint32(make([]byte, 0, 4+len(p)), intToUint32(len(p)))
	return append(out, p...)
}

// decodeFrame parses one frame from the front of buf; returns the frame, bytes consumed, ok.
func decodeFrame(buf []byte) (frame, int, bool) {
	if len(buf) < 4 {
		return frame{}, 0, false
	}
	n := binary.BigEndian.Uint32(buf)
	total := 4 + int(n)
	if len(buf) < total {
		return frame{}, 0, false
	}
	p := 4
	ver := buf[p]
	p++
	_ = ver
	typ := buf[p]
	p++
	flags := binary.BigEndian.Uint16(buf[p:])
	p += 2
	reqID := binary.BigEndian.Uint32(buf[p:])
	p += 4
	opcode := binary.BigEndian.Uint16(buf[p:])
	p += 2
	argc, err := readUvarint(buf, &p)
	if err != nil {
		return frame{}, 0, false
	}
	args := make([]value, 0, argc)
	for range argc {
		v, err := decodeValue(buf, &p)
		if err != nil {
			return frame{}, 0, false
		}
		args = append(args, v)
	}
	return frame{typ: typ, flags: flags, reqID: reqID, opcode: opcode, args: args}, total, true
}
