package tlsx

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
)

const (
	ServerHelloRandomLen = 32
)

// CurveID is the type of a TLS identifier for an elliptic curve. See
// https://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8.
type CurveID uint16

// TLS 1.3 Key Share. See RFC 8446, Section 4.2.8.
type keyShare struct {
	group CurveID
	data  []byte
}

// readUint8LengthPrefixed acts like s.ReadUint8LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint8LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint8LengthPrefixed((*cryptobyte.String)(out))
}

// readUint16LengthPrefixed acts like s.ReadUint16LengthPrefixed, but targets a
// []byte instead of a cryptobyte.String.
func readUint16LengthPrefixed(s *cryptobyte.String, out *[]byte) bool {
	return s.ReadUint16LengthPrefixed((*cryptobyte.String)(out))
}

// TLS extension numbers
const (
	extensionServerName              uint16 = 0
	extensionStatusRequest           uint16 = 5
	extensionSupportedCurves         uint16 = 10 // supported_groups in TLS 1.3, see RFC 8446, Section 4.2.7
	extensionSupportedPoints         uint16 = 11
	extensionSignatureAlgorithms     uint16 = 13
	extensionALPN                    uint16 = 16
	extensionSCT                     uint16 = 18
	extensionSessionTicket           uint16 = 35
	extensionPreSharedKey            uint16 = 41
	extensionEarlyData               uint16 = 42
	extensionSupportedVersions       uint16 = 43
	extensionCookie                  uint16 = 44
	extensionPSKModes                uint16 = 45
	extensionCertificateAuthorities  uint16 = 47
	extensionSignatureAlgorithmsCert uint16 = 50
	extensionKeyShare                uint16 = 51
	extensionNextProtoNeg            uint16 = 13172 // not IANA assigned
	extensionRenegotiationInfo       uint16 = 0xff01
)

type ServerHello struct {
	ServerHelloBasic

	NextProtoNeg                 bool
	NextProtos                   []string
	OCSPStapling                 bool
	TicketSupported              bool
	SecureRenegotiationSupported bool
	SecureRenegotiation          []byte
	AlpnProtocol                 string
	Ems                          bool
	Scts                         [][]byte
	SupportedVersion             uint16
	ServerShare                  keyShare
	SelectedIdentityPresent      bool
	SelectedIdentity             uint16

	// HelloRetryRequest extensions
	Cookie []byte
}

func (m *ServerHello) Unmarshal(data []byte) error {

	if len(data) < 5+4 {
		return errors.New("server returned short message")
	}

	// buf contains a TLS record, with a 5 byte record header and a 4 byte
	// handshake header. The length of the ServerHello is taken from the
	// handshake header.
	serverHelloLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])

	if serverHelloLen >= len(data) {
		return errors.New("invalid serverHelloLen")
	}

	// prevent slice bounds out of range [:19] with capacity 11
	if len(data) < 9+serverHelloLen {
		return errors.New("invalid data length for server hello")
	}

	data = data[5 : 9+serverHelloLen]

	*m = ServerHello{}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionID) ||
		!s.ReadUint16(&m.CipherSuite) ||
		!s.ReadUint8(&m.CompressionMethod) {
		return errors.New("invalid message type")
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return errors.New("failed to read extensions")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return errors.New("failed to read extension data")
		}

		m.Extensions = append(m.Extensions, extension)

		switch extension {
		case extensionNextProtoNeg:
			m.NextProtoNeg = true
			for !extData.Empty() {
				var proto cryptobyte.String
				if !extData.ReadUint8LengthPrefixed(&proto) ||
					proto.Empty() {
					return errors.New("failed to read extensionNextProtoNeg")
				}
				m.NextProtos = append(m.NextProtos, string(proto))
			}
		case extensionStatusRequest:
			m.OCSPStapling = true
		case extensionSessionTicket:
			m.TicketSupported = true
		case extensionRenegotiationInfo:
			if !readUint8LengthPrefixed(&extData, &m.SecureRenegotiation) {
				return errors.New("failed to read extensionRenegotiationInfo")
			}
			m.SecureRenegotiationSupported = true
		case extensionALPN:
			var protoList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&protoList) || protoList.Empty() {
				return errors.New("failed to read extensionALPN protoList")
			}
			var proto cryptobyte.String
			if !protoList.ReadUint8LengthPrefixed(&proto) ||
				proto.Empty() || !protoList.Empty() {
				return errors.New("failed to read extensionRenegotiationInfo proto")
			}
			m.AlpnProtocol = string(proto)
		case extensionSCT:
			var sctList cryptobyte.String
			if !extData.ReadUint16LengthPrefixed(&sctList) || sctList.Empty() {
				return errors.New("failed to read extensionSCT sctList")
			}
			for !sctList.Empty() {
				var sct []byte
				if !readUint16LengthPrefixed(&sctList, &sct) ||
					len(sct) == 0 {
					return errors.New("failed to read extensionSCT sctList sct")
				}
				m.Scts = append(m.Scts, sct)
			}
		case extensionSupportedVersions:
			if !extData.ReadUint16(&m.SupportedVersion) {
				return errors.New("failed to read extensionSupportedVersions")
			}
		case extensionCookie:
			if !readUint16LengthPrefixed(&extData, &m.Cookie) ||
				len(m.Cookie) == 0 {
				return errors.New("failed to read extensionCookie")
			}
		case extensionKeyShare:
			// This extension has different formats in SH and HRR, accept either
			// and let the handshake logic decide. See RFC 8446, Section 4.2.8.
			if len(extData) == 2 {
				if !extData.ReadUint16((*uint16)(&m.SelectedGroup)) {
					return errors.New("failed to read extensionKeyShare")
				}
			} else {
				if !extData.ReadUint16((*uint16)(&m.ServerShare.group)) ||
					!readUint16LengthPrefixed(&extData, &m.ServerShare.data) {
					return errors.New("failed to read extensionKeyShare")
				}
			}
		case extensionPreSharedKey:
			m.SelectedIdentityPresent = true
			if !extData.ReadUint16(&m.SelectedIdentity) {
				return errors.New("failed to read extensionPreSharedKey")
			}
		default:
			// Ignore unknown extensions.
			continue
		}

		if !extData.Empty() {
			return errors.New("failed to read extension data")
		}
	}

	return nil
}

func (ch ServerHello) String() string {

	str := fmt.Sprintln("Version:", ch.Vers)
	str += fmt.Sprintln("Random:", ch.Random)
	str += fmt.Sprintf("SessionId: %#v\n", ch.SessionID)
	str += fmt.Sprintf("CipherSuite (%d): %v\n", 1, ch.CipherSuite)
	str += fmt.Sprintf("CompressionMethod: %v\n", ch.CompressionMethod)
	str += fmt.Sprintln("NextProtoNeg:", ch.NextProtoNeg)
	str += fmt.Sprintf("NextProtos: %q\n", ch.NextProtos)
	str += fmt.Sprintf("OcspStapling: %#v\n", ch.OCSPStapling)
	str += fmt.Sprintf("Scts: %#v\n", ch.Scts)
	str += fmt.Sprintf("Ems: %#v\n", ch.Ems)
	str += fmt.Sprintf("TicketSupported: %v\n", ch.TicketSupported)
	str += fmt.Sprintf("SecureRenegotiation: %v\n", ch.SecureRenegotiation)
	str += fmt.Sprintf("SecureRenegotiationSupported: %v\n", ch.SecureRenegotiationSupported)
	str += fmt.Sprintf("AlpnProtocol: %v\n", ch.AlpnProtocol)
	str += fmt.Sprintf("Extensions: %v\n", ch.Extensions)
	str += fmt.Sprintf("SupportedVersion: %v\n", ch.SupportedVersion)
	str += fmt.Sprintf("ServerShare: %v\n", ch.ServerShare)
	str += fmt.Sprintf("SelectedIdentityPresent: %v\n", ch.SelectedIdentityPresent)
	str += fmt.Sprintf("SelectedIdentity: %v\n", ch.SelectedIdentity)
	str += fmt.Sprintf("Cookie: %v\n", ch.Cookie)
	str += fmt.Sprintf("SelectedGroup: %v\n", ch.SelectedGroup)

	return str
}

type ServerHelloBasic struct {
	Vers              uint16
	Random            []byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
	SelectedGroup     CurveID
	Extensions        []uint16
}

// Unmarshal only parses the fields needed for JA3 fingerprinting
// to avoids unnecessary allocations
func (m *ServerHelloBasic) Unmarshal(data []byte) error {

	if len(data) < 5+4 {
		return errors.New("server returned short message")
	}

	// buf contains a TLS record, with a 5 byte record header and a 4 byte
	// handshake header. The length of the ServerHello is taken from the
	// handshake header.
	serverHelloLen := int(data[6])<<16 | int(data[7])<<8 | int(data[8])

	if serverHelloLen >= len(data) {
		return errors.New("invalid serverHelloLen")
	}

	// prevent slice bounds out of range [:19] with capacity 11
	if len(data) < 9+serverHelloLen {
		return errors.New("invalid data length for server hello")
	}
	data = data[5 : 9+serverHelloLen]

	*m = ServerHelloBasic{}
	s := cryptobyte.String(data)

	if !s.Skip(4) || // message type and uint24 length field
		!s.ReadUint16(&m.Vers) || !s.ReadBytes(&m.Random, 32) ||
		!readUint8LengthPrefixed(&s, &m.SessionID) ||
		!s.ReadUint16(&m.CipherSuite) ||
		!s.ReadUint8(&m.CompressionMethod) {
		return errors.New("invalid message type")
	}

	if s.Empty() {
		// ServerHello is optionally followed by extension data
		return nil
	}

	var extensions cryptobyte.String
	if !s.ReadUint16LengthPrefixed(&extensions) || !s.Empty() {
		return errors.New("failed to read extensions")
	}

	for !extensions.Empty() {
		var extension uint16
		var extData cryptobyte.String
		if !extensions.ReadUint16(&extension) ||
			!extensions.ReadUint16LengthPrefixed(&extData) {
			return errors.New("failed to read extension data")
		}

		m.Extensions = append(m.Extensions, extension)
	}

	return nil
}

func (ch ServerHelloBasic) String() string {

	str := fmt.Sprintln("Version:", ch.Vers)
	str += fmt.Sprintln("Random:", ch.Random)
	str += fmt.Sprintf("SessionId: %#v\n", ch.SessionID)
	str += fmt.Sprintf("CipherSuite (%d): %v\n", 1, ch.CipherSuite)
	str += fmt.Sprintf("CompressionMethod: %v\n", ch.CompressionMethod)
	str += fmt.Sprintf("Extensions: %v\n", ch.Extensions)
	str += fmt.Sprintf("SelectedGroup: %v\n", ch.SelectedGroup)

	return str
}
