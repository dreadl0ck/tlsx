package tlsx

import (
<<<<<<< Updated upstream
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
=======
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
>>>>>>> Stashed changes
)

// GetServerHello returns a server hello message if the gopacket contains one
func GetServerHello(packet gopacket.Packet) *ServerHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		var (
			t, _  = tcpLayer.(*layers.TCP)
			hello = ServerHello{}
			err   = hello.Unmarshal(t.LayerPayload())
		)
		if err == nil {
			return &hello
		}
	}
	return nil
}

// GetServerHelloMinimal returns a server hello message if the gopacket contains one
// this variant only parses the fields necessary to generate a JA client hash
func GetServerHelloBasic(packet gopacket.Packet) *ServerHelloBasic {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		var (
			t, _  = tcpLayer.(*layers.TCP)
			hello = ServerHelloBasic{}
			err   = hello.Unmarshal(t.LayerPayload())
		)
		if err == nil {
			return &hello
		}
	}
	return nil
}

// GetClientHello returns a client hello message if the gopacket contains one
func GetClientHello(packet gopacket.Packet) *ClientHello {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		var (
			t, _  = tcpLayer.(*layers.TCP)
			hello = ClientHello{}
			err   = hello.Unmarshal(t.LayerPayload())
		)
		if err == nil {
			return &hello
		}
	}
	return nil
}

// GetClientHelloMinimal returns a client hello message if the gopacket contains one
// this variant only parses the fields necessary to generate a JA client hash
func GetClientHelloBasic(packet gopacket.Packet) *ClientHelloBasic {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		var (
			t, _  = tcpLayer.(*layers.TCP)
			hello = ClientHelloBasic{}
			err   = hello.Unmarshal(t.LayerPayload())
		)
		if err == nil {
			return &hello
		}
	}
	return nil
}
