package main

import (
	//"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"

<<<<<<< Updated upstream
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
=======
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
>>>>>>> Stashed changes
	"github.com/dreadl0ck/tlsx"
)

func main() {

	var (
		flagInterface = flag.String("iface", "en0", "Network interface to capture on")
		flagPcap      = flag.String("pcap", "", "use pcap file")
		flagBPF       = flag.String("bpf", "tcp", "bpf filter")
	)

	flag.Parse()

	// redirect to stdout (log pkg logs to stderr by default)
	// to allow grepping the result through a simple pipe
	log.SetOutput(os.Stdout)

	var (
		handle *pcap.Handle
		err    error
	)

	if *flagPcap != "" {
		fmt.Println("Opening file", *flagPcap)
		handle, err = pcap.OpenOffline(*flagPcap)
	} else {
		fmt.Println("Listening on", *flagInterface)

		// snapLen = 1514 (1500 Ethernet MTU + 14 byte Ethernet Header)
		handle, err = pcap.OpenLive(*flagInterface, 1514, false, pcap.BlockForever)
	}
	if err != nil {
		log.Fatal(err)
	}

	// set bpf
	err = handle.SetBPFFilter(*flagBPF)
	if err != nil {
		log.Fatal(err)
	}

	// create packet source
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	var wg sync.WaitGroup

	// handle packets
	for packet := range packetSource.Packets() {
		wg.Add(1)
		go readPacket(packet, &wg)
	}

	wg.Wait()
}

func readPacket(packet gopacket.Packet, wg *sync.WaitGroup) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		// cast TCP layer
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			log.Println("Could not decode TCP layer")
			return
		}

		if tcp.SYN {
			// Connection setup
		} else if tcp.FIN {
			// Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			// Acknowledgement packet
		} else if tcp.RST {
			// Unexpected packet
		} else {
			// data packet

			// process TLS client hello
			clientHello := tlsx.GetClientHello(packet)
			if clientHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Client hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}

			// process TLS server hello
			serverHello := tlsx.GetServerHello(packet)
			if serverHello != nil {
				destination := "[" + packet.NetworkLayer().NetworkFlow().Dst().String() + ":" + packet.TransportLayer().TransportFlow().Dst().String() + "]"
				log.Printf("%s Server hello from port %s to %s", destination, tcp.SrcPort, tcp.DstPort)
			}
		}
	}
	wg.Done()
}
