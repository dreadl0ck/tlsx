# Introduction

[![GoDoc](https://godoc.org/github.com/dreadl0ck/tlsx?status.svg)](https://godoc.org/github.com/dreadl0ck/tlsx)

This is a fork of the [bradleyfalzon/tlsx](https://github.com/bradleyfalzon/tlsx) package,
that was updated to store TLS extensions in the client hello message in the order they were encountered during parsing.
It was further extended with unit tests, benchmarks and parsing code to extract the TLS server hello message.

This package is used to create JA3 hashes, for fingerprinting TLS client and server hellos in [dreadl0ck/ja3](https://github.com/dreadl0ck/ja3)
Since not all values produced by parsing the hello messages are required to calculate the fingerprint,
two variations of the data structures are provided for both client and server: *XXXHello()* and *XXXHelloBasic()*.
The basic datatype contains less fields and does less parsing, which makes it faster and causes less allocations.

## API

    package tlsx // import "github.com/dreadl0ck/tlsx"
    
    const SNINameTypeDNS uint8 = 0 ...
    const ClientHelloRandomLen = 32
    const ServerHelloRandomLen = 32
    var ErrHandshakeWrongType = errors.New("handshake is of wrong type, or not a handshake message") ...
    var CipherSuiteReg = map[CipherSuite]string{ ... }
    var ExtensionReg = map[Extension]string{ ... }
    var VersionReg = map[Version]string{ ... }
    type CipherSuite uint16
    type ClientHello struct{ ... }
        func GetClientHello(packet gopacket.Packet) *ClientHello
    type ClientHelloBasic struct{ ... }
        func GetClientHelloBasic(packet gopacket.Packet) *ClientHelloBasic
    type CurveID uint16
    type Extension uint16
        const ExtServerName Extension = 0 ...
    type ServerHello struct{ ... }
        func GetServerHello(packet gopacket.Packet) *ServerHello
    type ServerHelloBasic struct{ ... }
        func GetServerHelloBasic(packet gopacket.Packet) *ServerHelloBasic
    type TLSMessage struct{ ... }
    type Version uint16
        const VerSSL30 Version = 0x300 ...

## Tests and Benchmarks

    $ go test -v -bench=.
    === RUN   TestClientHello
    --- PASS: TestClientHello (0.00s)
    === RUN   TestClientHelloBasic
    --- PASS: TestClientHelloBasic (0.00s)
    === RUN   TestServerHello
    --- PASS: TestServerHello (0.00s)
    === RUN   TestGetServerHelloBasic
    --- PASS: TestGetServerHelloBasic (0.00s)
    goos: darwin
    goarch: amd64
    pkg: github.com/dreadl0ck/tlsx
    BenchmarkGetClientHello
    BenchmarkGetClientHello-12         	 1000000	      1090 ns/op	     656 B/op	      16 allocs/op
    BenchmarkGetClientHelloBasic
    BenchmarkGetClientHelloBasic-12    	 2621624	       451 ns/op	     312 B/op	       8 allocs/op
    BenchmarkGetServerHello
    BenchmarkGetServerHello-12         	 3543003	       348 ns/op	     304 B/op	       3 allocs/op
    BenchmarkGetServerHelloBasic
    BenchmarkGetServerHelloBasic-12    	 5287196	       223 ns/op	     104 B/op	       2 allocs/op
    PASS
    ok  	github.com/dreadl0ck/tlsx	5.834s