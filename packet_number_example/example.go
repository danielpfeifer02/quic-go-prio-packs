package main

// https://fossies.org/linux/quic-go/example/echo/echo.go
// if error:
// sudo sysctl -w net.core.rmem_max=2500000
// sudo sysctl -w net.core.wmem_max=2500000

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/packet_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

const addr = "localhost:4242"

const message = "foobar"

const NUM_MESSAGES = 3

var counter int = 0
var liste = make([]int, 0)

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {

	os.Remove("tls.keylog")

	go func() { log.Fatal(echoServer()) }()

	err := clientMain()
	if err != nil {
		panic(err)
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {

	crypto_turnoff.CRYPTO_TURNED_OFF = false
	packet_setting.ALLOW_SETTING_PN = true
	packet_setting.ConnectionInitiationBPFHandler = initiationBPFHandler
	packet_setting.ConnectionRetirementBPFHandler = retirementBPFHandler

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	// Accept the incoming connection from the client
	conn, err := listener.Accept(context.Background())
	if err != nil {
		panic(err)
	}

	stream, err := conn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream.Close()

	pn_multiplier := 0x42

	for i := 1; i <= NUM_MESSAGES; i++ {

		buf := make([]byte, len(message)+1)

		_, err = io.ReadFull(stream, buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("	>>Server: Got '%s'\n	>>Server: Echoing on same stream\n", string(buf))
		_, err = stream.Write(buf)
		if err != nil {
			panic(err)
		}

		conn.SetPacketNumber(int64(i * pn_multiplier))
		conn.SetHighestSent(int64(i * pn_multiplier))

	}

	return nil
}

func initiationBPFHandler(id []byte, l uint8) {
	fmt.Println("new", len(id))
	// fmt.Println("Initiation BPF Handler called")
	// liste = append(liste, counter)
	// fmt.Printf("Adding %d to the list\n", counter)
	// counter++
}

func retirementBPFHandler(id []byte, l uint8) {
	fmt.Println("old", len(id))
	// fmt.Println("Retirement BPF Handler called")
	// fmt.Printf("Removing %d from the list\n", liste[0])
	// liste = liste[1:]
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	conn, err := quic.DialAddr(context.Background(), addr, tlsConf, generateQUICConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	// Open a new stream
	stream_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
	if err != nil {
		return err
	}
	defer stream_prio.Close()

	for i := 1; i <= NUM_MESSAGES; i++ {

		fmt.Printf("	>>Client: Sending '%s%d'\n", message, i)
		_, err = stream_prio.Write([]byte(message + fmt.Sprintf("%d", i)))
		if err != nil {
			return err
		}

		buf := make([]byte, len(message)+1)
		_, err = io.ReadFull(stream_prio, buf)
		if err != nil {
			return err
		}
		fmt.Printf("	>>Client: Got '%s'\n\n", buf)

	}

	return nil
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("	>>Server: Got '%s'\n	>>Server: Echoing on same stream\n", string(b))
	return w.Writer.Write(b)
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}

	// Create a KeyLogWriter
	keyLogFile, err := os.OpenFile("tls.keylog", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		panic(err)
	}
	// defer keyLogFile.Close() // TODO why not close?

	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
		KeyLogWriter: keyLogFile,
		CipherSuites: []uint16{tls.TLS_CHACHA20_POLY1305_SHA256},
	}
}

func generateQUICConfig() *quic.Config {
	return &quic.Config{}
}
