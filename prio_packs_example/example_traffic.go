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
	"math/big"
	"os"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
)

const addr = "192.168.11.2:4242"

const message = "foobar"

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {

	// check that there is an argument
	if len(os.Args) != 2 {
		fmt.Println("Usage: go run example.go server|client")
		return
	}

	crypto_turnoff.CRYPTO_TURNED_OFF = true

	// check if the argument is "server" or "client"
	is_server := os.Args[1] == "server"
	is_client := os.Args[1] == "client"

	if is_server {
		err := echoServer()
		if err != nil {
			panic(err)
		}
	} else if is_client {
		err := clientMain()
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Println("Usage: go run example.go server|client")
		return
	}
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {

	listener, err := quic.ListenAddr(addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		return err
	}
	defer listener.Close()

	// Accept the incoming connection from the client
	conn, err := listener.Accept(context.Background())
	if err != nil {
		return err
	}

	// Accept the first stream opened by the client
	stream_high_prio, err := conn.AcceptStream(context.Background())
	if err != nil {
		panic(err)
	}
	defer stream_high_prio.Close()

	// Handle the first stream opened by the client
	// in a separate goroutine
	go ListenAndRepeat(stream_high_prio)

	// Accept the second stream opened by the client
	stream_low_prio, err2 := conn.AcceptStream(context.Background())
	if err2 != nil {
		panic(err2)
	}
	defer stream_low_prio.Close()

	// Handle the second stream opened by the client
	// in the current goroutine
	// Echo through the loggingWriter
	ListenAndRepeat(stream_low_prio)

	return nil
}

func ListenAndRepeat(stream quic.Stream) {
	fmt.Println("Echo up and running")
	for {
		// Read and echo the message
		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			panic(err)
		}
		fmt.Printf("	>>Server: Got '%s'\n	>>Server: Echoing on same stream\n", string(buf[:n]))
		_, err = stream.Write(buf)
		if err != nil {
			panic(err)
		}
	}

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

	// Open a new stream with high priority
	stream_high_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
	if err != nil {
		return err
	}
	defer stream_high_prio.Close()
	fmt.Printf("Prio of stream one (clientside): %d\n", stream_high_prio.Priority())

	// Open a new stream with low priority
	stream_low_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.LowPriority)
	if err != nil {
		return err
	}
	defer stream_low_prio.Close()
	fmt.Printf("Prio of stream two (clientside): %d\n", stream_low_prio.Priority())

	for {

		// Print info field for the user
		fmt.Println("What would you like to do?")
		fmt.Println("1: Send a message with high priority")
		fmt.Println("2: Send a message with low priority")
		fmt.Println("3: Quit")

		// Read the user's choice
		var choice int
		fmt.Scan(&choice)

		var stream quic.Stream

		// Check the user's choice
		switch choice {
		case 1:
			stream = stream_high_prio
		case 2:
			stream = stream_low_prio
		case 3:
			return nil
		default:
			fmt.Println("Invalid choice")
			continue
		}

		fmt.Printf("	>>Client: Sending '%s'\n", message)
		_, err := stream.Write([]byte(message))
		if err != nil {
			return err
		}

		buf := make([]byte, 1024)
		n, err := stream.Read(buf)
		if err != nil {
			return err
		}
		fmt.Printf("	>>Client: Got '%s'\n\n", buf[:n])

	}
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
