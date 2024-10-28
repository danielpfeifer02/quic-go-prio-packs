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
	"time"

	"github.com/danielpfeifer02/quic-go-prio-packs"
	"github.com/danielpfeifer02/quic-go-prio-packs/crypto_turnoff"
	"github.com/danielpfeifer02/quic-go-prio-packs/priority_setting"
	"github.com/danielpfeifer02/quic-go-prio-packs/qlog"
)

const server_addr = "192.168.11.2:4242"

const message = "foobar"

const NUM_MESSAGES = 3

var PRIO = priority_setting.NoPriority
var PRIO_S = priority_setting.HighPriority
var PRIO_C = priority_setting.LowPriority

// We start a server echoing data on the first stream the client opens,
// then connect with a client, send the message, and wait for its receipt.
func main() {

	// expect one argument: "server" or "client"
	if len(os.Args) != 2 {
		//fmt.Println("Usage: go run example.go server|client")
		return
	}

	is_server := os.Args[1] == "server"
	is_client := os.Args[1] == "client"

	os.Remove("tls.keylog")
	crypto_turnoff.CRYPTO_TURNED_OFF = true

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
		//fmt.Println("Usage: go run example.go server|client")
	}

	time.Sleep(100 * time.Millisecond)
}

// Start a server that echos all data on the first stream opened by the client
func echoServer() error {

	listener, err := quic.ListenAddr(server_addr, generateTLSConfig(), generateQUICConfig())
	if err != nil {
		panic(err)
	}
	defer listener.Close()

	// Accept the incoming connection from the client
	conn, err := listener.Accept(context.Background())
	if err != nil {
		panic(err)
	}

	for i := 1; i <= NUM_MESSAGES; i++ {

		data, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		//fmt.Printf("	>>Server: Got '%s'\n", string(data))
		err = conn.SendDatagramWithPriority([]byte(data), PRIO_S)
		// err = conn.SendDatagram([]byte(data))
		if err != nil {
			return err
		}

	}

	time.Sleep(100 * time.Millisecond)

	return nil
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}
	conn, err := quic.DialAddr(context.Background(), server_addr, tlsConf, generateQUICConfig())
	if err != nil {
		return err
	}
	defer conn.CloseWithError(0, "")

	// Open a new stream
	// stream_prio, err := conn.OpenStreamSyncWithPriority(context.Background(), priority_setting.HighPriority)
	// if err != nil {
	// 	return err
	// }
	// defer stream_prio.Close()

	for i := 1; i <= NUM_MESSAGES; i++ {

		//fmt.Printf("	>>Client: Sending '%s%d'\n", message, i)

		err := conn.SendDatagramWithPriority([]byte(message+fmt.Sprintf("%d", i)), PRIO_C)
		// err := conn.SendDatagram([]byte(message + fmt.Sprintf("%d", i)))
		if err != nil {
			return err
		}
		buf, err := conn.ReceiveDatagram(context.Background())
		if err != nil {
			return err
		}
		//fmt.Printf("	>>Client: Got '%s'\n\n", buf)

	}

	time.Sleep(100 * time.Millisecond)

	return nil
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
	return &quic.Config{
		Tracer:          qlog.DefaultTracer,
		EnableDatagrams: true,
	}
}
