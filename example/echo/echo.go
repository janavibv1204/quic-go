package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"strings"

	quic "github.com/lucas-clemente/quic-go"
)

const addr = "10.113.49.130:4242"

const message = "hello"
const message2 = "hello Janavi"

var length int

// We start a server listening on an address,
// then connect with a client, send the message, and wait for its receipt.
func main() {
	flagMode := flag.String("mode", "server", "start in client or server mode")
	flag.Parse()
	if strings.ToLower(*flagMode) == "server" {
		fmt.Printf("SERVER MODE \n")
		err := echoServer()
		if err != nil {
			panic(err)
		}
	} else {
		fmt.Printf("CLIENT MODE\n")
		err := clientMain()
		if err != nil {
			panic(err)
		}
	}

}

// Start a server that listens on an address and accepts data from the client
func echoServer() error {
	listener, err := quic.ListenAddr(addr, generateTLSConfig(), nil) //self-signed pem file
	if err != nil {
		return err
	} else {
		fmt.Printf("echoServer() listening....\n")
	}
	sess, err := listener.Accept(context.Background()) //returns a new session/connection
	if err != nil {
		return err
	} else {
		fmt.Printf("echoServer() accepted connection....\n")
	}

	stream, err := sess.AcceptStream(context.Background()) // returns a new stream
	if err != nil {
		panic(err)
	} else {
		fmt.Printf("echoServer() session accepted stream....\n")
	}

	buf := make([]byte, len(message))
	length, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	if length > 0 {
		fmt.Printf("Server: Got '%s'\n", buf)

		fmt.Printf("Server: Sending '%s'\n", message2)
		_, err = stream.Write([]byte(message2))
		if err != nil {
			return err
		}
	}

	return err
}

func clientMain() error {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // InsecureSkipVerify controls whether a client verifies the
		// server's certificate chain and host name.
		// If InsecureSkipVerify is true, TLS accepts any certificate
		// presented by the server and any host name in that certificate.
		// In this mode, TLS is susceptible to man-in-the-middle attacks.
		// This should be used only for testing.

		NextProtos: []string{"quic-echo-example"}, // NextProtos is a list of supported application level protocols, in
		// order of preference.

	}
	session, err := quic.DialAddr(addr, tlsConf, nil) //establish a new QUIC connection to the server
	if err != nil {
		return err
	} else {
		fmt.Printf("clientMain() Dialing Addr...\n")
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		return err
	} else {
		fmt.Printf("clientMain() Opening bidirectional stream for sync...\n")
	}

	fmt.Printf("Client: Sending '%s'\n", message)
	_, err = stream.Write([]byte(message))
	if err != nil {
		return err
	} else {
		fmt.Printf("Client : Sent message..\n")
	}

	buf := make([]byte, len(message2))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	return nil
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {

	certPEM, err := ioutil.ReadFile("/home/janavibv/mygo/cert.pem")
	if err != nil {
		fmt.Printf("Error Reading cert File\n")
	} else {
		fmt.Printf("Reading cert File..... OK\n")
	}
	keyPEM, err := ioutil.ReadFile("/home/janavibv/mygo/key.pem")
	if err != nil {
		fmt.Printf("Error Reading key File\n")
	} else {
		fmt.Printf("Reading key File..... OK\n")
	}
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	} else {
		fmt.Printf("KeyPair OK \n")
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert}, // Certificates contains one or more certificate chains to present to
		// the other side of the connection. Server configurations must include
		// at least one certificate or else set GetCertificate. Clients doing
		// client-authentication may set either Certificates or
		// GetClientCertificate.

		NextProtos: []string{"quic-echo-example"},
	}
}

// LoadCertficateAndKeyFromFile reads file, divides into key and certificates  (https://gist.github.com/ukautz/cd118e298bbd8f0a88fc)

