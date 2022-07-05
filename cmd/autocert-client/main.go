package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

var (
	AutocertHost string
	LocalPort    int
	LocalHost    string
	Keys         string
)

func MakeRequest(wr io.Writer, buf *bufio.Reader, method string, arguments ...string) (string, error) {
	_, err := fmt.Fprintf(wr, "%v %v\n", method, strings.Join(arguments, " "))
	if err != nil {
		return "", err
	}

	resp, err := buf.ReadString('\n')
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(resp, "err: ") {
		errorText := strings.TrimPrefix(resp, "err: ")
		return "", fmt.Errorf("server error: %v", errorText)
	}

	resp = strings.TrimPrefix(resp, "ok: ")
	resp = strings.TrimSuffix(resp, "\n")
	return resp, nil
}

func ChallengeServer(l net.Listener, serverCfg *ssh.ServerConfig, challenge string) {
	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("could not accept a connection: %v\n", err)
			continue
		}

		sshConn, channels, requests, err := ssh.NewServerConn(conn, serverCfg)
		if err != nil {
			fmt.Printf("could not perform an SSH handshake: %v\n", err)
			continue
		}

		go ssh.DiscardRequests(requests)

		pendingChannel, ok := <-channels
		if !ok {
			sshConn.Close()
			fmt.Println("autocert closed connection before opening a channel")
			continue
		}

		if pendingChannel.ChannelType() != "session" {
			_ = pendingChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
			sshConn.Close()
			fmt.Println("autocert requested an unsupported channel type")
			continue
		}

		channel, requests, err := pendingChannel.Accept()

		_, _ = channel.Write([]byte(challenge))
		_ = sshConn.Close()
	}
}

func main() {
	flag.StringVar(&AutocertHost, "autocert", "", "host and port of autocert instance")
	flag.IntVar(&LocalPort, "port", 555, "local port that will be used for verification")
	flag.StringVar(&LocalHost, "host", "", "host that will be used for challenge validation")
	flag.StringVar(&Keys, "keys", "", "comma separated host keys to be signed")

	flag.Parse()

	if AutocertHost == "" {
		fmt.Println("-autocert is missing")
		os.Exit(1)
	}

	if LocalHost == "" {
		fmt.Println("-host is missing")
		os.Exit(1)
	}

	if Keys == "" {
		fmt.Println("-keys is missing")
		os.Exit(1)
	}

	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)
	authKey, _ := ssh.NewSignerFromKey(ed25519Key)

	keyPaths := strings.Split(Keys, ",")
	var keys []ssh.PublicKey
	for _, key := range keyPaths {
		data, err := os.ReadFile(key)
		if err != nil {
			fmt.Printf("cannot open key %q: %v\n", key, err)
			os.Exit(2)
		}

		splitKey := strings.Split(string(data), " ")
		if len(splitKey) < 2 {
			fmt.Printf("key %q is malformed\n", key)
			os.Exit(2)
		}

		keyData, err := base64.StdEncoding.DecodeString(splitKey[1])
		if err != nil {
			fmt.Printf("key %q is malformed\n", key)
			os.Exit(2)
		}

		key, err := ssh.ParsePublicKey(keyData)
		if err != nil {
			fmt.Printf("key %q is malformed: %v\n", key, err)
			os.Exit(2)
		}

		keys = append(keys, key)
	}

	client, err := ssh.Dial("tcp", AutocertHost, &ssh.ClientConfig{
		User: "autocert",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(authKey)},
		// TODO: retrieve key out of band through HTTPS
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         1 * time.Second,
	})
	if err != nil {
		fmt.Printf("cannot dial autocert: %v\n", err)
		os.Exit(3)
	}

	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		fmt.Printf("cannot open session: %v\n", err)
		os.Exit(3)
	}

	go ssh.DiscardRequests(requests)

	reader := bufio.NewReader(channel)

	challenge, err := MakeRequest(channel, reader, "challenge", LocalHost+":"+strconv.Itoa(LocalPort))
	if err != nil {
		fmt.Printf("could not generate challenge: %v\n", err)
		os.Exit(4)
	}

	l, err := net.Listen("tcp", ":"+strconv.Itoa(LocalPort)) //nolint:gosec
	if err != nil {
		fmt.Printf("cannot listen for new connections on %v: %v\n", LocalPort, err)
		os.Exit(5)
	}

	serverCfg := &ssh.ServerConfig{
		PasswordCallback: func(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if conn.User() != "autocert" {
				return nil, errors.New("user must be autocert")
			}

			if string(password) != "autocert" {
				return nil, errors.New("password must be autocert")
			}

			return &ssh.Permissions{}, nil
		},
	}
	serverCfg.AddHostKey(authKey)

	go ChallengeServer(l, serverCfg, challenge)

	resp, err := MakeRequest(channel, reader, "ready")
	if err != nil {
		fmt.Printf("challenge failed: %v\n", err)
		os.Exit(6)
	}

	fmt.Println(resp)

	var encodedKeys []string
	for _, key := range keys {
		encodedKeys = append(encodedKeys, base64.StdEncoding.EncodeToString(key.Marshal()))
	}

	certs, err := MakeRequest(channel, reader, "issue", encodedKeys...)
	if err != nil {
		fmt.Printf("could not issue certificates: %v\n", err)
		os.Exit(7)
	}

	splitCerts := strings.Fields(certs)
	for idx, cert := range splitCerts {
		data, err := base64.StdEncoding.DecodeString(cert)
		if err != nil {
			fmt.Printf("could not decode base64 from autocert: %v\n", err)
			os.Exit(8)
		}

		public, err := ssh.ParsePublicKey(data)
		if err != nil {
			fmt.Printf("could not parse certificate from autocert: %v\n", err)
			os.Exit(8)
		}

		cert, ok := public.(*ssh.Certificate)
		if !ok {
			fmt.Printf("autocert returned not a certificate\n")
			os.Exit(8)
		}

		certType := cert.Type()
		certData := certType + " " + base64.StdEncoding.EncodeToString(cert.Marshal()) + "\n"

		output := strings.TrimSuffix(path.Base(keyPaths[idx]), path.Ext(keyPaths[idx])) + "-cert.pub"
		err = os.WriteFile(path.Join(path.Dir(keyPaths[idx]), output), []byte(certData), 0600)
		if err != nil {
			fmt.Printf("could not write certificate file: %v\n", err)
			os.Exit(8)
		}
	}
}
