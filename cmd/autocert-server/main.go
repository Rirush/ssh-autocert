package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type Configuration struct {
	CASigner ssh.Signer
}

func GenerateAndSaveRSAKey(path string) ssh.Signer {
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 4096)
	rsaSSHKey, _ := ssh.NewSignerFromKey(rsaKey)
	bytes, _ := x509.MarshalPKCS8PrivateKey(rsaKey)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}), 0600)
	return rsaSSHKey
}

func GenerateAndSaveECDSAKey(path string) ssh.Signer {
	ecdsaKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdsaSSHKey, _ := ssh.NewSignerFromKey(ecdsaKey)
	bytes, _ := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}), 0600)
	return ecdsaSSHKey
}

func GenerateAndSaveEd25519Key(path string) ssh.Signer {
	_, ed25519Key, _ := ed25519.GenerateKey(rand.Reader)
	ed25519SSHKey, _ := ssh.NewSignerFromKey(ed25519Key)
	bytes, _ := x509.MarshalPKCS8PrivateKey(ed25519Key)
	_ = os.WriteFile(path, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: bytes,
	}), 0600)
	return ed25519SSHKey
}

func LoadKey(defaultPath string, fallback func(string) ssh.Signer) ssh.Signer {
	data, err := os.ReadFile(defaultPath)
	switch {
	case os.IsNotExist(err):
		return fallback(defaultPath)

	case err != nil:
		panic(err)
	}

	key, err := ssh.ParsePrivateKey(data)
	if err != nil {
		panic(err)
	}

	return key
}

func AcceptAllCallback(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"Provided-Key": key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal()),
		},
	}, nil
}

func AllowShell(reqs <-chan *ssh.Request) {
	for req := range reqs {
		if req.WantReply {
			_ = req.Reply(req.Type == "shell", nil)
		}
	}
}

func ExactArguments(length, want int, resp io.Writer) bool {
	if length == want {
		return true
	}

	_, _ = fmt.Fprintf(resp, "err: wanted %v arguments, got %v\n", want, length)
	return false
}

func AtMostArguments(length, want int, resp io.Writer) bool {
	if length <= want {
		return true
	}

	_, _ = fmt.Fprintf(resp, "err: wanted at most %v arguments, got %v\n", want, length)
	return false
}

type Handler func(*State, []string, io.Writer, *Configuration)

func QuitHandler(s *State, _ []string, _ io.Writer, _ *Configuration) {
	s.MustExit = true
}

var (
	alphabet     = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	alphabetSize = big.NewInt(int64(len(alphabet)))
)

var (
	MaxSerial = new(big.Int).SetUint64(^uint64(0))
)

const (
	ChallengeSize = 40

	ConnectionAttempts = 5
	ConnectionDelay    = 500 * time.Millisecond
	ReadTimeout        = 1 * time.Second

	CertificateLifetime = 90 * 24 * time.Hour // 90 days
)

func GenerateRandomString(length int) (string, error) {
	var out strings.Builder
	out.Grow(length)

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, alphabetSize)
		if err != nil {
			return "", err
		}

		out.WriteRune(alphabet[idx.Int64()])
	}

	return out.String(), nil
}

func ChallengeHandler(s *State, args []string, resp io.Writer, _ *Configuration) {
	if !ExactArguments(len(args), 1, resp) {
		return
	}

	host := args[0]
	parts := strings.Split(host, ":")
	if len(parts) != 2 {
		_, _ = fmt.Fprintln(resp, "err: host must be a pair of domain/ip and port separated by :")
		return
	}
	host, portStr := parts[0], parts[1]

	portNumber, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		_, _ = fmt.Fprintln(resp, "err: port must be a 16-bit number")
		return
	}

	if portNumber >= 1024 {
		_, _ = fmt.Fprintln(resp, "err: only privileged ports are allowed")
		return
	}

	// Not an IP, check if it's a valid domain
	if net.ParseIP(host) == nil {
		// Not a domain either - don't attempt to use it
		if _, err := net.ResolveIPAddr("ip", host); err != nil {
			_, _ = fmt.Fprintln(resp, "err: provided host is neither an IP address, nor a domain that resolves")
			return
		}
	}

	challenge, err := GenerateRandomString(ChallengeSize)
	if err != nil {
		_, _ = fmt.Fprintln(resp, "err: internal server error")
		return
	}

	s.CurrentChallenge = challenge
	s.Host = strings.ToLower(host)
	s.Port = portNumber
	_, _ = fmt.Fprintf(resp, "ok: %v\n", challenge)
}

func AttemptChallenge(host, challenge string) error {
	c := &ssh.ClientConfig{
		Timeout: ReadTimeout,
		User:    "autocert",
		// Authenticate with an empty password
		Auth: []ssh.AuthMethod{ssh.Password("autocert")},
		// Ignoring host key seems fine in this case
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
	}

	client, err := ssh.Dial("tcp", host, c)
	if err != nil {
		return err
	}

	channel, requests, err := client.OpenChannel("session", nil)
	if err != nil {
		return err
	}

	defer func(channel ssh.Channel) {
		_ = channel.Close()
	}(channel)

	go ssh.DiscardRequests(requests)

	result := make(chan []byte, 1)
	timeout := time.After(ReadTimeout)

	go func() {
		defer close(result)

		buf := make([]byte, ChallengeSize)
		_, err = channel.Read(buf)
		if err != nil {
			return
		}

		result <- buf
	}()

	select {
	case data := <-result:
		if subtle.ConstantTimeCompare([]byte(challenge), data) == 1 {
			return nil
		}

		return errors.New("challenge didn't match")
	case <-timeout:

		return errors.New("timeout")
	}
}

func ReadyHandler(s *State, _ []string, resp io.Writer, _ *Configuration) {
	if s.CurrentChallenge == "" {
		_, _ = fmt.Fprintln(resp, "err: challenge was not generated, call challenge first")
		return
	}

	success := false
	var lastErr error

	for i := 0; i < ConnectionAttempts; i++ {
		if i != 0 {
			time.Sleep(ConnectionDelay)
		}

		err := AttemptChallenge(s.Host+":"+strconv.Itoa(int(s.Port)), s.CurrentChallenge)
		if err != nil {
			lastErr = err
		} else {
			success = true
			break
		}
	}

	if !success {
		_, _ = fmt.Fprintf(resp, "err: %v\n", lastErr)
		return
	}

	s.CanIssue = true
	_, _ = fmt.Fprintf(resp, "ok: verified\n")
}

func FormatCertificates(resp io.Writer, certs []ssh.Certificate) {
	_, _ = fmt.Fprint(resp, "ok:")

	for _, cert := range certs {
		_, _ = fmt.Fprint(resp, " ", base64.StdEncoding.EncodeToString(cert.Marshal()))
	}

	_, _ = fmt.Fprint(resp, "\n")
}

func IssueHandler(s *State, args []string, resp io.Writer, appCfg *Configuration) {
	if !s.CanIssue {
		_, _ = fmt.Fprintln(resp, "err: challenge has not been passed yet")
		return
	}

	if !AtMostArguments(len(args), 4, resp) {
		return
	}

	serial, err := rand.Int(rand.Reader, MaxSerial)
	if err != nil {
		_, _ = fmt.Fprintln(resp, "err: internal server error")
		return
	}

	template := ssh.Certificate{
		Key:             nil,
		Serial:          serial.Uint64(),
		CertType:        ssh.HostCert,
		KeyId:           s.Host,
		ValidPrincipals: []string{s.Host},
		ValidAfter:      uint64(time.Now().Unix()),
		ValidBefore:     uint64(time.Now().Add(CertificateLifetime).Unix()),
	}

	signedCerts := make([]ssh.Certificate, 0, len(args))

	for idx, key := range args {
		data, err := base64.StdEncoding.DecodeString(key)
		if err != nil {
			_, _ = fmt.Fprintf(resp, "err: could not decode base64 on public key #%d\n", idx)
			return
		}

		publicKey, err := ssh.ParsePublicKey(data)
		if err != nil {
			_, _ = fmt.Fprintf(resp, "err: could not parse public key #%d\n", idx)
			return
		}

		cert := template
		cert.Key = publicKey

		err = cert.SignCert(rand.Reader, appCfg.CASigner)
		if err != nil {
			_, _ = fmt.Fprintln(resp, "err: internal server error")
			return
		}

		signedCerts = append(signedCerts, cert)
	}

	*s = State{}

	FormatCertificates(resp, signedCerts)
}

var Handlers = map[string]Handler{
	"quit":      QuitHandler,
	"challenge": ChallengeHandler,
	"ready":     ReadyHandler,
	"issue":     IssueHandler,
}

type State struct {
	CurrentChallenge string
	Host             string
	Port             uint64
	MustExit         bool
	CanIssue         bool
}

func ReadLine(reader *bufio.Reader) ([]string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	fields := strings.Fields(line)
	return fields, nil
}

func ChannelLoop(channel ssh.Channel, appCfg *Configuration) {
	state := &State{}
	reader := bufio.NewReader(channel)

	for {
		fields, err := ReadLine(reader)
		if err != nil {
			break
		}

		if len(fields) == 0 {
			_, err = fmt.Fprintln(channel, "err: empty line is not a valid command")
			if err != nil {
				break
			}

			continue
		}

		f, ok := Handlers[strings.ToLower(fields[0])]
		if !ok {
			_, err = fmt.Fprintf(channel, "err: unknown command %v\n", fields[0])
			if err != nil {
				break
			}

			continue
		}

		f(state, fields[1:], channel, appCfg)

		if state.MustExit {
			break
		}
	}
}

func ConnectionHandler(conn net.Conn, cfg *ssh.ServerConfig, appCfg *Configuration) {
	sshConn, channels, requests, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		fmt.Printf("could not perform an SSH handshake: %v\n", err)
		return
	}

	defer func(sshConn *ssh.ServerConn) {
		_ = sshConn.Close()
	}(sshConn)

	go ssh.DiscardRequests(requests)

	pendingChannel, ok := <-channels
	if !ok {
		return
	}

	if pendingChannel.ChannelType() != "session" {
		fmt.Println("unsupported channel type")
		_ = pendingChannel.Reject(ssh.UnknownChannelType, "unsupported channel type")
		return
	}

	channel, requests, err := pendingChannel.Accept()
	switch {
	case errors.Is(err, io.EOF):
		return

	case err != nil:
		fmt.Printf("could not accept a channel: %v\n", err)
		return
	}

	go AllowShell(requests)

	ChannelLoop(channel, appCfg)
}

func main() {
	// TODO: get listen address from configuration
	l, err := net.Listen("tcp", ":777") //nolint:gosec
	if err != nil {
		fmt.Printf("cannot listen for new connections on :777: %v\n", err)
		os.Exit(1)
	}

	rsaKey := LoadKey("host_key_rsa", GenerateAndSaveRSAKey)
	ecdsaKey := LoadKey("host_key_ecdsa", GenerateAndSaveECDSAKey)
	ed25519Key := LoadKey("host_key_ed25519", GenerateAndSaveEd25519Key)

	authority := LoadKey("authority_ed25519", GenerateAndSaveEd25519Key)

	appCfg := Configuration{
		CASigner: authority,
	}

	cfg := ssh.ServerConfig{
		PublicKeyCallback: AcceptAllCallback,
	}

	cfg.AddHostKey(rsaKey)
	cfg.AddHostKey(ecdsaKey)
	cfg.AddHostKey(ed25519Key)

	for {
		conn, err := l.Accept()
		if err != nil {
			fmt.Printf("could not accept a connection: %v\n", err)
			continue
		}

		go ConnectionHandler(conn, &cfg, &appCfg)
	}
}
