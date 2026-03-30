package edgediscovery

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
)

// clearProxyEnv unsets all proxy env vars and returns a restore function.
func clearProxyEnv(t *testing.T) func() {
	t.Helper()
	keys := []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "NO_PROXY", "no_proxy"}
	saved := make(map[string]string)
	for _, k := range keys {
		saved[k] = os.Getenv(k)
		os.Unsetenv(k)
	}
	return func() {
		for _, k := range keys {
			os.Setenv(k, saved[k])
		}
	}
}

// generateTestTLSConfig creates a self-signed TLS certificate and returns
// server and client TLS configs.
func generateTestTLSConfig(t *testing.T) (serverTLS *tls.Config, clientTLS *tls.Config) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-edge"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:     []string{"localhost"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	require.NoError(t, err)

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(certPEM)

	serverTLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	clientTLS = &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
	}
	return serverTLS, clientTLS
}

// startMockEdgeServer starts a TLS listener that accepts a connection, completes
// the TLS handshake, and echoes data back. Returns the listener address.
func startMockEdgeServer(t *testing.T, serverTLS *tls.Config) net.Listener {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln
}

// startMockProxy starts an HTTP CONNECT proxy that forwards connections to the
// specified target address. Returns the proxy listener address.
func startMockProxy(t *testing.T, targetAddr string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				if req.Method != "CONNECT" {
					fmt.Fprintf(c, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
					return
				}
				// Connect to the real target (mock edge)
				target, err := net.Dial("tcp", targetAddr)
				if err != nil {
					fmt.Fprintf(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer target.Close()
				fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// Splice bytes in both directions
				go io.Copy(target, c)
				io.Copy(c, target)
			}(conn)
		}
	}()
	return ln
}

// startRejectingProxy starts a proxy that rejects all CONNECT requests.
func startRejectingProxy(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Read the request to avoid broken pipe on the client
				http.ReadRequest(bufio.NewReader(c))
				fmt.Fprintf(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
			}(conn)
		}
	}()
	return ln
}

func makeEdgeAddr(t *testing.T, addr string) *allregions.EdgeAddr {
	t.Helper()
	tcpAddr, err := net.ResolveTCPAddr("tcp", addr)
	require.NoError(t, err)
	return &allregions.EdgeAddr{
		TCP: tcpAddr,
	}
}

func TestDialEdge_Direct(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	serverTLS, clientTLS := generateTestTLSConfig(t)
	edgeLn := startMockEdgeServer(t, serverTLS)

	edgeAddr := makeEdgeAddr(t, edgeLn.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialEdge(ctx, 5*time.Second, clientTLS, edgeAddr, nil)
	require.NoError(t, err)
	defer conn.Close()

	// In direct mode, returned conn should be a *tls.Conn (not wrapped)
	_, isTLS := conn.(*tls.Conn)
	assert.True(t, isTLS, "direct mode should return *tls.Conn")

	// Verify data flows through
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

func TestDialEdge_Proxy(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	serverTLS, clientTLS := generateTestTLSConfig(t)
	edgeLn := startMockEdgeServer(t, serverTLS)
	proxyLn := startMockProxy(t, edgeLn.Addr().String())

	os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s", proxyLn.Addr().String()))

	// In proxy mode, edgeAddr needs Hostname set
	edgeAddr := makeEdgeAddr(t, edgeLn.Addr().String())
	edgeAddr.Hostname = edgeLn.Addr().String()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialEdge(ctx, 5*time.Second, clientTLS, edgeAddr, nil)
	require.NoError(t, err)
	defer conn.Close()

	// In proxy mode, the connection is tunneled through the proxy but returns
	// a standard *tls.Conn (same as direct mode).
	_, isTLS := conn.(*tls.Conn)
	assert.True(t, isTLS, "proxy mode should return *tls.Conn")

	// Verify data flows through the proxy tunnel
	_, err = conn.Write([]byte("ping"))
	require.NoError(t, err)

	buf := make([]byte, 4)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "ping", string(buf))
}

func TestDialEdge_ProxyNoHostname(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	serverTLS, clientTLS := generateTestTLSConfig(t)
	edgeLn := startMockEdgeServer(t, serverTLS)
	proxyLn := startMockProxy(t, edgeLn.Addr().String())

	os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s", proxyLn.Addr().String()))

	// Hostname empty -> falls back to direct mode even with proxy env set
	edgeAddr := makeEdgeAddr(t, edgeLn.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialEdge(ctx, 5*time.Second, clientTLS, edgeAddr, nil)
	require.NoError(t, err)
	defer conn.Close()

	// Should be direct mode (not wrapped)
	_, isTLS := conn.(*tls.Conn)
	assert.True(t, isTLS, "empty Hostname should fall back to direct mode")
}

func TestDialEdge_ProxyConnectFails(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	proxyLn := startRejectingProxy(t)
	os.Setenv("HTTPS_PROXY", fmt.Sprintf("http://%s", proxyLn.Addr().String()))

	edgeAddr := &allregions.EdgeAddr{
		TCP:      &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999},
		Hostname: "127.0.0.1:9999",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := DialEdge(ctx, 5*time.Second, &tls.Config{}, edgeAddr, nil)
	require.Error(t, err)

	// Should be a DialError wrapping the proxy failure
	var dialErr DialError
	assert.ErrorAs(t, err, &dialErr)
	assert.Contains(t, err.Error(), "403")
}
