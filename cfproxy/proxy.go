package cfproxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
)

// HasHTTPProxy returns true if HTTP_PROXY or HTTPS_PROXY environment variables are set.
func HasHTTPProxy() bool {
	return getEnvAny("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy") != ""
}

// GetHTTPProxyURL returns the parsed proxy URL from environment variables, or nil if none is set.
// It checks HTTPS_PROXY first (since edge connections are TLS), then HTTP_PROXY.
func GetHTTPProxyURL() *url.URL {
	raw := getEnvAny("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil
	}
	return u
}

// DialThroughProxy establishes a TCP connection to the target address through an HTTP CONNECT proxy.
// The proxy handles DNS resolution of the target hostname.
// If proxyURL contains userinfo, a Proxy-Authorization header is sent.
func DialThroughProxy(ctx context.Context, proxyURL *url.URL, target string) (net.Conn, error) {
	proxyAddr := proxyURL.Host
	if proxyURL.Port() == "" {
		if proxyURL.Scheme == "https" {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(proxyURL.Hostname(), "80")
		}
	}

	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("proxy connection to %s failed: %w", proxyAddr, err)
	}

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if proxyURL.User != nil {
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", basicAuth(proxyURL.User))
	}
	connectReq += "\r\n"

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT write failed: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: "CONNECT"})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT response read failed: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("proxy CONNECT to %s failed: %s", target, resp.Status)
	}

	// If the bufio.Reader has buffered data beyond the CONNECT response,
	// we must return a connection that drains the buffer first. Otherwise
	// the TLS handshake (which reads from the raw conn) would miss those bytes.
	if br.Buffered() > 0 {
		return &bufferedConn{Conn: conn, br: br}, nil
	}

	return conn, nil
}

// bufferedConn wraps a net.Conn with a bufio.Reader that may contain
// bytes already read from the connection (e.g., after parsing an HTTP response).
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}

// H2 client connection preface per RFC 7540 Section 3.5.
var h2ClientPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// WrapH2ForProxy wraps a net.Conn so that http2.Server.ServeConn can operate
// through an HTTP proxy. The Cloudflare edge expects the remote side to send
// the HTTP/2 client connection preface when the connection arrives through a
// proxy. Without it, the edge returns "HTTP/1.1 400 Bad Request".
//
// This wrapper:
//   - On the first Write, prepends the H2 client preface (so the edge sees a
//     valid client).
//   - On the first Reads, returns an injected client preface (so ServeConn
//     believes the edge sent the preface as the H2 "client").
func WrapH2ForProxy(conn net.Conn) net.Conn {
	return &h2PrefaceConn{
		Conn:    conn,
		readBuf: bytes.NewReader(h2ClientPreface),
	}
}

type h2PrefaceConn struct {
	net.Conn
	writeOnce sync.Once
	readBuf   *bytes.Reader
}

func (c *h2PrefaceConn) Write(b []byte) (int, error) {
	var prefaceErr error
	c.writeOnce.Do(func() {
		_, prefaceErr = c.Conn.Write(h2ClientPreface)
	})
	if prefaceErr != nil {
		return 0, prefaceErr
	}
	return c.Conn.Write(b)
}

func (c *h2PrefaceConn) Read(b []byte) (int, error) {
	if c.readBuf.Len() > 0 {
		n, err := c.readBuf.Read(b)
		if err == io.EOF {
			err = nil
		}
		if n > 0 {
			return n, err
		}
	}
	return c.Conn.Read(b)
}

func basicAuth(user *url.Userinfo) string {
	username := user.Username()
	password, _ := user.Password()
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func getEnvAny(names ...string) string {
	for _, name := range names {
		if v := os.Getenv(name); v != "" {
			return v
		}
	}
	return ""
}
