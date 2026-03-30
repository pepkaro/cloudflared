package cfproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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

func TestHasHTTPProxy(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	assert.False(t, HasHTTPProxy(), "should be false with no proxy env vars")

	os.Setenv("HTTP_PROXY", "http://proxy:8080")
	assert.True(t, HasHTTPProxy(), "should be true with HTTP_PROXY set")
	os.Unsetenv("HTTP_PROXY")

	os.Setenv("https_proxy", "http://proxy:8080")
	assert.True(t, HasHTTPProxy(), "should be true with https_proxy (lowercase) set")
	os.Unsetenv("https_proxy")
}

func TestGetHTTPProxyURL(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	assert.Nil(t, GetHTTPProxyURL(), "should be nil with no proxy env vars")

	os.Setenv("HTTPS_PROXY", "http://user:pass@proxy.example.com:8080")
	u := GetHTTPProxyURL()
	require.NotNil(t, u)
	assert.Equal(t, "proxy.example.com", u.Hostname())
	assert.Equal(t, "8080", u.Port())
	assert.Equal(t, "user", u.User.Username())
	pw, ok := u.User.Password()
	assert.True(t, ok)
	assert.Equal(t, "pass", pw)
	os.Unsetenv("HTTPS_PROXY")

	// HTTPS_PROXY takes precedence over HTTP_PROXY
	os.Setenv("HTTPS_PROXY", "http://https-proxy:443")
	os.Setenv("HTTP_PROXY", "http://http-proxy:80")
	u = GetHTTPProxyURL()
	require.NotNil(t, u)
	assert.Equal(t, "https-proxy", u.Hostname())
	os.Unsetenv("HTTPS_PROXY")
	os.Unsetenv("HTTP_PROXY")
}

func TestGetHTTPProxyURLInvalidURL(t *testing.T) {
	restore := clearProxyEnv(t)
	defer restore()

	os.Setenv("HTTP_PROXY", "://not-a-valid-url")
	assert.Nil(t, GetHTTPProxyURL(), "should return nil for invalid URL")
	os.Unsetenv("HTTP_PROXY")
}

func TestDialThroughProxy(t *testing.T) {
	// Start a mock proxy server that handles CONNECT
	var receivedMethod string
	var receivedHost string
	var receivedAuth string

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufioReader(c))
				if err != nil {
					return
				}
				receivedMethod = req.Method
				receivedHost = req.Host
				receivedAuth = req.Header.Get("Proxy-Authorization")
				fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				// Echo back whatever the client sends after CONNECT
				buf := make([]byte, 1024)
				n, _ := c.Read(buf)
				if n > 0 {
					c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("http://testuser:testpass@%s", proxyListener.Addr().String()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialThroughProxy(ctx, proxyURL, "target.example.com:443")
	require.NoError(t, err)
	defer conn.Close()

	assert.Equal(t, "CONNECT", receivedMethod)
	assert.Equal(t, "target.example.com:443", receivedHost)
	assert.NotEmpty(t, receivedAuth, "should have Proxy-Authorization header")
	assert.True(t, strings.HasPrefix(receivedAuth, "Basic "), "auth should be Basic scheme")

	// Verify the connection works (echo test)
	_, err = conn.Write([]byte("hello"))
	require.NoError(t, err)

	buf := make([]byte, 5)
	_, err = io.ReadFull(conn, buf)
	require.NoError(t, err)
	assert.Equal(t, "hello", string(buf))
}

func TestDialThroughProxyNoAuth(t *testing.T) {
	var receivedAuth string

	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer proxyListener.Close()

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				req, err := http.ReadRequest(bufioReader(c))
				if err != nil {
					return
				}
				receivedAuth = req.Header.Get("Proxy-Authorization")
				fmt.Fprintf(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
			}(conn)
		}
	}()

	proxyURL, err := url.Parse(fmt.Sprintf("http://%s", proxyListener.Addr().String()))
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := DialThroughProxy(ctx, proxyURL, "target.example.com:443")
	require.NoError(t, err)
	conn.Close()

	assert.Empty(t, receivedAuth, "should NOT have Proxy-Authorization header when no userinfo")
}

func TestDialThroughProxyRejectsConnection(t *testing.T) {
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer proxyServer.Close()

	proxyURL, err := url.Parse(proxyServer.URL)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = DialThroughProxy(ctx, proxyURL, "target.example.com:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "403")
}

func TestDialThroughProxyUnreachable(t *testing.T) {
	proxyURL, err := url.Parse("http://192.0.2.1:1") // RFC 5737 TEST-NET, unreachable
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	_, err = DialThroughProxy(ctx, proxyURL, "target.example.com:443")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "proxy connection")
}

func bufioReader(r io.Reader) *bufio.Reader {
	return bufio.NewReader(r)
}
