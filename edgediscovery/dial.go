package edgediscovery

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/pkg/errors"

	"github.com/cloudflare/cloudflared/cfproxy"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
)

// DialEdge makes a TLS connection to a Cloudflare edge node.
// When an HTTP proxy is configured and edgeAddr.Hostname is set, the connection
// is tunneled through the proxy via HTTP CONNECT. Otherwise, a direct TCP
// connection is made (original behavior).
func DialEdge(
	ctx context.Context,
	timeout time.Duration,
	tlsConfig *tls.Config,
	edgeAddr *allregions.EdgeAddr,
	localIP net.IP,
) (net.Conn, error) {
	// Inherit from parent context so we can cancel (Ctrl-C) while dialing
	dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
	defer dialCancel()

	var edgeConn net.Conn
	var err error

	isProxy := false
	if proxyURL := cfproxy.GetHTTPProxyURL(); proxyURL != nil && edgeAddr.Hostname != "" {
		// Proxy mode: tunnel through HTTP CONNECT. The proxy resolves the hostname.
		edgeConn, err = cfproxy.DialThroughProxy(dialCtx, proxyURL, edgeAddr.Hostname)
		if err != nil {
			return nil, newDialError(err, "proxy CONNECT to edge error")
		}
		isProxy = true
	} else {
		// Direct mode: original behavior
		dialer := net.Dialer{}
		if localIP != nil {
			dialer.LocalAddr = &net.TCPAddr{IP: localIP, Port: 0}
		}
		edgeConn, err = dialer.DialContext(dialCtx, "tcp", edgeAddr.TCP.String())
		if err != nil {
			return nil, newDialError(err, "DialContext error")
		}
	}

	tlsEdgeConn := tls.Client(edgeConn, tlsConfig)
	tlsEdgeConn.SetDeadline(time.Now().Add(timeout))

	if err = tlsEdgeConn.Handshake(); err != nil {
		return nil, newDialError(err, "TLS handshake with edge error")
	}
	// clear the deadline on the conn; http2 has its own timeouts
	tlsEdgeConn.SetDeadline(time.Time{})

	if isProxy {
		// The Cloudflare edge expects the HTTP/2 client connection preface when
		// connecting through a proxy. WrapH2ForProxy handles this transparently
		// so that http2.Server.ServeConn still works correctly.
		return cfproxy.WrapH2ForProxy(tlsEdgeConn), nil
	}
	return tlsEdgeConn, nil
}

// DialError is an error returned from DialEdge
type DialError struct {
	cause error
}

func newDialError(err error, message string) error {
	return DialError{cause: errors.Wrap(err, message)}
}

func (e DialError) Error() string {
	return e.cause.Error()
}

func (e DialError) Cause() error {
	return e.cause
}
