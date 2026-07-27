//go:build linux

package l4mmproxy

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
)

const testTimeout = 5 * time.Second

// tcpPair returns a connected pair of loopback TCP sockets. dialed is the
// client end, accepted is the server end; both are closed when the test ends.
func tcpPair(t *testing.T) (dialed, accepted *net.TCPConn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	accepts := make(chan result, 1)
	go func() {
		conn, err := ln.Accept()
		accepts <- result{conn, err}
	}()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	r := <-accepts
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}

	dialed = c.(*net.TCPConn)
	accepted = r.conn.(*net.TCPConn)
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = accepted.Close()
	})

	deadline := time.Now().Add(testTimeout)
	_ = dialed.SetDeadline(deadline)
	_ = accepted.SetDeadline(deadline)
	return dialed, accepted
}

// wrapPrefetched builds the Connection state a terminal handler sees when the
// matchers have already read prefetched bytes that nobody consumed.
func wrapPrefetched(conn net.Conn, prefetched string) *layer4.Connection {
	return layer4.WrapConnection(conn, []byte(prefetched), zap.NewNop())
}

// readAll reads until EOF, failing the test if the peer never half-closes.
func readAll(t *testing.T, r net.Conn) string {
	t.Helper()

	_ = r.SetReadDeadline(time.Now().Add(testTimeout))
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read to EOF: %v", err)
	}
	return string(b)
}

// runWithin fails the test if fn has not returned before testTimeout.
func runWithin(t *testing.T, name string, fn func()) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatalf("%s did not return within %s", name, testTimeout)
	}
}

func TestSpliceableConnAcceptsBareTCPSocket(t *testing.T) {
	_, accepted := tcpPair(t)

	if got := spliceableConn(wrapPrefetched(accepted, "")); got != accepted {
		t.Fatalf("spliceableConn = %v, want the underlying *net.TCPConn %v", got, accepted)
	}
}

func TestSpliceableConnRejectsNonTCPConn(t *testing.T) {
	p1, p2 := net.Pipe()
	t.Cleanup(func() {
		_ = p1.Close()
		_ = p2.Close()
	})

	if got := spliceableConn(wrapPrefetched(p2, "")); got != nil {
		t.Fatalf("spliceableConn = %v, want nil for a non-TCP conn", got)
	}
}

// closeWrite must reach through layer4.Connection, which embeds net.Conn as an
// interface and therefore does not promote CloseWrite.
func TestCloseWriteUnwrapsLayer4Connection(t *testing.T) {
	peer, accepted := tcpPair(t)

	closeWrite(wrapPrefetched(accepted, ""))

	if got := readAll(t, peer); got != "" {
		t.Fatalf("peer read %q, want EOF with no data", got)
	}
}

// Success path: prefetched bytes are flushed ahead of the live stream, exactly
// once, and the upstream sees a half-close when the client is done.
func TestCopyToUpstreamFlushesPrefetchedBytesThenSplices(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, upstream := tcpPair(t)

	down := wrapPrefetched(proxyDown, "PREFETCH")
	go copyToUpstream(proxyUp, down)

	if _, err := client.Write([]byte("LIVE")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatalf("client half-close: %v", err)
	}

	if got, want := readAll(t, upstream), "PREFETCHLIVE"; got != want {
		t.Fatalf("upstream received %q, want %q", got, want)
	}
}

// Fallback path: a downstream that is not a bare TCP socket must go through
// Connection.Read, which replays the prefetched bytes itself. Flushing them
// separately here would send them twice.
func TestCopyToUpstreamFallbackReplaysPrefetchedBytesOnce(t *testing.T) {
	clientPipe, downPipe := net.Pipe()
	t.Cleanup(func() {
		_ = clientPipe.Close()
		_ = downPipe.Close()
	})
	proxyUp, upstream := tcpPair(t)

	down := wrapPrefetched(downPipe, "PREFETCH")
	if spliceableConn(down) != nil {
		t.Fatal("test precondition: net.Pipe must not be spliceable")
	}
	go copyToUpstream(proxyUp, down)

	go func() {
		_, _ = clientPipe.Write([]byte("LIVE"))
		_ = clientPipe.Close()
	}()

	if got, want := readAll(t, upstream), "PREFETCHLIVE"; got != want {
		t.Fatalf("upstream received %q, want %q", got, want)
	}
}

// Failure path: the upstream socket is gone before the prefetched bytes can be
// flushed. The copy must give up instead of blocking on the downstream.
func TestCopyToUpstreamGivesUpWhenUpstreamIsClosed(t *testing.T) {
	_, proxyDown := tcpPair(t)
	proxyUp, upstream := tcpPair(t)

	_ = upstream.Close()
	_ = proxyUp.Close()

	down := wrapPrefetched(proxyDown, "PREFETCH")
	runWithin(t, "copyToUpstream", func() { copyToUpstream(proxyUp, down) })
}

// Success path for the reverse direction, including the half-close that lets
// the client see EOF without waiting for the whole handler to unwind.
func TestCopyToDownstreamRelaysAndHalfCloses(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, upstream := tcpPair(t)

	down := wrapPrefetched(proxyDown, "")
	go copyToDownstream(down, proxyUp)

	if _, err := upstream.Write([]byte("HELLO")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	if err := upstream.CloseWrite(); err != nil {
		t.Fatalf("upstream half-close: %v", err)
	}

	if got, want := readAll(t, client), "HELLO"; got != want {
		t.Fatalf("client received %q, want %q", got, want)
	}
}

// Failure path for the reverse direction: a dead downstream must not wedge the
// copy loop.
func TestCopyToDownstreamGivesUpWhenDownstreamIsClosed(t *testing.T) {
	client, proxyDown := tcpPair(t)
	proxyUp, upstream := tcpPair(t)

	_ = client.Close()
	_ = proxyDown.Close()

	go func() {
		_, _ = upstream.Write([]byte("HELLO"))
		_ = upstream.Close()
	}()

	down := wrapPrefetched(proxyDown, "")
	runWithin(t, "copyToDownstream", func() { copyToDownstream(down, proxyUp) })
}
