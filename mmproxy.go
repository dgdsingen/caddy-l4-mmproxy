//go:build linux

// Package l4mmproxy implements a caddy-l4 handler that proxies TCP
// connections to a loopback upstream while preserving the original client
// IP at the socket level, using Linux IP_TRANSPARENT.
//
// This is a Caddy-native reimplementation of the core mechanism from
// go-mmproxy (github.com/path-network/go-mmproxy). It is intended for
// backends that cannot read a PROXY-protocol header — most notably sshd —
// so that IP-based tooling (e.g. sshguard) sees the real client address
// via getpeername() instead of the proxy's address.
//
// Requirements on the host (see README):
//   - CAP_NET_ADMIN on the Caddy process (for IP_TRANSPARENT).
//   - Return-path policy routing that redirects the backend's replies
//     (loopback source, non-local destination) back to the local socket.
//   - The upstream MUST be a loopback address, otherwise the reply's
//     source address will not match the routing rule and the connection
//     will never complete.
package l4mmproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/mholt/caddy-l4/layer4"
	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

func init() {
	caddy.RegisterModule(&Handler{})
}

// Handler is a terminal layer4 handler. It dials the upstream using the
// downstream client's IP:port as the socket source address.
type Handler struct {
	// Upstream is the backend address to proxy to, e.g. "127.0.0.1:22".
	// It MUST be a loopback address for the return-path routing to work.
	Upstream string `json:"upstream,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.mmproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision sets up the handler.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// Validate checks that the configuration is sane.
func (h *Handler) Validate() error {
	if h.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if _, _, err := net.SplitHostPort(h.Upstream); err != nil {
		return fmt.Errorf("invalid upstream %q: %w", h.Upstream, err)
	}
	return nil
}

// Handle proxies the connection. It is terminal and ignores next.
func (h *Handler) Handle(down *layer4.Connection, _ layer4.Handler) error {
	client, ok := down.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("mmproxy: remote addr is not TCP: %v", down.RemoteAddr())
	}

	up, err := dialSpoofed(down.Context, client, h.Upstream)
	if err != nil {
		h.logger.Error("dial upstream failed",
			zap.String("client", client.String()),
			zap.String("upstream", h.Upstream),
			zap.Error(err))
		return err
	}
	defer up.Close()

	var wg sync.WaitGroup
	wg.Go(func() {
		copyToUpstream(up, down)
	})
	wg.Go(func() {
		copyToDownstream(down, up)
	})
	wg.Wait()
	return nil
}

// copyToUpstream relays client -> upstream.
//
// Bytes prefetched by the layer4 matchers live in down's replay buffer and
// must reach the upstream before anything else, so they are flushed first and
// only then is the bare socket handed to io.Copy. Splitting it this way is
// what enables splice(2); wrapping both sources in an io.MultiReader would
// defeat it, because a MultiReader matches none of the types net's splice
// helper keys off.
func copyToUpstream(up net.Conn, down *layer4.Connection) {
	defer closeWrite(up)

	src := spliceableConn(down)
	if src == nil {
		// down.Read replays the prefetched bytes itself, so do not flush them
		// separately here or they would be sent twice.
		_, _ = io.Copy(up, down)
		return
	}

	if pending := down.MatchingBytes(); len(pending) > 0 {
		if _, err := up.Write(pending); err != nil {
			return
		}
	}
	_, _ = io.Copy(up, src)
}

// copyToDownstream relays upstream -> client. Nothing is buffered in this
// direction, so the bare socket can be used straight away.
func copyToDownstream(down *layer4.Connection, up net.Conn) {
	dst := spliceableConn(down)
	if dst == nil {
		defer closeWrite(down)
		_, _ = io.Copy(down, up)
		return
	}

	defer closeWrite(dst)
	_, _ = io.Copy(dst, up)
}

// spliceableConn returns the raw TCP socket behind cx, or nil when cx wraps
// anything else (TLS termination, a packet conn, a listener wrapper). Only a
// bare *net.TCPConn may bypass cx: any other wrapper owns Read/Write semantics
// that must not be skipped.
//
// Bypassing cx is what lets the kernel move bytes with splice(2). io.Copy
// reaches splice only through net.TCPConn.ReadFrom, whose type switch accepts
// a *net.TCPConn source but not a *layer4.Connection. cx cannot qualify on its
// own either: it embeds net.Conn as an interface, so it promotes neither
// ReadFrom nor WriteTo no matter what concrete socket is inside.
//
// Trade-off: cx.bytesRead / cx.bytesWritten stop advancing, so caddy-l4's
// debug-level connection stats report only the prefetched bytes. Those
// counters feed nothing but that one log line.
func spliceableConn(cx *layer4.Connection) *net.TCPConn {
	tc, _ := cx.Conn.(*net.TCPConn)
	return tc
}

type closeWriter interface{ CloseWrite() error }

// closeWrite half-closes the write side so the peer sees EOF.
//
// layer4.Connection embeds net.Conn as an interface, so CloseWrite is not
// promoted through it and a direct type assertion always fails. Unwrap first,
// otherwise the downstream client never gets an early FIN.
func closeWrite(c net.Conn) {
	if cx, ok := c.(*layer4.Connection); ok {
		c = cx.Conn
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// dialSpoofed opens a TCP connection to upstream whose source address is the
// client's IP:port. This requires IP_TRANSPARENT (CAP_NET_ADMIN) so the
// kernel allows binding a non-local address. Go's Dialer runs Control after
// socket() but before bind()/connect(), which is exactly the order needed:
// IP_TRANSPARENT must be set before the non-local bind.
func dialSpoofed(ctx context.Context, client *net.TCPAddr, upstream string) (net.Conn, error) {
	// bind the client ip as source (not port to avoid conflict)
	clientAddr := &net.TCPAddr{IP: client.IP, Port: 0}
	d := net.Dialer{
		LocalAddr: clientAddr,
		Control: func(_, _ string, c syscall.RawConn) error {
			var soErr error
			ctrlErr := c.Control(func(fd uintptr) {
				if client.IP.To4() != nil {
					soErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				} else {
					soErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				}
			})
			if ctrlErr != nil {
				return ctrlErr
			}
			return soErr
		},
	}
	return d.DialContext(ctx, "tcp", upstream)
}

// UnmarshalCaddyfile parses: mmproxy <upstream>
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // consume directive name
	if !d.Args(&h.Upstream) {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// Interface guards.
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddy.Validator       = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
