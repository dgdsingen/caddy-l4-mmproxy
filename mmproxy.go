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

	// Read from `down` (the Connection), not the raw underlying conn, so any
	// bytes prefetched by upstream matchers are replayed correctly.
	var wg sync.WaitGroup
	wg.Add(2)
	go pipe(&wg, up, down) // client -> upstream
	go pipe(&wg, down, up) // upstream -> client
	wg.Wait()
	return nil
}

type closeWriter interface{ CloseWrite() error }

func pipe(wg *sync.WaitGroup, dst, src net.Conn) {
	defer wg.Done()
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(closeWriter); ok {
		_ = cw.CloseWrite() // half-close so the peer sees EOF
	}
}

// dialSpoofed opens a TCP connection to upstream whose source address is the
// client's IP:port. This requires IP_TRANSPARENT (CAP_NET_ADMIN) so the
// kernel allows binding a non-local address. Go's Dialer runs Control after
// socket() but before bind()/connect(), which is exactly the order needed:
// IP_TRANSPARENT must be set before the non-local bind.
func dialSpoofed(ctx context.Context, client *net.TCPAddr, upstream string) (net.Conn, error) {
	d := net.Dialer{
		LocalAddr: client, // bind the (non-local) client address as source
		Control: func(_, _ string, c syscall.RawConn) error {
			var soErr error
			ctrlErr := c.Control(func(fd uintptr) {
				if client.IP.To4() != nil {
					soErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				} else {
					soErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				}
				if soErr != nil {
					return
				}
				soErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
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
