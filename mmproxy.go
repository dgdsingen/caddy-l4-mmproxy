//go:build linux

// caddy-l4-mmproxy는 Linux의 IP_TRANSPARENT 소켓 옵션을 사용해 원본 client ip를
// 보존하면서 TCP 커넥션을 loopback upstream으로 reverse proxy 해준다.
// github.com/path-network/go-mmproxy 핵심 메커니즘을 Caddy 모듈로 재구현한 것이며
// proxy-protocol을 지원하지 않는 upstream(e.g. sshd)을 위한 것으로
// 정확한 client ip가 필요한 툴(e.g. sshguard)에 caddy 주소 대신 client ip를 전달함.
//
// 호스트 요구사항:
//   - Caddy에 CAP_NET_ADMIN 권한 부여 (for IP_TRANSPARENT)
//   - upstream의 응답 패킷(loopback src, non-local dst)을 로컬 소켓으로 라우팅하게 설정
//   - upstream은 반드시 loopback 주소여야 함.
//     그렇지 않으면 응답의 src가 라우팅 룰과 맞지 않아 커넥션이 성립하지 않음.
package l4mmproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
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

type Handler struct {
	// upstream address (e.g. 127.0.0.1:22)
	// return-path 라우팅이 동작하려면 반드시 loopback 주소여야 한다.
	Upstream string `json:"upstream,omitempty"`

	// Splice == true면 splice(2) 사용, nil || false면 userspace copy 사용
	Splice *bool `json:"splice,omitempty"`

	logger *zap.Logger
}

func (h *Handler) useSplice() bool {
	return h.Splice != nil && *h.Splice
}

func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.mmproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	h.logger.Info("mmproxy provisioned",
		zap.String("upstream", h.Upstream),
		zap.Bool("splice", h.useSplice()))
	return nil
}

func (h *Handler) Validate() error {
	if h.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if _, _, err := net.SplitHostPort(h.Upstream); err != nil {
		return fmt.Errorf("invalid upstream %q: %w", h.Upstream, err)
	}
	return nil
}

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

	useSplice := h.useSplice()
	var wg sync.WaitGroup
	wg.Go(func() {
		copyToUpstream(up, down, useSplice)
	})
	wg.Go(func() {
		copyToDownstream(down, up, useSplice)
	})
	wg.Wait()
	return nil
}

var bufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64<<10)
		return &buf
	},
}

// io.CopyBuffer(dst, src, buf) 호출시 dst.WriteTo || src.ReadFrom 하나라도 있으면
// buf를 무시하고 바로 해당 method를 호출해서 끝내버리므로 buf 할당은 낭비다.
// 아래 struct로 감싸면 강제로 dst.Write, src.Read 만 존재하게 되므로 buf를 무조건 타게 된다.
type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func userspaceCopy(dst io.Writer, src io.Reader) {
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	_, _ = io.CopyBuffer(writerOnly{dst}, readerOnly{src}, *buf)
}

// layer4 matcher가 미리 읽어둔 바이트는 down의 replay 버퍼에 있고 다른 무엇보다 먼저 upstream에 도달해야 한다.
// 그래서 이 바이트를 먼저 flush한 뒤에야 raw 소켓을 io.Copy에 넘기며, 그때부터 커널이 나머지를 splice로 옮긴다.
//
// splice 불가 시(useSplice=false이거나 내부 conn이 *net.TCPConn이 아닌 경우)
// userspaceCopy로 대체한다. down.Read가 prefetch된 바이트를 스스로 replay하므로
// 여기서 따로 flush하면 두 번 전송된다.
func copyToUpstream(up net.Conn, down *layer4.Connection, useSplice bool) {
	defer closeWrite(up)

	src := spliceableConn(down)
	if !useSplice || src == nil {
		userspaceCopy(up, down)
		return
	}

	if pending := down.MatchingBytes(); len(pending) > 0 {
		if _, err := up.Write(pending); err != nil {
			return
		}
	}
	_, _ = io.Copy(up, src)
}

// upstream > client 시에는 버퍼링된 데이터가 없으므로 raw 소켓을 바로 쓸 수 있다.
// useSplice=false면 wrapper를 유지해 userspace 경로로 복사한다.
func copyToDownstream(down *layer4.Connection, up net.Conn, useSplice bool) {
	dst := spliceableConn(down)
	if !useSplice || dst == nil {
		defer closeWrite(down)
		userspaceCopy(down, up)
		return
	}

	defer closeWrite(dst)
	_, _ = io.Copy(dst, up)
}

// spliceableConn은 cx 뒤에 있는 raw TCP 소켓을 반환한다.
// cx가 그 외의 것(TLS 종단, packet conn, listener wrapper)을 감싸고 있으면 nil을 반환한다.
// cx를 우회해도 되는 것은 순수한 *net.TCPConn뿐이며, 다른 wrapper는 건너뛰면 안 되는 Read/Write 동작을 자체적으로 가지고 있다.
//
// cx를 우회하는 것이 커널 splice(2)를 쓰게 만드는 핵심이다.
// io.Copy는 오직 net.TCPConn.ReadFrom을 통해서만 splice에 도달하는데, 그 타입 스위치는 *net.TCPConn은 받지만 *layer4.Connection은 받지 않는다.
// cx 자체도 자격이 없다. net.Conn을 인터페이스로 embed하기 때문에 안에 어떤 소켓이 들어 있든 ReadFrom도 WriteTo도 승격되지 않는다.
//
// trade-off: cx.bytesRead / cx.bytesWritten이 더 이상 증가하지 않으므로 caddy-l4의 debug 레벨 커넥션 통계에는 prefetch된 바이트만 잡힌다.
// 이 카운터는 그 로그 한 줄 외에는 쓰이지 않는다.
func spliceableConn(cx *layer4.Connection) *net.TCPConn {
	tc, _ := cx.Conn.(*net.TCPConn)
	return tc
}

type closeWriter interface{ CloseWrite() error }

// closeWrite는 write 쪽을 half-close하여 상대가 EOF를 보게 한다.
// layer4.Connection은 net.Conn을 인터페이스로 embed하므로 CloseWrite가 승격되지 않고, 직접 타입 단언하면 항상 실패한다.
// 먼저 벗겨내야 한다. 그러지 않으면 다운스트림 클라이언트가 FIN을 제때 받지 못한다.
func closeWrite(c net.Conn) {
	if cx, ok := c.(*layer4.Connection); ok {
		c = cx.Conn
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// dialSpoofed는 출발지 주소가 client ip:port인 TCP 커넥션을 upstream으로 연다.
// 커널이 비로컬 주소 bind를 허용하려면 IP_TRANSPARENT(CAP_NET_ADMIN)가 필요하다.
// Dialer는 socket() 이후 bind()/connect() 이전에 Control을 실행하는데
// IP_TRANSPARENT는 비로컬 bind보다 먼저 설정되어야 하므로 정확히 필요한 순서다.
func dialSpoofed(ctx context.Context, client *net.TCPAddr, upstream string) (net.Conn, error) {
	// client port는 그대로 사용시 os에서 충돌날 수 있으므로 client ip만 bind
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

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next()
	if !d.Args(&h.Upstream) {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	for nesting := d.Nesting(); d.NextBlock(nesting); {
		switch d.Val() {
		case "splice":
			var v string
			if !d.AllArgs(&v) {
				return d.ArgErr()
			}
			b, err := strconv.ParseBool(v)
			if err != nil {
				return d.Errf("invalid splice value %q: %v", v, err)
			}
			h.Splice = &b
		default:
			return d.Errf("unknown mmproxy option %q", d.Val())
		}
	}
	return nil
}

var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddy.Validator       = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
