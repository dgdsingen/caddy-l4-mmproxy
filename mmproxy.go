//go:build linux

// Package l4mmproxy는 Linux IP_TRANSPARENT를 사용해 원본 클라이언트 IP를 소켓
// 수준에서 보존하면서 TCP 커넥션을 loopback upstream으로 프록시하는 caddy-l4
// handler다.
//
// go-mmproxy(github.com/path-network/go-mmproxy)의 핵심 메커니즘을 Caddy 네이티브로
// 다시 구현한 것이다. PROXY-protocol 헤더를 읽지 못하는 백엔드, 특히 sshd를 위한
// 것으로, IP 기반 도구(예: sshguard)가 프록시 주소 대신 getpeername()으로 실제
// 클라이언트 주소를 보게 한다.
//
// 호스트 요구사항 (README 참고):
//   - Caddy 프로세스에 CAP_NET_ADMIN (IP_TRANSPARENT용).
//   - 백엔드의 응답(loopback 출발지, 비로컬 목적지)을 로컬 소켓으로 되돌리는
//     return-path 정책 라우팅.
//   - upstream은 반드시 loopback 주소여야 한다. 그렇지 않으면 응답의 출발지 주소가
//     라우팅 룰과 맞지 않아 커넥션이 절대 완료되지 않는다.
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

// Handler는 종단(terminal) layer4 handler다. 다운스트림 클라이언트의 IP:port를 소켓
// 출발지 주소로 사용해 upstream에 연결한다.
type Handler struct {
	// Upstream은 프록시할 백엔드 주소다. 예: "127.0.0.1:22".
	// return-path 라우팅이 동작하려면 반드시 loopback 주소여야 한다.
	Upstream string `json:"upstream,omitempty"`

	logger *zap.Logger
}

// CaddyModule은 Caddy 모듈 정보를 반환한다.
func (*Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "layer4.handlers.mmproxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

// Provision은 handler를 초기화한다.
func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger()
	return nil
}

// Validate는 설정이 올바른지 검사한다.
func (h *Handler) Validate() error {
	if h.Upstream == "" {
		return fmt.Errorf("upstream is required")
	}
	if _, _, err := net.SplitHostPort(h.Upstream); err != nil {
		return fmt.Errorf("invalid upstream %q: %w", h.Upstream, err)
	}
	return nil
}

// Handle은 커넥션을 프록시한다. 종단 handler이므로 next는 무시한다.
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

// copyToUpstream은 client -> upstream 방향을 중계한다.
//
// layer4 matcher가 미리 읽어둔 바이트는 down의 replay 버퍼에 있고 다른 무엇보다 먼저
// upstream에 도달해야 한다. 그래서 이 바이트를 먼저 flush한 뒤에야 raw 소켓을
// io.Copy에 넘기며, 그때부터 커널이 나머지를 splice로 옮긴다.
//
// io.MultiReader로 합쳐도 splice는 동작한다. multiReader.WriteTo가 서브 리더마다 다시
// 디스패치하므로 소켓이 net.TCPConn.ReadFrom에 도달하기 때문이다. 다만 커넥션마다
// 32KB 버퍼를 할당하는데 그 버퍼는 작은 prefetch 조각에만 쓰인다. 따로 flush하면 그
// 할당을 피할 수 있다.
func copyToUpstream(up net.Conn, down *layer4.Connection) {
	defer closeWrite(up)

	src := spliceableConn(down)
	if src == nil {
		// down.Read가 prefetch된 바이트를 스스로 replay하므로, 여기서 따로 flush하면
		// 두 번 전송된다.
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

// copyToDownstream은 upstream -> client 방향을 중계한다. 이 방향에는 버퍼링된 데이터가
// 없으므로 raw 소켓을 바로 쓸 수 있다.
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

// spliceableConn은 cx 뒤에 있는 raw TCP 소켓을 반환한다. cx가 그 외의 것(TLS 종단,
// packet conn, listener wrapper)을 감싸고 있으면 nil을 반환한다. cx를 우회해도 되는
// 것은 순수한 *net.TCPConn뿐이며, 다른 wrapper는 건너뛰면 안 되는 Read/Write 동작을
// 자체적으로 가지고 있다.
//
// cx를 우회하는 것이 커널 splice(2)를 쓰게 만드는 핵심이다. io.Copy는 오직
// net.TCPConn.ReadFrom을 통해서만 splice에 도달하는데, 그 타입 스위치는 *net.TCPConn은
// 받지만 *layer4.Connection은 받지 않는다. cx 자체도 자격이 없다. net.Conn을
// 인터페이스로 embed하기 때문에 안에 어떤 소켓이 들어 있든 ReadFrom도 WriteTo도
// 승격되지 않는다.
//
// 트레이드오프: cx.bytesRead / cx.bytesWritten이 더 이상 증가하지 않으므로 caddy-l4의
// debug 레벨 커넥션 통계에는 prefetch된 바이트만 잡힌다. 이 카운터는 그 로그 한 줄
// 외에는 쓰이지 않는다.
func spliceableConn(cx *layer4.Connection) *net.TCPConn {
	tc, _ := cx.Conn.(*net.TCPConn)
	return tc
}

type closeWriter interface{ CloseWrite() error }

// closeWrite는 write 쪽을 half-close하여 상대가 EOF를 보게 한다.
//
// layer4.Connection은 net.Conn을 인터페이스로 embed하므로 CloseWrite가 승격되지 않고,
// 직접 타입 단언하면 항상 실패한다. 먼저 벗겨내야 한다. 그러지 않으면 다운스트림
// 클라이언트가 FIN을 제때 받지 못한다.
func closeWrite(c net.Conn) {
	if cx, ok := c.(*layer4.Connection); ok {
		c = cx.Conn
	}
	if cw, ok := c.(closeWriter); ok {
		_ = cw.CloseWrite()
	}
}

// dialSpoofed는 출발지 주소가 클라이언트의 IP:port인 TCP 커넥션을 upstream으로 연다.
// 커널이 비로컬 주소 bind를 허용하려면 IP_TRANSPARENT(CAP_NET_ADMIN)가 필요하다. Go의
// Dialer는 socket() 이후 bind()/connect() 이전에 Control을 실행하는데, IP_TRANSPARENT는
// 비로컬 bind보다 먼저 설정되어야 하므로 정확히 필요한 순서다.
func dialSpoofed(ctx context.Context, client *net.TCPAddr, upstream string) (net.Conn, error) {
	// 출발지로 클라이언트 IP만 bind한다 (port는 충돌을 피하려고 제외)
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

// UnmarshalCaddyfile은 다음 형식을 파싱한다: mmproxy <upstream>
func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	d.Next() // 지시어 이름 소비
	if !d.Args(&h.Upstream) {
		return d.ArgErr()
	}
	if d.NextArg() {
		return d.ArgErr()
	}
	return nil
}

// 인터페이스 가드.
var (
	_ caddy.Provisioner     = (*Handler)(nil)
	_ caddy.Validator       = (*Handler)(nil)
	_ layer4.NextHandler    = (*Handler)(nil)
	_ caddyfile.Unmarshaler = (*Handler)(nil)
)
