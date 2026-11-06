package honeydetect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
)

// Do not return parser/dial errors containing URLs: the URL may contain secrets.
func parseProbeProxy(raw string) (*url.URL, error) {
	if raw == "" {
		return nil, nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return nil, errors.New("行为验证的上游代理地址无效")
	}
	switch u.Scheme {
	case "http", "https", "socks5":
	default:
		return nil, errors.New("行为验证仅支持 HTTP、HTTPS 或 SOCKS5 上游代理")
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return nil, errors.New("行为验证的上游代理端口无效")
		}
	}
	return u, nil
}

type probeTunnelConn struct {
	net.Conn
	reader io.Reader
}

func (c *probeTunnelConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// Both plain HTTP and HTTPS targets use a tunnel to a numeric, locally checked
// IP. The original URL/Host and TLS server name remain intact in http.Transport.
// An upstream that forbids CONNECT to a target port fails closed.
func dialProbeProxy(ctx context.Context, u *url.URL, target string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080"}[u.Scheme]
	}
	addr := net.JoinHostPort(u.Hostname(), port)
	d := &net.Dialer{Timeout: 3 * time.Second}
	if u.Scheme == "socks5" {
		var auth *proxy.Auth
		if u.User != nil {
			password, _ := u.User.Password()
			auth = &proxy.Auth{User: u.User.Username(), Password: password}
		}
		p, err := proxy.SOCKS5("tcp", addr, auth, d)
		if err != nil {
			return nil, errors.New("无法建立 SOCKS5 上游连接")
		}
		cd, ok := p.(proxy.ContextDialer)
		if !ok {
			return nil, errors.New("SOCKS5 上游不支持有界连接")
		}
		conn, err := cd.DialContext(ctx, "tcp", target)
		if err != nil {
			return nil, errors.New("SOCKS5 上游连接失败")
		}
		return conn, nil
	}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, errors.New("上游代理连接失败")
	}
	succeeded := false
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer func() {
		stop()
		if !succeeded {
			conn.Close()
		}
	}()
	deadline, _ := ctx.Deadline()
	conn.SetDeadline(deadline)
	tunnel := conn
	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: u.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, errors.New("HTTPS 上游代理证书校验或握手失败")
		}
		tunnel = tlsConn
	}
	req := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target}, Host: target, Header: make(http.Header)}
	if u.User != nil {
		password, _ := u.User.Password()
		token := base64.StdEncoding.EncodeToString([]byte(u.User.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+token)
	}
	if err := req.Write(tunnel); err != nil {
		return nil, errors.New("上游代理隧道请求失败")
	}
	// Bound even a malicious proxy's response headers; preserve any prefetched
	// tunnel bytes without imposing the header limit on subsequent target traffic.
	br := bufio.NewReader(io.LimitReader(tunnel, 16*1024))
	resp, err := http.ReadResponse(br, req)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, errors.New("上游代理拒绝 CONNECT 或响应无效")
	}
	pending, _ := br.Peek(br.Buffered())
	reader := io.MultiReader(bytes.NewReader(bytes.Clone(pending)), tunnel)
	if !stop() || ctx.Err() != nil {
		return nil, errors.New("上游代理连接已取消")
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, errors.New("上游代理连接不可用")
	}
	succeeded = true
	return &probeTunnelConn{Conn: tunnel, reader: reader}, nil
}
