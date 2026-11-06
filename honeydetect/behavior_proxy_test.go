package honeydetect

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const probeTestIP = "192.0.2.10"

func proxyTestTarget(t *testing.T, secure bool, hits *atomic.Int32) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Proxy-Authorization") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("credentials reached target")
		}
		if !strings.HasPrefix(r.Host, probeTestIP+":") && r.Host != "probe.example:8080" {
			t.Errorf("target Host changed: %q", r.Host)
		}
		if r.Host == "probe.example:8080" && (r.TLS == nil || r.TLS.ServerName != "probe.example") {
			t.Error("TLS server name changed to pinned IP")
		}
		if strings.HasPrefix(r.URL.Path, "/artex-behavior-check-") {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte("ordinary service"))
	})
	s := httptest.NewUnstartedServer(h)
	if secure {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP(probeTestIP)}, DNSNames: []string{"probe.example"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		s.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
		s.StartTLS()
	} else {
		s.Start()
	}
	t.Cleanup(s.Close)
	return s
}

func proxyTestHTTP(t *testing.T, target string, secure bool, connects *atomic.Int32) *httptest.Server {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connects.Add(1)
		if r.Method != "CONNECT" || r.Host != probeTestIP+":8080" {
			t.Errorf("proxy did not receive pinned IP CONNECT: %s %s", r.Method, r.Host)
			w.WriteHeader(400)
			return
		}
		if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("probe:secret")) {
			w.WriteHeader(407)
			return
		}
		up, err := net.DialTimeout("tcp", target, time.Second)
		if err != nil {
			t.Error(err)
			w.WriteHeader(502)
			return
		}
		defer up.Close()
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
		done := make(chan struct{})
		go func() { io.Copy(up, rw); up.Close(); close(done) }()
		io.Copy(conn, up)
		conn.Close()
		<-done
	})
	var p *httptest.Server
	if secure {
		p = httptest.NewTLSServer(h)
	} else {
		p = httptest.NewServer(h)
	}
	t.Cleanup(p.Close)
	return p
}

func TestBehaviorHTTPProxyPinnedHTTPAndHTTPS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[secure], func(t *testing.T) {
			var hits, connects atomic.Int32
			target := proxyTestTarget(t, secure, &hits)
			p := proxyTestHTTP(t, target.Listener.Addr().String(), false, &connects)
			origin := "http://" + probeTestIP + ":8080"
			if secure {
				origin = "https://" + probeTestIP + ":8080"
			}
			c, err := probeClient(t.Context(), origin, strings.Replace(p.URL, "://", "://probe:secret@", 1))
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			if secure {
				roots := x509.NewCertPool()
				roots.AddCert(target.Certificate())
				c.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: roots}
				// Exercise Host/SNI independently of the already pinned numeric dial
				// address, without relying on external DNS in this fixture.
				origin = "https://probe.example:8080"
			}
			var admitted atomic.Int32
			out := probeWithClient(t.Context(), c, origin, DefaultRules(), func(context.Context, string, string) error { admitted.Add(1); return nil })
			if out.Outcome != "no_signal" || hits.Load() != 4 || connects.Load() != 4 || admitted.Load() != 4 {
				t.Fatalf("result=%+v target=%d proxy=%d admitted=%d", out, hits.Load(), connects.Load(), admitted.Load())
			}
		})
	}
}

func TestBehaviorProxyFailsClosedAndKeepsTLSVerification(t *testing.T) {
	var hits, connects atomic.Int32
	target := proxyTestTarget(t, true, &hits)
	p := proxyTestHTTP(t, target.Listener.Addr().String(), false, &connects)
	for _, proxyURL := range []string{p.URL, strings.Replace(p.URL, "://", "://probe:secret@", 1)} {
		out, err := ProbeViaProxy(t.Context(), "https://"+probeTestIP+":8080", proxyURL, DefaultRules(), nil)
		if err != nil || len(out.Observations) != 1 || out.Observations[0].Error != "network_tls_or_timeout" || hits.Load() != 0 {
			t.Fatalf("auth/invalid TLS accepted: %+v %v", out, err)
		}
	}
	// Local targets are rejected before even contacting an upstream.
	before := connects.Load()
	if _, err := ProbeViaProxy(t.Context(), target.URL, p.URL, DefaultRules(), nil); err == nil || connects.Load() != before {
		t.Fatal("loopback target reached proxy")
	}
	for _, raw := range []string{"http://probe:secret@localhost:0", "ftp://probe:secret@localhost", "http://probe:secret@localhost/path", "http://probe:secret@localhost/?x=y"} {
		_, err := ProbeViaProxy(t.Context(), "http://"+probeTestIP+":8080", raw, DefaultRules(), nil)
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Fatal("invalid proxy or error leak", err)
		}
	}
	// An untrusted HTTPS proxy is rejected before a CONNECT request.
	secureProxy := proxyTestHTTP(t, target.Listener.Addr().String(), true, &connects)
	before = connects.Load()
	out, err := ProbeViaProxy(t.Context(), "http://"+probeTestIP+":8080", secureProxy.URL, DefaultRules(), nil)
	if err != nil || len(out.Observations) != 1 || out.Observations[0].Error == "" || connects.Load() != before {
		t.Fatal(out, err)
	}
}

func TestBehaviorHTTPSProxyTrusted(t *testing.T) {
	// A subprocess has fresh system roots, allowing a private test CA without
	// changing production trust or adding an insecure transport option.
	if raw := os.Getenv("ARTEX_TEST_HTTPS_PROXY"); raw != "" {
		out, err := ProbeViaProxy(t.Context(), "http://"+probeTestIP+":8080", raw, DefaultRules(), nil)
		if err != nil || out.Outcome != "no_signal" {
			t.Fatal(out, err)
		}
		return
	}
	var hits, connects atomic.Int32
	target := proxyTestTarget(t, false, &hits)
	p := proxyTestHTTP(t, target.Listener.Addr().String(), true, &connects)
	certFile := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestBehaviorHTTPSProxyTrusted$", "-test.timeout=15s")
	cmd.Env = append(os.Environ(), "ARTEX_TEST_HTTPS_PROXY="+strings.Replace(p.URL, "://", "://probe:secret@", 1), "SSL_CERT_FILE="+certFile, "SSL_CERT_DIR="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if hits.Load() != 4 || connects.Load() != 4 {
		t.Fatal(hits.Load(), connects.Load())
	}
}

func TestBehaviorProxyCancellationAndBoundedHeaders(t *testing.T) {
	for _, mode := range []string{"cancel", "large", "reject"} {
		t.Run(mode, func(t *testing.T) {
			entered := make(chan struct{}, 1)
			p := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				entered <- struct{}{}
				if mode == "cancel" {
					<-r.Context().Done()
					return
				}
				if mode == "large" {
					w.Header().Set("X-Large", strings.Repeat("x", 20*1024))
					w.WriteHeader(200)
					return
				}
				w.WriteHeader(403)
			}))
			defer p.Close()
			u, _ := url.Parse(p.URL)
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			if mode == "cancel" {
				go func() { <-entered; cancel() }()
			}
			start := time.Now()
			conn, err := dialProbeProxy(ctx, u, probeTestIP+":8080")
			if conn != nil {
				conn.Close()
			}
			if err == nil || time.Since(start) > 2*time.Second {
				t.Fatal("unbounded/accepted handshake", err)
			}
		})
	}
}

func TestBehaviorSOCKS5PinnedAndAuthenticated(t *testing.T) {
	var hits, connects atomic.Int32
	target := proxyTestTarget(t, false, &hits)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			func() {
				defer c.Close()
				c.SetDeadline(time.Now().Add(5 * time.Second))
				br := bufio.NewReader(c)
				read := func(n int) []byte {
					b := make([]byte, n)
					if _, e := io.ReadFull(br, b); e != nil {
						t.Error(e)
					}
					return b
				}
				header := read(2)
				if header[0] != 5 {
					t.Error("SOCKS version")
					return
				}
				read(int(header[1]))
				c.Write([]byte{5, 2})
				auth := read(2)
				user := string(read(int(auth[1])))
				size := read(1)
				pass := string(read(int(size[0])))
				if auth[0] != 1 || user != "probe" || pass != "secret" {
					t.Error("SOCKS authentication")
					return
				}
				c.Write([]byte{1, 0})
				request := read(4)
				if request[0] != 5 || request[1] != 1 || request[3] != 1 {
					t.Errorf("expected IPv4, not proxy DNS: %v", request)
					return
				}
				ip := net.IP(read(4))
				port := binary.BigEndian.Uint16(read(2))
				if ip.String() != probeTestIP || port != 8080 {
					t.Error("unpinned address", ip, port)
					return
				}
				connects.Add(1)
				up, e := net.Dial("tcp", target.Listener.Addr().String())
				if e != nil {
					t.Error(e)
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
				copied := make(chan struct{})
				go func() { io.Copy(up, br); up.Close(); close(copied) }()
				io.Copy(c, up)
				c.Close()
				<-copied
			}()
		}
	}()
	out, e := ProbeViaProxy(t.Context(), "http://"+probeTestIP+":8080", "socks5://probe:secret@"+listener.Addr().String(), DefaultRules(), nil)
	listener.Close()
	<-done
	if e != nil || out.Outcome != "no_signal" || hits.Load() != 4 || connects.Load() != 4 {
		t.Fatal(out, e, hits.Load(), connects.Load())
	}
}
