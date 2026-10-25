package core

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gologme/log"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// TestQUICLinkThroughLimitedPath exercises both QUIC link endpoints. The proxy
// drops oversized UDP datagrams without returning an error to the sender, as a
// router with a smaller MTU would.
func TestQUICLinkThroughLimitedPath(t *testing.T) {
	for _, tc := range []struct {
		name       string
		network    string
		host       string
		maxPayload int // IP MTU less the IP and UDP headers.
	}{
		{name: "ipv4-mtu1500", network: "udp4", host: "127.0.0.1", maxPayload: 1472},
		{name: "ipv4-mtu1280", network: "udp4", host: "127.0.0.1", maxPayload: 1252},
		{name: "ipv6-mtu1280", network: "udp6", host: "::1", maxPayload: 1232},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.network == "udp6" {
				probe, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.ParseIP(tc.host)})
				if err != nil {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				_ = probe.Close()
			}
			ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
			defer cancel()

			server := newTestQUICLink(t)
			client := newTestQUICLink(t)
			listenURL := &url.URL{Scheme: "quic", Host: net.JoinHostPort(tc.host, "0")}
			listener, err := server.listen(ctx, listenURL, "")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			proxyAddr, dropped := startTestQUICProxy(t, tc.network, listener.Addr().(*net.UDPAddr), tc.maxPayload)
			dialURL := &url.URL{Scheme: "quic", Host: proxyAddr.String()}
			outbound, err := client.dial(ctx, dialURL, linkInfo{}, linkOptions{})
			if err != nil {
				t.Fatalf("QUIC dial through %d-byte UDP path: %v", tc.maxPayload, err)
			}
			defer func() { _ = outbound.(*linkQUICStream).Conn.CloseWithError(0, "") }()
			defer outbound.Close()

			// OpenStreamSync on the dialer does not send data until the first Write.
			request := bytes.Repeat([]byte("client to server"), 256)
			if err := outbound.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := outbound.Write(request); err != nil {
				t.Fatalf("client write: %v", err)
			}
			var inbound *linkQUICStream
			select {
			case inbound = <-listener.(*linkQUICListener).ch:
				if inbound == nil {
					t.Fatal("QUIC listener closed before accepting a stream")
				}
			case <-ctx.Done():
				t.Fatalf("server accept stream: %v", ctx.Err())
			}
			defer func() { _ = inbound.Conn.CloseWithError(0, "") }()
			defer inbound.Close()
			if err := inbound.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			gotRequest := make([]byte, len(request))
			if _, err := io.ReadFull(inbound, gotRequest); err != nil {
				t.Fatalf("server read: %v", err)
			}
			if !bytes.Equal(gotRequest, request) {
				t.Fatal("server received different payload")
			}

			reply := bytes.Repeat([]byte("server to client"), 256)
			if _, err := inbound.Write(reply); err != nil {
				t.Fatalf("server write: %v", err)
			}
			gotReply := make([]byte, len(reply))
			if _, err := io.ReadFull(outbound, gotReply); err != nil {
				t.Fatalf("client read: %v", err)
			}
			if !bytes.Equal(gotReply, reply) {
				t.Fatal("client received different payload")
			}
			t.Logf("proxy dropped %d oversized datagrams", dropped.Load())
		})
	}
}

func newTestQUICLink(t *testing.T) *linkQUIC {
	t.Helper()
	cfg := config.GenerateConfig()
	if err := cfg.GenerateSelfSignedCertificate(); err != nil {
		t.Fatal(err)
	}
	c := &Core{log: log.New(io.Discard, "", 0)}
	var err error
	c.config.tls, err = c.generateTLSConfig(cfg.Certificate)
	if err != nil {
		t.Fatal(err)
	}
	return (&links{core: c}).newLinkQUIC()
}

func startTestQUICProxy(t *testing.T, network string, server *net.UDPAddr, maxPayload int) (*net.UDPAddr, *atomic.Int64) {
	t.Helper()
	proxy, err := net.ListenUDP(network, &net.UDPAddr{IP: server.IP})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	dropped := &atomic.Int64{}
	go func() {
		defer close(done)
		var client *net.UDPAddr
		buf := make([]byte, 65535)
		for {
			n, source, err := proxy.ReadFromUDP(buf)
			if err != nil {
				return
			}
			if n > maxPayload {
				dropped.Add(1)
				continue
			}
			if source.IP.Equal(server.IP) && source.Port == server.Port {
				if client != nil {
					_, _ = proxy.WriteToUDP(buf[:n], client)
				}
			} else {
				client = source
				_, _ = proxy.WriteToUDP(buf[:n], server)
			}
		}
	}()
	t.Cleanup(func() {
		_ = proxy.Close()
		<-done
	})
	return proxy.LocalAddr().(*net.UDPAddr), dropped
}
