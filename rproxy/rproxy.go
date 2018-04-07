package rproxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/yhat/wsutil"
)

// ReverseProxy holds the state for the HTTP ReverseProxy and Websocket Proxy
type ReverseProxy struct {
	URL      *url.URL
	Hostname string

	proxy   *httputil.ReverseProxy
	wsproxy *wsutil.ReverseProxy
}

// New returns a new ReverseProxy
func New(target *url.URL, hostname string) (*ReverseProxy, error) {
	targetQuery := target.RawQuery

	director := func(req *http.Request) {
		if hostname != "" {
			req.Host = hostname
		}
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.URL.Path = singleJoiningSlash(target.Path, req.URL.Path)
		if targetQuery == "" || req.URL.RawQuery == "" {
			req.URL.RawQuery = targetQuery + req.URL.RawQuery
		} else {
			req.URL.RawQuery = targetQuery + "&" + req.URL.RawQuery
		}
		if _, ok := req.Header["User-Agent"]; !ok {
			// explicitly disable User-Agent so it's not set to default value
			req.Header.Set("User-Agent", "")
		}
	}

	transport := &myTransport{
		transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				conn, err := (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 60 * time.Second,
				}).Dial(network, addr)
				if err != nil {
					fmt.Println("[rproxy] ~dial~", addr, "error:", err.Error())
				} else {
					fmt.Println("[rproxy] ~dial~", addr, ":", conn.LocalAddr(), "->", conn.RemoteAddr())
				}
				return conn, err
			},
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
		stripHeaders: []string{"Server"},
	}

	proxy := &httputil.ReverseProxy{
		Transport:     transport,
		Director:      director,
		FlushInterval: 250 * time.Millisecond,
	}

	wsproxy := &wsutil.ReverseProxy{
		Director: director,
	}

	return &ReverseProxy{
		URL:      target,
		Hostname: hostname,
		proxy:    proxy,
		wsproxy:  wsproxy,
	}, nil
}

// ServeHTTP determines whether to proxy a HTTP request or a WS one
func (p *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.TLS != nil {
		r.Header.Set("x-forwarded-proto", "https")
	} else {
		r.Header.Set("x-forwarded-proto", "http")
	}

	if r.Header.Get("Connection") == "Upgrade" && r.Header.Get("Upgrade") == "websocket" {
		p.wsproxy.ServeHTTP(w, r)
	} else {
		p.proxy.ServeHTTP(w, r)
	}
}

type myTransport struct {
	transport    *http.Transport
	stripHeaders []string
}

func (t *myTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	for _, hdr := range t.stripHeaders {
		resp.Header.Del(hdr)
	}
	return resp, nil
}

// https://golang.org/src/net/http/httputil/reverseproxy.go
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}
