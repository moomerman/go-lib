package rproxy

import (
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestReverseProxy(t *testing.T) {
	backendURL, err := url.Parse("https://www.richt.co.uk")
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler, err := New(backendURL, "www.richt.co.uk")
	if err != nil {
		t.Fatal(err)
	}

	proxyHandler.proxy.ErrorLog = log.New(ioutil.Discard, "", 0) // quiet for tests
	proxy := httptest.NewServer(proxyHandler)
	defer proxy.Close()
	client := proxy.Client()

	getReq, _ := http.NewRequest("GET", proxy.URL, nil)
	getReq.Host = "some-name"
	getReq.Header.Set("Connection", "close")
	getReq.Close = true
	res, err := client.Do(getReq)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g, e := res.StatusCode, http.StatusAccepted; g != e {
		t.Errorf("got res.StatusCode %d; expected %d", g, e)
	}

}
