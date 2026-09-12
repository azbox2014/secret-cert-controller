package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestFingerprint(t *testing.T) {
	certPEM, _ := makeTestCertPEM(t, "example.com")

	fp := Fingerprint(certPEM)
	if fp == "" {
		t.Fatal("合法证书的指纹不应为空")
	}
	if Fingerprint("not a pem") != "" {
		t.Fatal("非法 PEM 的指纹应为空")
	}
	if Fingerprint(certPEM) != fp {
		t.Fatal("同一证书指纹不稳定")
	}
}

func makeTestCertPEM(t *testing.T, domain string) (string, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成私钥失败: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("创建证书失败: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	return certPEM, keyPEM
}

func TestFetchFullchainAndPrivkey(t *testing.T) {
	certPEM, keyPEM := makeTestCertPEM(t, "example.com")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/example.com/fullchain.pem":
			_, _ = w.Write([]byte(certPEM))
		case "/example.com/privkey.pem":
			_, _ = w.Write([]byte(keyPEM))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	old := certServer
	certServer = srv.URL
	defer func() { certServer = old }()

	gotCert, err := FetchFullchain("example.com")
	if err != nil {
		t.Fatalf("FetchFullchain 失败: %v", err)
	}
	if gotCert != certPEM {
		t.Fatal("FetchFullchain 内容不一致")
	}

	gotKey, err := FetchPrivkey("example.com")
	if err != nil {
		t.Fatalf("FetchPrivkey 失败: %v", err)
	}
	if gotKey != keyPEM {
		t.Fatal("FetchPrivkey 内容不一致")
	}

	if _, err := FetchFullchain("missing.example"); err == nil {
		t.Fatal("404 场景应返回错误")
	}
}
