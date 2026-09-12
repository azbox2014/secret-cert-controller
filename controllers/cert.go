package controllers

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"k8s.io/klog/v2"
)

// ---------- HTTP ----------

var httpClient = &http.Client{
	Timeout: time.Duration(getEnvInt("HTTP_TIMEOUT", 5)) * time.Second,
}

func init() {
	proxy := os.Getenv("HTTPPROXY_URL")
	if proxy == "" {
		return
	}
	proxyURL, err := url.Parse(proxy)
	if err != nil {
		klog.Warningf("代理地址 %q 非法: %v，将直接连接", proxy, err)
		return
	}
	httpClient.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxyURL),
	}
	klog.Infof("HTTP 请求使用代理 %s", proxy)
}

// ---------- 证书工具 ----------

// Fingerprint 计算 PEM 编码证书（链）第一个证书 DER 的 sha256 指纹
func Fingerprint(certPEM string) string {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return ""
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:])
}

func validateCert(certPEM string) error {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return fmt.Errorf("证书不是合法的 PEM")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err
}

func validateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return fmt.Errorf("私钥不是合法的 PEM")
	}
	return nil
}

// ---------- 拉取 ----------

// FetchFullchain 拉取域名的完整证书链
func FetchFullchain(domain string) (string, error) {
	certURL := fmt.Sprintf("%s/%s/fullchain.pem", certServer, domain)
	body, err := httpGet(certURL, domain, "证书")
	if err != nil {
		return "", err
	}
	if err := validateCert(body); err != nil {
		return "", fmt.Errorf("域名 %s 的证书校验失败: %w", domain, err)
	}
	return body, nil
}

// FetchPrivkey 拉取域名的私钥
func FetchPrivkey(domain string) (string, error) {
	keyURL := fmt.Sprintf("%s/%s/privkey.pem", certServer, domain)
	body, err := httpGet(keyURL, domain, "私钥")
	if err != nil {
		return "", err
	}
	if err := validateKey(body); err != nil {
		return "", fmt.Errorf("域名 %s 的私钥校验失败: %w", domain, err)
	}
	return body, nil
}

func httpGet(fullURL, domain, what string) (string, error) {
	klog.V(4).Infof("拉取域名 %s 的%s: %s", domain, what, fullURL)

	resp, err := httpClient.Get(fullURL)
	if err != nil {
		return "", fmt.Errorf("拉取域名 %s 的%s失败: %w", domain, what, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("拉取域名 %s 的%s失败: HTTP %d", domain, what, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取域名 %s 的%s响应失败: %w", domain, what, err)
	}
	return string(body), nil
}
