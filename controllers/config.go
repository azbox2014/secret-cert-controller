package controllers

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/validation"
	"sigs.k8s.io/yaml"
)

// 运行参数（环境变量）
var (
	certServer   = getEnv("CERT_SERVER", "http://cert-server")
	ConfigPath   = getEnv("CONFIG_PATH", "/etc/cert-sync/config.yaml")
	SyncInterval = time.Duration(getEnvInt("SYNC_INTERVAL", 60)) * time.Second
)

func getEnv(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getEnvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	i, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return i
}

// SyncTarget 指定命名空间下需要同步的域名列表
type SyncTarget struct {
	Namespace string   `json:"namespace" yaml:"namespace"`
	Domains   []string `json:"domains"    yaml:"domains"`
}

// Config 配置文件结构
type Config struct {
	Sync []SyncTarget `json:"sync" yaml:"sync"`
}

// LoadConfig 读取并校验 YAML 配置文件
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件 %s 失败: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("解析配置文件 %s 失败: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("配置文件 %s 校验失败: %w", path, err)
	}

	return &cfg, nil
}

// Validate 校验配置：namespace/domain 合法且 (namespace, domain) 不重复
func (c *Config) Validate() error {
	if len(c.Sync) == 0 {
		return fmt.Errorf("sync 为空，没有需要同步的目标")
	}

	seen := make(map[string]map[string]bool)
	for i, target := range c.Sync {
		ns := strings.TrimSpace(target.Namespace)
		if ns == "" {
			return fmt.Errorf("sync[%d] 缺少 namespace", i)
		}
		if errs := validation.IsDNS1123Label(ns); len(errs) > 0 {
			return fmt.Errorf("sync[%d] namespace %q 非法: %s", i, ns, errs[0])
		}
		if len(target.Domains) == 0 {
			return fmt.Errorf("sync[%d] namespace %q 的 domains 为空", i, ns)
		}

		domains := seen[ns]
		if domains == nil {
			domains = make(map[string]bool)
			seen[ns] = domains
		}

		for _, domain := range target.Domains {
			domain = strings.TrimSpace(domain)
			if domain == "" {
				return fmt.Errorf("sync[%d] namespace %q 存在空域名", i, ns)
			}
			if errs := validation.IsDNS1123Subdomain(SecretName(domain)); len(errs) > 0 {
				return fmt.Errorf("namespace %q 域名 %q 生成的 Secret 名非法: %s", ns, domain, errs[0])
			}
			if domains[domain] {
				return fmt.Errorf("namespace %q 下域名 %q 重复配置", ns, domain)
			}
			domains[domain] = true
		}
	}

	return nil
}

// SecretName 按域名生成 TLS Secret 名称：域名中的 "." 替换为 "-"，再追加 "-tls"。
// example.com      -> example-com-tls
// www.example.com  -> www-example-com-tls
func SecretName(domain string) string {
	return strings.ReplaceAll(domain, ".", "-") + "-tls"
}
