package controllers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecretName(t *testing.T) {
	cases := []struct {
		domain string
		want   string
	}{
		{"example.com", "example-com-tls"},
		{"www.example.com", "www-example-com-tls"},
		{"a.b.c.example.com", "a-b-c-example-com-tls"},
	}
	for _, c := range cases {
		if got := SecretName(c.domain); got != c.want {
			t.Errorf("SecretName(%q) = %q, 期望 %q", c.domain, got, c.want)
		}
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写临时配置失败: %v", err)
	}
	return path
}

func TestLoadConfigOK(t *testing.T) {
	content := `
sync:
  - namespace: default
    domains:
      - example.com
      - www.example.com
  - namespace: kube-system
    domains:
      - api.example.com
`
	cfg, err := LoadConfig(writeConfig(t, content))
	if err != nil {
		t.Fatalf("加载配置失败: %v", err)
	}
	if len(cfg.Sync) != 2 {
		t.Fatalf("Sync 目标数 = %d, 期望 2", len(cfg.Sync))
	}
	if cfg.Sync[0].Namespace != "default" || len(cfg.Sync[0].Domains) != 2 {
		t.Fatalf("第一个目标不符合预期: %+v", cfg.Sync[0])
	}
}

func TestLoadConfigErrors(t *testing.T) {
	cases := map[string]string{
		"文件不存在":        "",
		"非法 YAML":      "sync: [",
		"sync 为空":      "sync: []",
		"缺少 namespace": "sync:\n  - domains:\n      - example.com\n",
		"domains 为空":   "sync:\n  - namespace: default\n    domains: []\n",
		"空域名":          "sync:\n  - namespace: default\n    domains: [\"  \"]\n",
		"同命名空间重复域名":    "sync:\n  - namespace: default\n    domains: [example.com, example.com]\n",
		"非法 namespace": "sync:\n  - namespace: Bad_NS\n    domains: [example.com]\n",
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			var path string
			if content == "" {
				path = filepath.Join(t.TempDir(), "missing.yaml")
			} else {
				path = writeConfig(t, content)
			}
			if _, err := LoadConfig(path); err == nil {
				t.Fatalf("用例 %q 应当返回错误", name)
			}
		})
	}
}

func TestDuplicateDomainAcrossNamespacesAllowed(t *testing.T) {
	content := `
sync:
  - namespace: ns-a
    domains: [example.com]
  - namespace: ns-b
    domains: [example.com]
`
	if _, err := LoadConfig(writeConfig(t, content)); err != nil {
		t.Fatalf("不同命名空间的相同域名应允许: %v", err)
	}
}
