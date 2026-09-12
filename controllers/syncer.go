package controllers

import (
	"context"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Syncer 配置文件驱动的证书同步器，作为 manager Runnable 周期运行
type Syncer struct {
	// Client 用于 create/update Secret
	Client client.Client
	// Reader 用于只读查询（走直连 API，不依赖 informer 缓存权限）
	Reader client.Reader
	// ConfigPath 配置文件路径
	ConfigPath string
	// Interval 同步周期
	Interval time.Duration
}

// Start 实现 manager.Runnable：启动即同步一次，之后按周期重读配置并同步
func (s *Syncer) Start(ctx context.Context) error {
	if s.Reader == nil {
		s.Reader = s.Client
	}
	if s.ConfigPath == "" {
		s.ConfigPath = ConfigPath
	}
	if s.Interval <= 0 {
		s.Interval = SyncInterval
	}

	klog.Infof("证书同步器启动，配置文件: %s，同步周期: %v", s.ConfigPath, s.Interval)

	// 保留上一份有效配置：配置文件暂时不可读/解析失败时继续按旧配置同步
	var lastCfg *Config

	syncOnce := func() {
		cfg, err := LoadConfig(s.ConfigPath)
		if err != nil {
			klog.Errorf("%v", err)
			if lastCfg == nil {
				klog.Warning("尚无可用配置，跳过本轮同步")
				return
			}
			klog.Warning("配置加载失败，沿用上一份有效配置")
			cfg = lastCfg
		} else {
			lastCfg = cfg
		}
		s.reconcile(ctx, cfg)
	}

	syncOnce()

	ticker := time.NewTicker(s.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			klog.Info("证书同步器停止")
			return nil
		case <-ticker.C:
			syncOnce()
		}
	}
}

var _ manager.Runnable = (*Syncer)(nil)

func (s *Syncer) reconcile(ctx context.Context, cfg *Config) {
	klog.V(3).Infof("开始同步，共 %d 个命名空间目标", len(cfg.Sync))

	for _, target := range cfg.Sync {
		var ns corev1.Namespace
		err := s.Reader.Get(ctx, types.NamespacedName{Name: target.Namespace}, &ns)
		switch {
		case apierrors.IsNotFound(err):
			klog.Warningf("命名空间 %q 不存在，跳过其中 %d 个域名的同步", target.Namespace, len(target.Domains))
			continue
		case err != nil:
			klog.Errorf("查询命名空间 %q 失败，跳过本轮: %v", target.Namespace, err)
			continue
		}

		for _, domain := range target.Domains {
			if err := s.syncDomain(ctx, target.Namespace, domain); err != nil {
				klog.Errorf("同步命名空间 %q 域名 %s 失败: %v", target.Namespace, domain, err)
			}
		}
	}
}

// syncDomain 在指定命名空间下按域名规则创建或更新 TLS Secret
func (s *Syncer) syncDomain(ctx context.Context, namespace, domain string) error {
	secretName := SecretName(domain)
	key := types.NamespacedName{Namespace: namespace, Name: secretName}

	var existing corev1.Secret
	err := s.Reader.Get(ctx, key, &existing)
	if apierrors.IsNotFound(err) {
		return s.createSecret(ctx, namespace, secretName, domain)
	}
	if err != nil {
		return err
	}

	if existing.Type != corev1.SecretTypeTLS {
		klog.Warningf("Secret %s/%s 已存在但类型为 %s（非 kubernetes.io/tls），跳过", namespace, secretName, existing.Type)
		return nil
	}

	fullchain, err := FetchFullchain(domain)
	if err != nil {
		return err
	}

	serverFP := Fingerprint(fullchain)
	currentFP := Fingerprint(string(existing.Data[corev1.TLSCertKey]))
	if serverFP != "" && serverFP == currentFP {
		klog.V(3).Infof("Secret %s/%s 证书已是最新，指纹: %s", namespace, secretName, serverFP)
		return nil
	}

	privkey, err := FetchPrivkey(domain)
	if err != nil {
		return err
	}

	updated := existing.DeepCopy()
	if updated.Data == nil {
		updated.Data = map[string][]byte{}
	}
	updated.Data[corev1.TLSCertKey] = []byte(fullchain)
	updated.Data[corev1.TLSPrivateKeyKey] = []byte(privkey)

	if err := s.Client.Update(ctx, updated); err != nil {
		return err
	}

	klog.Infof("已更新 Secret %s/%s，旧指纹: %s，新指纹: %s", namespace, secretName, currentFP, serverFP)
	return nil
}

func (s *Syncer) createSecret(ctx context.Context, namespace, secretName, domain string) error {
	fullchain, err := FetchFullchain(domain)
	if err != nil {
		return err
	}
	privkey, err := FetchPrivkey(domain)
	if err != nil {
		return err
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       []byte(fullchain),
			corev1.TLSPrivateKeyKey: []byte(privkey),
		},
	}

	if err := s.Client.Create(ctx, secret); err != nil {
		if apierrors.IsAlreadyExists(err) {
			return s.syncDomain(ctx, namespace, domain)
		}
		return err
	}

	klog.Infof("已创建 Secret %s/%s（域名 %s），指纹: %s",
		namespace, secretName, domain, Fingerprint(fullchain))
	return nil
}
