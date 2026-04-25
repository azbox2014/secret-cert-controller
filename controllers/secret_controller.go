package controllers

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"k8s.io/apimachinery/pkg/runtime"
)

type SecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}


var (
	certServer           = getEnv("CERT_SERVER", "http://cert-server")
	cacheInterval        = time.Duration(getEnvInt("CACHE_REFRESH_INTERVAL", 5)) * time.Second
	reconcileInterval    = time.Duration(getEnvInt("RECONCILE_INTERVAL", 3600)) * time.Second
	httpTimeout          = time.Duration(getEnvInt("HTTP_TIMEOUT", 5)) * time.Second
	annPrefix            = getEnv("ANN_PREFIX", "cert.example.com")
	annManaged   string // = annPrefix + "/managed"
	annDomain    string // = annPrefix + "/domain"
	annFP        string // = annPrefix + "/fingerprint"
)

func init() {
	annManaged = annPrefix + "/managed"
	annDomain = annPrefix + "/domain"
	annFP = annPrefix + "/fingerprint"
}

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
	i, _ := strconv.Atoi(v)
	return i
}

// ---------- HTTP ----------
var httpClient = &http.Client{
	Timeout: httpTimeout,
}

// ---------- CACHE ----------
type CertData struct {
	Cert        string
	Key         string
	Fingerprint string
}

var certCache sync.Map

// ---------- UTILS ----------
func fingerprint(certPEM string) string {
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
		return fmt.Errorf("invalid cert")
	}
	_, err := x509.ParseCertificate(block.Bytes)
	return err
}

func validateKey(keyPEM string) error {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return fmt.Errorf("invalid key")
	}
	return nil
}

// ---------- FETCH ----------
func fetchCert(domain string) (CertData, error) {
	certURL := fmt.Sprintf("%s/cert/%s/fullchain.pem", certServer, domain)
	keyURL := fmt.Sprintf("%s/cert/%s/privkey.pem", certServer, domain)

	resp, err := httpClient.Get(certURL)
	if err != nil {
		return CertData{}, err
	}
	defer resp.Body.Close()

	certBytes, _ := io.ReadAll(resp.Body)

	resp2, err := httpClient.Get(keyURL)
	if err != nil {
		return CertData{}, err
	}
	defer resp2.Body.Close()

	keyBytes, _ := io.ReadAll(resp2.Body)

	certStr := string(certBytes)
	keyStr := string(keyBytes)

	if err := validateCert(certStr); err != nil {
		return CertData{}, err
	}
	if err := validateKey(keyStr); err != nil {
		return CertData{}, err
	}

	return CertData{
		Cert:        certStr,
		Key:         keyStr,
		Fingerprint: fingerprint(certStr),
	}, nil
}

// ---------- CACHE LOOP ----------
func startCacheRefresher(ctx context.Context) {
	ticker := time.NewTicker(cacheInterval)

	go func() {
		for {
			select {
			case <-ticker.C:
				certCache.Range(func(key, value interface{}) bool {
					domain := key.(string)

					cert, err := fetchCert(domain)
					if err == nil {
						certCache.Store(domain, cert)
					}
					return true
				})
			case <-ctx.Done():
				return
			}
		}
	}()
}

// ---------- RECONCILE ----------
func (r *SecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	var secret corev1.Secret
	if err := r.Get(ctx, req.NamespacedName, &secret); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	if secret.Type != corev1.SecretTypeTLS {
		return ctrl.Result{}, nil
	}

	ann := secret.Annotations
	if ann == nil || ann[annManaged] != "true" {
		return ctrl.Result{}, nil
	}

	domain := ann[annDomain]
	if domain == "" {
		return ctrl.Result{}, nil
	}

	val, ok := certCache.Load(domain)
	if !ok {
		cert, err := fetchCert(domain)
		if err != nil {
			return ctrl.Result{RequeueAfter: time.Minute}, err
		}
		certCache.Store(domain, cert)
		val = cert
	}

	certData := val.(CertData)

	// 检查是否需要立即同步：
	// 1. 新添加的 secret（没有 fingerprint）
	// 2. 已有 secret 新添加了 annotation（没有 fingerprint）
	// 3. 证书指纹发生变化
	needImmediateSync := ann[annFP] == "" || ann[annFP] != certData.Fingerprint

	if !needImmediateSync {
		return ctrl.Result{RequeueAfter: reconcileInterval}, nil
	}

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}

	secret.Data["tls.crt"] = []byte(certData.Cert)
	secret.Data["tls.key"] = []byte(certData.Key)

	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[annFP] = certData.Fingerprint

	if err := r.Update(ctx, &secret); err != nil {
		return ctrl.Result{}, err
	}

	return ctrl.Result{RequeueAfter: reconcileInterval}, nil
}

// ---------- SETUP ----------
func (r *SecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	startCacheRefresher(context.Background())

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1.Secret{}).
		WithEventFilter(predicate.NewPredicateFuncs(func(obj client.Object) bool {
			ann := obj.GetAnnotations()
			return ann != nil && ann[annManaged] == "true"
		})).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 5,
		}).
		Complete(r)
}