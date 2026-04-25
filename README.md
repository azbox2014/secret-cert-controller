# Secret Cert Controller

用于从外部证书服务器同步 TLS 证书到 Kubernetes Secret 的控制器。

## 功能特性

- **自动证书同步**: 从外部证书服务器自动获取域名证书
- **证书缓存**: 本地缓存已获取的证书，避免频繁请求
- **指纹校验**: 通过证书指纹判断是否需要更新
- **事件过滤**: 仅处理带有特定注解的 Secret 资源

## 工作原理

1. 控制器监听 TLS 类型的 Secret 资源
2. 只有带有 `cert.example.com/managed=true` 注解的 Secret 才会被处理
3. 从证书服务器获取域名对应的证书和私钥
4. 将证书写入 Secret 的 `tls.crt` 和 `tls.key` 字段
5. 通过指纹比对判断证书是否变更，仅在变更时更新

## 架构

```
┌─────────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Cert Server    │────▶│ SecretReconciler │────▶│  K8s Secret     │
│ (外部证书服务)   │     │ (控制器)          │     │ (TLS 证书)      │
└─────────────────┘     └──────────────────┘     └─────────────────┘
                                │
                                ▼
                        ┌──────────────────┐
                        │  sync.Map        │
                        │  (证书缓存)       │
                        └──────────────────┘
```

## 注解说明

| 注解 | 必填 | 说明 |
|------|------|------|
| `cert.example.com/managed` | 是 | 设为 `true` 表示由控制器管理 |
| `cert.example.com/domain` | 是 | 要获取证书的域名 |
| `cert.example.com/fingerprint` | 否 | 证书指纹，由控制器自动更新 |

## 使用方法

### 1. 创建 Secret

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: example-tls
  namespace: default
  annotations:
    cert.example.com/managed: "true"
    cert.example.com/domain: "example.com"
type: kubernetes.io/tls
data: {}
```

### 2. 配置证书服务器

通过环境变量 `CERT_SERVER` 配置证书服务器地址：

```yaml
env:
  - name: CERT_SERVER
    value: "http://cert-server"
```

### 3. Helm 部署

```bash
helm install secret-cert-controller ./chart \
  --set controller.certServer=http://cert-server
```

## 配置参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `controller.certServer` | `http://cert-server` | 证书服务器地址 |
| `controller.annPrefix` | `cert.example.com` | 注解前缀，可自定义 |
| `controller.cacheRefreshInterval` | `5` | 证书缓存刷新间隔（秒） |
| `controller.reconcileInterval` | `3600` | reconcile 间隔（秒） |
| `controller.httpTimeout` | `5` | HTTP 请求超时（秒） |
| `replicaCount` | `1` | 副本数 |
| `image.repository` | - | 镜像仓库 |
| `image.tag` | `latest` | 镜像标签 |
| `resources.limits.cpu` | `200m` | CPU 限制 |
| `resources.limits.memory` | `256Mi` | 内存限制 |
| `resources.requests.cpu` | `50m` | CPU 请求 |
| `resources.requests.memory` | `64Mi` | 内存请求 |

## 环境变量

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `CERT_SERVER` | `http://cert-server` | 证书服务器地址 |
| `ANN_PREFIX` | `cert.example.com` | 注解前缀 |
| `CACHE_REFRESH_INTERVAL` | `5` | 缓存刷新间隔（秒） |
| `RECONCILE_INTERVAL` | `3600` | reconcile 间隔（秒） |
| `HTTP_TIMEOUT` | `5` | HTTP 超时（秒） |

## 证书服务器 API

控制器期望证书服务器提供以下接口：

```
GET /cert/{domain}/fullchain.pem  -> 返回完整证书链 (PEM)
GET /cert/{domain}/privkey.pem    -> 返回私钥 (PEM)
```

## 开发

### 构建

```bash
go build -o bin/manager .
```

### 运行

```bash
go run .
```

### 测试

```bash
go test ./...
```

## 项目结构

```
qff-secret-cert-controller/
├── chart/
│   ├── Chart.yaml          # Helm Chart 定义
│   ├── values.yaml         # 默认配置
│   └── templates/          # K8s 资源模板
├── controllers/
│   └── secret_controller.go  # 主要控制器逻辑
├── main.go                 # 程序入口
├── Dockerfile              # Docker 镜像构建
└── go.mod                  # Go 依赖
```

## License

MIT